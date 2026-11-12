//! NFS — Notion File Sharing.
//!
//! One binary: `serve` (secure links + web generator), `create`, `decode`, `keygen`, `health`.

mod config;
mod kutt;
mod links;
mod notion;
mod server;
mod token;

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::config::Config;

#[derive(Parser)]
#[command(
    name = "nfs",
    version,
    about = "Notion File Sharing: secure, expiring links to files in Notion"
)]
struct Cli {
    /// Configuration file (TOML).
    #[arg(short, long, env = "NFS_CONFIG", global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the HTTP server.
    Serve,
    /// Create a secure link (and its short URL) for a Notion block.
    Create {
        /// Notion URL with the block id: https://www.notion.so/…#<block_id>
        url: String,
        /// Expiry: +30m, +24h, +7d, +2w, +50y or 2026-12-31T23:59:59Z.
        #[arg(short = 'X', long, default_value = "+50y")]
        expire: String,
        /// Custom short URL alias (u.joor.net/<alias>).
        #[arg(short = 'C', long)]
        custom_shortcut: Option<String>,
        /// Protect the link with a password ("-" = read it from stdin).
        #[arg(short = 'P', long)]
        password: Option<String>,
        /// Do not create a short URL.
        #[arg(long)]
        no_short: bool,
        /// Skip the Notion check (works offline, no file name).
        #[arg(long)]
        no_check: bool,
    },
    /// Inspect a short or secure URL and optionally download the file.
    Decode {
        url: String,
        /// Only show the information, do not download.
        #[arg(short, long)]
        skip_download: bool,
        /// Download directory.
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
    /// Generate a new 32-byte key file.
    Keygen { file: PathBuf },
    /// Exit 0 when the server answers on its health endpoint (container healthcheck).
    Health {
        #[arg(long, default_value = "http://127.0.0.1:9100/healthz")]
        url: String,
    },
}

fn default_config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("nfs/config.toml")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let default_level = if matches!(cli.cmd, Cmd::Serve) {
        "info"
    } else {
        "warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| default_level.into()),
        )
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_writer(std::io::stderr)
        .init();
    server::install_crypto();

    let config_path = cli.config.clone().unwrap_or_else(default_config_path);
    let load = || Config::load(&config_path);

    match cli.cmd {
        Cmd::Serve => server::run(load()?).await,
        Cmd::Create {
            url,
            expire,
            custom_shortcut,
            password,
            no_short,
            no_check,
        } => {
            create(
                &load()?,
                &url,
                &expire,
                custom_shortcut.as_deref(),
                password,
                no_short,
                no_check,
            )
            .await
        }
        Cmd::Decode {
            url,
            skip_download,
            output,
        } => decode(&load()?, &url, skip_download, &output).await,
        Cmd::Keygen { file } => keygen(&file),
        Cmd::Health { url } => health(&url).await,
    }
}

async fn create(
    cfg: &Config,
    url: &str,
    expire: &str,
    slug: Option<&str>,
    password: Option<String>,
    no_short: bool,
    no_check: bool,
) -> anyhow::Result<()> {
    let keys = cfg.keys()?;
    let block_id = links::block_id_from_url(url).map_err(anyhow::Error::msg)?;
    let now = token::now();
    let exp = links::parse_expire(expire, now).map_err(anyhow::Error::msg)?;
    if let Some(s) = slug {
        links::validate_slug(s).map_err(anyhow::Error::msg)?;
    }
    let password = match password.as_deref() {
        Some("-") => {
            eprint!("Password: ");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Some(line.trim_end_matches(['\r', '\n']).to_string())
        }
        other => other.map(str::to_string),
    };
    let http = server::api_client();
    let mut file_name = String::from("file");
    if !no_check {
        let notion = notion::Notion::new(
            http.clone(),
            cfg.notion.api_url.clone(),
            cfg.notion_api_key()?,
            cfg.notion.version.clone(),
        );
        let (r, _) = notion
            .resolve(&block_id)
            .await
            .context("checking the block in Notion (use --no-check to skip)")?;
        file_name = r.file_name.clone();
        eprintln!("File: {} ({})", r.file_name, r.block_type);
    }
    let path = links::secure_path(&keys, &cfg.customer_id, exp, &block_id, password.as_deref());
    let secure = format!("{}{}", cfg.base_url, path);
    println!("Secure URL:\n{secure}");
    println!("Expires: {}", links::format_ts(exp));
    if !no_short {
        let kutt = kutt::Kutt::new(http, cfg.kutt.api_url.clone(), cfg.kutt_api_key()?);
        let expire_in = links::kutt_expire_in(exp, now);
        let short = kutt
            .create(
                &secure,
                slug,
                expire_in.as_deref(),
                &format!("NFS: {file_name}"),
            )
            .await?;
        println!("URL for sharing your file:\n{}", short.link);
    }
    Ok(())
}

async fn decode(cfg: &Config, url: &str, skip_download: bool, output: &Path) -> anyhow::Result<()> {
    let keys = cfg.keys()?;
    let secure = if url.starts_with(&cfg.base_url) {
        url.to_string()
    } else {
        let no_redirect = reqwest::Client::builder()
            .user_agent(server::USER_AGENT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        kutt::unshorten(&no_redirect, url).await?
    };
    println!("Secure URL:\n{secure}\n");
    let parsed = url::Url::parse(&secure)?;
    let path = percent_encoding::percent_decode_str(parsed.path())
        .decode_utf8_lossy()
        .to_string();
    let now = token::now();
    let (block_id, expire, protected) = if let Some(tok) = path.strip_prefix("/v2/") {
        let p = token::v2_decode(&keys, tok, now)?;
        (p.b, p.e, p.p.is_some())
    } else {
        let link = token::V1Link::parse(&path).ok_or_else(|| anyhow::anyhow!("not an NFS link"))?;
        let block = token::v1_decode(&keys, &link, now)?;
        (block, link.expire.parse().unwrap_or_default(), false)
    };
    println!("Signature: OK");
    println!("Block id:  {block_id}");
    println!("Expires:   {}", links::format_ts(expire));
    println!("Password:  {}", if protected { "yes" } else { "no" });

    let http = server::api_client();
    let notion = notion::Notion::new(
        http,
        cfg.notion.api_url.clone(),
        cfg.notion_api_key()?,
        cfg.notion.version.clone(),
    );
    let (r, _) = notion.resolve(&block_id).await?;
    println!("File:      {} ({})", r.file_name, r.block_type);
    let notion::Source::Hosted { url: file_url } = &r.source else {
        if let notion::Source::External { url } = &r.source {
            println!("External:  {url}");
        }
        return Ok(());
    };
    if skip_download {
        return Ok(());
    }
    let safe_name: String = r
        .file_name
        .chars()
        .map(|c| if c == '/' || c == '\\' { '_' } else { c })
        .collect();
    let target = output.join(safe_name);
    if target.exists() {
        bail!("{} already exists", target.display());
    }
    let resp = server::file_client()
        .get(file_url)
        .send()
        .await?
        .error_for_status()?;
    let total = resp.content_length();
    let mut file = tokio::fs::File::create(&target).await?;
    let mut done: u64 = 0;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        done += chunk.len() as u64;
        if let Some(t) = total {
            eprint!(
                "\r{:>5.1}%  {}",
                done as f64 * 100.0 / t as f64,
                server::human_size(done)
            );
            let _ = std::io::stderr().flush();
        }
    }
    file.flush().await?;
    eprintln!();
    println!("Saved:     {}", target.display());
    Ok(())
}

fn keygen(file: &Path) -> anyhow::Result<()> {
    if file.exists() {
        bail!(
            "{} already exists: refusing to overwrite a key (it would break every link)",
            file.display()
        );
    }
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| anyhow::anyhow!("random: {e}"))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(file)?.write_all(&key)?;
    println!("Key written to {}", file.display());
    Ok(())
}

async fn health(url: &str) -> anyhow::Result<()> {
    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?
        .get(url)
        .send()
        .await?;
    if resp.status().is_success() {
        Ok(())
    } else {
        bail!("unhealthy: HTTP {}", resp.status())
    }
}
