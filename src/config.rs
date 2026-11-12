//! Configuration: one TOML file. Secrets can be inline (`x = "…"`) or read from a file (`x_file = "…"`).

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::token::Keys;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Public listener (links, generator).
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Internal listener for `/metrics` and `/healthz` (never published by the reverse proxy).
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
    /// Public base URL of the secure links, e.g. `https://n.joor.net`.
    pub base_url: String,
    #[serde(default = "default_customer_id")]
    pub customer_id: String,
    /// 32-byte secretbox key (`key.bin`).
    pub key_file: PathBuf,
    pub seed: Option<String>,
    pub seed_file: Option<PathBuf>,
    pub notion: NotionConfig,
    pub kutt: KuttConfig,
    pub oidc: Option<OidcConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotionConfig {
    pub api_key: Option<String>,
    pub api_key_file: Option<PathBuf>,
    #[serde(default = "default_notion_api_url")]
    pub api_url: String,
    #[serde(default = "default_notion_version")]
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KuttConfig {
    /// Kutt API endpoint for links, e.g. `https://u.joor.net/api/v2/links`.
    pub api_url: String,
    pub api_key: Option<String>,
    pub api_key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// e.g. `https://iam.joor.net/realms/joornet`
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_secret_file: Option<PathBuf>,
    /// `preferred_username` values allowed to create links. Empty = every user of the realm.
    #[serde(default)]
    pub allowed_users: Vec<String>,
}

fn default_listen() -> String {
    "0.0.0.0:8080".into()
}
fn default_admin_listen() -> String {
    "0.0.0.0:9100".into()
}
fn default_customer_id() -> String {
    "1".into()
}
fn default_notion_api_url() -> String {
    "https://api.notion.com/v1/blocks/".into()
}
fn default_notion_version() -> String {
    "2026-03-11".into()
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        cfg.base_url = cfg.base_url.trim_end_matches('/').to_string();
        if !cfg.notion.api_url.ends_with('/') {
            cfg.notion.api_url.push('/');
        }
        Ok(cfg)
    }

    pub fn keys(&self) -> anyhow::Result<Keys> {
        let key = std::fs::read(&self.key_file)
            .with_context(|| format!("reading key {}", self.key_file.display()))?;
        let seed = secret("seed", &self.seed, &self.seed_file)?;
        Keys::new(&key, seed)
    }

    pub fn notion_api_key(&self) -> anyhow::Result<String> {
        secret(
            "notion.api_key",
            &self.notion.api_key,
            &self.notion.api_key_file,
        )
    }

    pub fn kutt_api_key(&self) -> anyhow::Result<String> {
        secret("kutt.api_key", &self.kutt.api_key, &self.kutt.api_key_file)
    }
}

impl OidcConfig {
    pub fn secret(&self) -> anyhow::Result<String> {
        secret(
            "oidc.client_secret",
            &self.client_secret,
            &self.client_secret_file,
        )
    }
}

/// Inline value or file content (trailing newline removed). Exactly one must be set.
fn secret(name: &str, value: &Option<String>, file: &Option<PathBuf>) -> anyhow::Result<String> {
    match (value, file) {
        (Some(v), None) => Ok(v.clone()),
        (None, Some(f)) => {
            let v = std::fs::read_to_string(f)
                .with_context(|| format!("reading {name} from {}", f.display()))?;
            Ok(v.strip_suffix('\n').unwrap_or(&v).to_string())
        }
        (Some(_), Some(_)) => bail!("set either {name} or {name}_file, not both"),
        (None, None) => bail!("missing {name} (or {name}_file)"),
    }
}
