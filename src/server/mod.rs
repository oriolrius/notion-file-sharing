//! HTTP server: public links + web generator on `listen`, metrics/health on `admin_listen`.

mod auth;
mod download;
mod metrics;
mod pages;
mod web;

use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::FromRef;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use axum_extra::extract::cookie::Key;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::kutt::Kutt;
use crate::notion::Notion;
use crate::token::Keys;

pub use metrics::Metrics;
pub use web::human_size;

pub struct Inner {
    pub cfg: Config,
    pub keys: Keys,
    pub notion: Notion,
    pub kutt: Kutt,
    /// Client for file downloads (no total timeout: streams can last hours).
    pub files: reqwest::Client,
    pub cookie_key: Key,
    pub oidc: Option<auth::Oidc>,
    pub metrics: Metrics,
    pub limiter: download::Limiter,
    pub secure_cookies: bool,
}

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Key {
        state.cookie_key.clone()
    }
}

pub const USER_AGENT: &str = concat!(
    "nfs/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/oriolrius/notion-file-sharing)"
);

/// rustls needs one process-wide crypto provider (ring).
pub fn install_crypto() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub fn api_client() -> reqwest::Client {
    install_crypto();
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("HTTP client")
}

pub fn file_client() -> reqwest::Client {
    install_crypto();
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(120))
        .build()
        .expect("HTTP client")
}

impl AppState {
    pub fn new(cfg: Config) -> anyhow::Result<Self> {
        let keys = cfg.keys()?;
        let api = api_client();
        let notion = Notion::new(
            api.clone(),
            cfg.notion.api_url.clone(),
            cfg.notion_api_key()?,
            cfg.notion.version.clone(),
        );
        let kutt = Kutt::new(api.clone(), cfg.kutt.api_url.clone(), cfg.kutt_api_key()?);
        let oidc = match &cfg.oidc {
            Some(o) => Some(auth::Oidc::new(
                o.clone(),
                o.secret()?,
                api.clone(),
                &cfg.base_url,
            )),
            None => None,
        };
        let cookie_key = Key::from(&keys.derive64(b"nfs/cookies"));
        Ok(Self(Arc::new(Inner {
            secure_cookies: cfg.base_url.starts_with("https://"),
            cfg,
            keys,
            notion,
            kutt,
            files: file_client(),
            cookie_key,
            oidc,
            metrics: Metrics::default(),
            limiter: download::Limiter::default(),
        })))
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/robots.txt",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/plain")],
                    "User-agent: *\nDisallow: /\n",
                )
            }),
        )
        .route(
            "/favicon.ico",
            get(|| async { Redirect::permanent("/_/assets/favicon.svg") }),
        )
        .route("/", get(|| async { Redirect::to("/_/") }))
        .route("/_/", get(web::form))
        .route("/_/links", axum::routing::post(web::create))
        .route("/_/assets/{file}", get(web::asset))
        .route("/_/auth/login", get(auth::login))
        .route("/_/auth/callback", get(auth::callback))
        .route("/_/auth/logout", get(auth::logout))
        .route("/v2/{token}", get(download::v2_get).post(download::v2_post))
        .fallback(download::v1)
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
}

async fn security_headers(mut resp: axum::response::Response) -> axum::response::Response {
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    let is_html = h
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"));
    if is_html {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; \
                 connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            ),
        );
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

fn admin_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/metrics",
            get(
                |axum::extract::State(st): axum::extract::State<AppState>| async move {
                    (
                        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
                        st.metrics.render(),
                    )
                },
            ),
        )
        .fallback(|| async { StatusCode::NOT_FOUND.into_response() })
        .with_state(state)
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let listen = cfg.listen.clone();
    let admin_listen = cfg.admin_listen.clone();
    let state = AppState::new(cfg)?;
    if state.oidc.is_none() {
        tracing::warn!("no [oidc] section: the web generator is disabled");
    }
    let public = TcpListener::bind(&listen).await?;
    let admin = TcpListener::bind(&admin_listen).await?;
    tracing::info!(%listen, %admin_listen, version = env!("CARGO_PKG_VERSION"), "nfs server started");

    let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let admin_app = admin_router(state);
    let a = axum::serve(public, app).with_graceful_shutdown(shutdown());
    let b = axum::serve(admin, admin_app).with_graceful_shutdown(shutdown());
    tokio::try_join!(async { a.await }, async { b.await })?;
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

#[cfg(test)]
pub mod test_support {
    use super::*;

    /// State with test keys, pointing Notion/Kutt at `mock` and OIDC disabled.
    pub fn state(mock: &str) -> AppState {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nfs-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("key.bin");
        std::fs::write(&key_file, (1u8..=32).collect::<Vec<u8>>()).unwrap();
        let toml = format!(
            r##"
base_url = "https://n.example"
key_file = "{}"
seed = "test-seed-!\"#$%&'()*+,-./:;<=>?@[]^_`{{|}}~"
[notion]
api_key = "secret_test"
api_url = "{mock}/v1/blocks/"
[kutt]
api_url = "{mock}/api/v2/links"
api_key = "kutt_test"
"##,
            key_file.display()
        );
        let path = dir.join("config.toml");
        std::fs::write(&path, toml).unwrap();
        AppState::new(Config::load(&path).unwrap()).unwrap()
    }
}
