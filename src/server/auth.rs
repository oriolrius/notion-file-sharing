//! OIDC login for the generator (Keycloak), authorization code + PKCE, confidential client.
//!
//! The ID token comes straight from the token endpoint over TLS, so (OIDC Core 3.1.3.7) TLS server
//! validation replaces the signature check; we still verify `iss`, `aud`, `nonce` and `exp`.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::OnceCell;

use super::AppState;
use super::metrics::inc;
use super::pages;
use crate::config::OidcConfig;
use crate::token;

pub const SESSION_COOKIE: &str = "nfs_session";
const PENDING_COOKIE: &str = "nfs_oidc";
const SESSION_SECONDS: i64 = 12 * 3600;

pub struct Oidc {
    cfg: OidcConfig,
    secret: String,
    http: reqwest::Client,
    meta: OnceCell<Metadata>,
    redirect_uri: String,
    home: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    end_session_endpoint: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    state: String,
    verifier: String,
    nonce: String,
    exp: i64,
}

/// Generator session (private = encrypted + authenticated cookie).
#[derive(Serialize, Deserialize)]
pub struct Session {
    pub user: String,
    pub exp: i64,
    pub csrf: String,
}

impl Oidc {
    pub fn new(cfg: OidcConfig, secret: String, http: reqwest::Client, base_url: &str) -> Self {
        Self {
            cfg,
            secret,
            http,
            meta: OnceCell::new(),
            redirect_uri: format!("{base_url}/_/auth/callback"),
            home: format!("{base_url}/_/"),
        }
    }

    async fn metadata(&self) -> anyhow::Result<&Metadata> {
        self.meta
            .get_or_try_init(|| async {
                let url = format!(
                    "{}/.well-known/openid-configuration",
                    self.cfg.issuer.trim_end_matches('/')
                );
                let meta: Metadata = self
                    .http
                    .get(url)
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                if meta.issuer != self.cfg.issuer.trim_end_matches('/') {
                    anyhow::bail!("issuer mismatch: {}", meta.issuer);
                }
                Ok(meta)
            })
            .await
    }
}

fn random_b64(n: usize) -> String {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("OS random generator");
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn session(jar: &PrivateCookieJar) -> Option<Session> {
    let s: Session = serde_json::from_str(jar.get(SESSION_COOKIE)?.value()).ok()?;
    (s.exp > token::now()).then_some(s)
}

fn cookie<'a>(
    st: &AppState,
    name: &'a str,
    value: String,
    path: &'a str,
    seconds: i64,
) -> Cookie<'a> {
    Cookie::build((name, value))
        .path(path)
        .http_only(true)
        .secure(st.secure_cookies)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(seconds))
        .build()
}

fn auth_error(text: &str) -> Response {
    pages::message(StatusCode::BAD_GATEWAY, "Error d'inici de sessió", text)
}

/// `GET /_/auth/login`
pub async fn login(State(st): State<AppState>, jar: PrivateCookieJar) -> Response {
    let Some(oidc) = &st.oidc else {
        return pages::not_found();
    };
    let meta = match oidc.metadata().await {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(error = %e, "OIDC discovery failed");
            return auth_error("No s'ha pogut contactar el servidor d'identitat.");
        }
    };
    let pending = Pending {
        state: random_b64(16),
        verifier: random_b64(32),
        nonce: random_b64(16),
        exp: token::now() + 600,
    };
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pending.verifier.as_bytes()));
    let Ok(url) = url::Url::parse_with_params(
        &meta.authorization_endpoint,
        [
            ("response_type", "code"),
            ("client_id", oidc.cfg.client_id.as_str()),
            ("redirect_uri", oidc.redirect_uri.as_str()),
            ("scope", "openid profile email"),
            ("state", pending.state.as_str()),
            ("nonce", pending.nonce.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ],
    ) else {
        return auth_error("Configuració OIDC no vàlida.");
    };
    let value = serde_json::to_string(&pending).expect("serializes");
    let jar = jar.add(cookie(&st, PENDING_COOKIE, value, "/_/auth/", 600));
    (jar, Redirect::to(url.as_str())).into_response()
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: serde_json::Value,
    exp: i64,
    nonce: Option<String>,
    sub: String,
    preferred_username: Option<String>,
}

/// `GET /_/auth/callback`
pub async fn callback(
    State(st): State<AppState>,
    jar: PrivateCookieJar,
    Query(q): Query<CallbackParams>,
) -> Response {
    let Some(oidc) = &st.oidc else {
        return pages::not_found();
    };
    let pending: Option<Pending> = jar
        .get(PENDING_COOKIE)
        .and_then(|c| serde_json::from_str(c.value()).ok());
    let jar = jar.remove(Cookie::build(PENDING_COOKIE).path("/_/auth/"));
    if let Some(err) = q.error {
        tracing::warn!(%err, "OIDC provider returned an error");
        return (
            jar,
            auth_error("El servidor d'identitat ha rebutjat l'inici de sessió."),
        )
            .into_response();
    }
    let (Some(pending), Some(code), Some(state)) = (pending, q.code, q.state) else {
        return (jar, Redirect::to("/_/auth/login")).into_response();
    };
    if pending.exp < token::now() || !bool::from(pending.state.as_bytes().ct_eq(state.as_bytes())) {
        return (jar, Redirect::to("/_/auth/login")).into_response();
    }
    let claims = match exchange(oidc, &code, &pending).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "OIDC code exchange failed");
            return (
                jar,
                auth_error("No s'ha pogut completar l'inici de sessió."),
            )
                .into_response();
        }
    };
    let user = claims.preferred_username.unwrap_or(claims.sub);
    if !oidc.cfg.allowed_users.is_empty() && !oidc.cfg.allowed_users.iter().any(|u| u == &user) {
        tracing::warn!(%user, "user not allowed to create links");
        let page = pages::message(
            StatusCode::FORBIDDEN,
            "Sense permís",
            "El teu usuari no pot crear enllaços.",
        );
        return (jar, page).into_response();
    }
    inc(&st.metrics.logins);
    tracing::info!(%user, "generator login");
    let session = Session {
        user,
        exp: token::now() + SESSION_SECONDS,
        csrf: random_b64(24),
    };
    let value = serde_json::to_string(&session).expect("serializes");
    let jar = jar.add(cookie(&st, SESSION_COOKIE, value, "/_/", SESSION_SECONDS));
    (jar, Redirect::to("/_/")).into_response()
}

async fn exchange(oidc: &Oidc, code: &str, pending: &Pending) -> anyhow::Result<Claims> {
    let meta = oidc.metadata().await?;
    let resp = oidc
        .http
        .post(&meta.token_endpoint)
        .basic_auth(&oidc.cfg.client_id, Some(&oidc.secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", oidc.redirect_uri.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ])
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "token endpoint HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let tokens: TokenResponse = resp.json().await?;
    let payload = tokens
        .id_token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("malformed id_token"))?;
    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
    let aud_ok = match &claims.aud {
        serde_json::Value::String(a) => a == &oidc.cfg.client_id,
        serde_json::Value::Array(v) => v
            .iter()
            .any(|a| a.as_str() == Some(oidc.cfg.client_id.as_str())),
        _ => false,
    };
    if claims.iss != meta.issuer
        || !aud_ok
        || claims.exp <= token::now()
        || claims.nonce.as_deref() != Some(pending.nonce.as_str())
    {
        anyhow::bail!("id_token validation failed (iss/aud/exp/nonce)");
    }
    Ok(claims)
}

/// `GET /_/auth/logout`
pub async fn logout(State(st): State<AppState>, jar: PrivateCookieJar) -> Response {
    let jar = jar.remove(Cookie::build(SESSION_COOKIE).path("/_/"));
    let target = match &st.oidc {
        Some(oidc) => match oidc
            .metadata()
            .await
            .ok()
            .and_then(|m| m.end_session_endpoint.clone())
        {
            Some(end) => url::Url::parse_with_params(
                &end,
                [
                    ("client_id", oidc.cfg.client_id.as_str()),
                    ("post_logout_redirect_uri", oidc.home.as_str()),
                ],
            )
            .map(|u| u.to_string())
            .unwrap_or_else(|_| "/_/".into()),
            None => "/_/".into(),
        },
        None => "/_/".into(),
    };
    (jar, Redirect::to(&target)).into_response()
}
