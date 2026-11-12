//! Web generator: `/_/` form (OIDC login required) → secure URL + short URL.

use axum::extract::{Form, Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::PrivateCookieJar;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use super::AppState;
use super::auth::{self, Session};
use super::metrics::inc;
use super::pages::{self, ASSET_V, FormValues, GeneratorPage, LinkResult};
use crate::links;
use crate::notion::{NotionError, Source};
use crate::token;

const TTL_CHOICES: &[&str] = &["+24h", "+7d", "+30d", "+1y", "+50y", "date"];

#[allow(clippy::result_large_err)] // the error is the response to send (axum pattern)
fn require_session(st: &AppState, jar: &PrivateCookieJar) -> Result<Session, Response> {
    if st.oidc.is_none() {
        return Err(pages::message(
            StatusCode::NOT_FOUND,
            "Generador desactivat",
            "Aquest servidor no té el generador actiu.",
        ));
    }
    auth::session(jar).ok_or_else(|| Redirect::to("/_/auth/login").into_response())
}

/// `GET /_/`
pub async fn form(State(st): State<AppState>, jar: PrivateCookieJar) -> Response {
    let session = match require_session(&st, &jar) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let page = GeneratorPage {
        v: ASSET_V,
        user: &session.user,
        csrf: &session.csrf,
        form: FormValues::default(),
        error: None,
        result: None,
    };
    pages::render(StatusCode::OK, &page)
}

#[derive(Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    ttl: String,
    #[serde(default)]
    date_utc: String,
    /// `datetime-local` value, used (as UTC) only when JavaScript did not fill `date_utc`.
    #[serde(default)]
    date: String,
    #[serde(default)]
    slug: String,
    #[serde(default)]
    password: String,
}

/// `POST /_/links`
pub async fn create(
    State(st): State<AppState>,
    jar: PrivateCookieJar,
    Form(f): Form<CreateForm>,
) -> Response {
    let session = match require_session(&st, &jar) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !bool::from(f.csrf.as_bytes().ct_eq(session.csrf.as_bytes())) {
        return pages::message(
            StatusCode::FORBIDDEN,
            "Sessió caducada",
            "Torna a carregar la pàgina i prova-ho de nou.",
        );
    }
    let date_utc = if f.date_utc.is_empty() && !f.date.is_empty() {
        format!("{}:00Z", f.date)
    } else {
        f.date_utc.clone()
    };
    let values = FormValues {
        url: f.url.trim().into(),
        ttl: f.ttl.clone(),
        date_utc,
        slug: f.slug.trim().into(),
    };
    let page = |error: Option<String>, result: Option<LinkResult>, form: FormValues| {
        let status = if error.is_some() {
            StatusCode::UNPROCESSABLE_ENTITY
        } else {
            StatusCode::OK
        };
        let p = GeneratorPage {
            v: ASSET_V,
            user: &session.user,
            csrf: &session.csrf,
            form,
            error,
            result,
        };
        pages::render(status, &p)
    };
    match build(&st, &session.user, &values, &f.password).await {
        Ok(result) => page(
            None,
            Some(result),
            FormValues {
                ttl: values.ttl,
                ..Default::default()
            },
        ),
        Err(msg) => page(Some(msg), None, values),
    }
}

async fn build(
    st: &AppState,
    user: &str,
    f: &FormValues,
    password: &str,
) -> Result<LinkResult, String> {
    let block_id = links::block_id_from_url(&f.url)?;
    let now = token::now();
    if !TTL_CHOICES.contains(&f.ttl.as_str()) {
        return Err("tria una caducitat".into());
    }
    let spec = if f.ttl == "date" {
        if f.date_utc.is_empty() {
            return Err("tria la data de caducitat".into());
        }
        f.date_utc.as_str()
    } else {
        f.ttl.as_str()
    };
    let expire = links::parse_expire(spec, now)?;
    let slug = (!f.slug.is_empty()).then_some(f.slug.as_str());
    if let Some(s) = slug {
        links::validate_slug(s)?;
    }

    // Check now that the block exists and the Notion integration can read it.
    let (resolved, _) = st.notion.resolve(&block_id).await.map_err(|e| match e {
        NotionError::NotFound => "Notion no troba el bloc: comprova l'enllaç i que la pàgina estigui compartida amb la integració".to_string(),
        NotionError::NotAFile(t) => format!("aquest bloc ({t}) no conté cap fitxer"),
        NotionError::RateLimited(s) => format!("Notion està limitant peticions; torna-ho a provar d'aquí a {s} s"),
        NotionError::Upstream(_) => "error consultant Notion; torna-ho a provar".to_string(),
    })?;
    let size = match &resolved.source {
        Source::Hosted { url } => file_size(st, url).await,
        Source::External { .. } => None,
    };

    let protected = !password.is_empty();
    let path = links::secure_path(
        &st.keys,
        &st.cfg.customer_id,
        expire,
        &block_id,
        Some(password),
    );
    let secure_url = format!("{}{}", st.cfg.base_url, path);
    let expire_in = links::kutt_expire_in(expire, now);
    let description = format!("NFS: {}", resolved.file_name);
    let short = st
        .kutt
        .create(&secure_url, slug, expire_in.as_deref(), &description)
        .await
        .map_err(|e| format!("l'escurçador (Kutt) ha fallat: {e}"))?;

    inc(&st.metrics.links_created);
    tracing::info!(%user, block = &block_id[..8], expire, protected, short = %short.link, "link created");
    Ok(LinkResult {
        short_url: short.link,
        secure_url,
        file_name: resolved.file_name.clone(),
        size,
        expire_ts: expire,
        expire_utc: links::format_ts(expire),
        no_limit: expire_in.is_none(),
        protected,
    })
}

/// Total size from a 1-byte range request (pre-signed URLs only allow GET).
async fn file_size(st: &AppState, url: &str) -> Option<String> {
    let resp = st
        .files
        .get(url)
        .header(header::RANGE, "bytes=0-0")
        .send()
        .await
        .ok()?;
    let total: u64 = resp
        .headers()
        .get(header::CONTENT_RANGE)?
        .to_str()
        .ok()?
        .rsplit('/')
        .next()?
        .parse()
        .ok()?;
    Some(human_size(total))
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{:.1} {}", v, UNITS[i]).replace('.', ",")
    }
}

// ---------------------------------------------------------------- static assets

struct Asset {
    name: &'static str,
    mime: &'static str,
    body: &'static [u8],
}

const ASSETS: &[Asset] = &[
    Asset {
        name: "app.css",
        mime: "text/css; charset=utf-8",
        body: include_bytes!("../../assets/app.css"),
    },
    Asset {
        name: "app.js",
        mime: "text/javascript; charset=utf-8",
        body: include_bytes!("../../assets/app.js"),
    },
    Asset {
        name: "favicon.svg",
        mime: "image/svg+xml",
        body: include_bytes!("../../assets/favicon.svg"),
    },
    Asset {
        name: "ubuntu-300.woff2",
        mime: "font/woff2",
        body: include_bytes!("../../assets/fonts/ubuntu-latin-300-normal.woff2"),
    },
    Asset {
        name: "ubuntu-400.woff2",
        mime: "font/woff2",
        body: include_bytes!("../../assets/fonts/ubuntu-latin-400-normal.woff2"),
    },
    Asset {
        name: "ubuntu-500.woff2",
        mime: "font/woff2",
        body: include_bytes!("../../assets/fonts/ubuntu-latin-500-normal.woff2"),
    },
    Asset {
        name: "ubuntu-700.woff2",
        mime: "font/woff2",
        body: include_bytes!("../../assets/fonts/ubuntu-latin-700-normal.woff2"),
    },
    Asset {
        name: "ubuntu-mono-400.woff2",
        mime: "font/woff2",
        body: include_bytes!("../../assets/fonts/ubuntu-mono-latin-400-normal.woff2"),
    },
];

/// `GET /_/assets/{file}`
pub async fn asset(Path(file): Path<String>) -> Response {
    match ASSETS.iter().find(|a| a.name == file) {
        Some(a) => {
            let mut r = a.body.into_response();
            r.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(a.mime));
            r.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400"),
            );
            r
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(795_840_218), "795,8 MB");
        assert_eq!(human_size(1_500_000_000), "1,5 GB");
    }
}
