//! HTML pages (askama templates in `templates/`).

use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

/// Cache-busting value for `/_/assets/*`.
pub const ASSET_V: &str = env!("CARGO_PKG_VERSION");

#[derive(Template)]
#[template(path = "message.html")]
pub struct MessagePage<'a> {
    pub v: &'a str,
    pub title: &'a str,
    pub text: &'a str,
}

#[derive(Template)]
#[template(path = "password.html")]
pub struct PasswordPage<'a> {
    pub v: &'a str,
    pub action: &'a str,
    pub error: Option<&'a str>,
}

#[derive(Default, Clone)]
pub struct FormValues {
    pub url: String,
    pub ttl: String,
    pub date_utc: String,
    pub slug: String,
}

pub struct LinkResult {
    pub short_url: String,
    pub secure_url: String,
    pub file_name: String,
    pub size: Option<String>,
    pub expire_ts: i64,
    pub expire_utc: String,
    pub no_limit: bool,
    pub protected: bool,
}

#[derive(Template)]
#[template(path = "generator.html")]
pub struct GeneratorPage<'a> {
    pub v: &'a str,
    pub user: &'a str,
    pub csrf: &'a str,
    pub form: FormValues,
    pub error: Option<String>,
    pub result: Option<LinkResult>,
}

impl GeneratorPage<'_> {
    pub fn ttl_checked(&self, value: &str) -> bool {
        let ttl = if self.form.ttl.is_empty() {
            "+7d"
        } else {
            self.form.ttl.as_str()
        };
        ttl == value
    }
}

pub fn render(status: StatusCode, tpl: &impl Template) -> Response {
    match tpl.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template rendering failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

pub fn message(status: StatusCode, title: &str, text: &str) -> Response {
    render(
        status,
        &MessagePage {
            v: ASSET_V,
            title,
            text,
        },
    )
}

pub fn not_found() -> Response {
    message(
        StatusCode::NOT_FOUND,
        "Enllaç no trobat",
        "Aquest enllaç no existeix o no és vàlid. · This link does not exist.",
    )
}

pub fn expired() -> Response {
    message(
        StatusCode::GONE,
        "Enllaç caducat",
        "Aquest enllaç ha caducat. · This link has expired.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GeneratorPage<'static> {
        GeneratorPage {
            v: ASSET_V,
            user: "oriol",
            csrf: "tok<en>",
            form: FormValues {
                ttl: "+50y".into(),
                ..Default::default()
            },
            error: None,
            result: Some(LinkResult {
                short_url: "https://u.joor.net/vaga-s12".into(),
                secure_url: "https://n.joor.net/f731/1/3371301493/U9A3+/x==".into(),
                file_name: "GMT20261111 <rec>.mp4".into(),
                size: Some("795,8 MB".into()),
                expire_ts: 4_102_444_800,
                expire_utc: "2100-01-01T00:00:00Z".into(),
                no_limit: true,
                protected: true,
            }),
        }
    }

    #[test]
    fn generator_renders_and_escapes() {
        let html = sample().render().unwrap();
        assert!(html.contains("https://u.joor.net/vaga-s12"));
        assert!(html.contains("value=\"+50y\" checked"));
        assert!(html.contains("tok&#60;en&#62;") || html.contains("tok&lt;en&gt;"));
        assert!(!html.contains("<rec>"));
        if let Ok(path) = std::env::var("NFS_DUMP_HTML") {
            let html = html.replace(
                "/_/assets/",
                &format!("{}/assets/", env!("CARGO_MANIFEST_DIR")),
            );
            std::fs::write(path, html).unwrap();
        }
    }

    #[test]
    fn password_page_renders() {
        let html = PasswordPage {
            v: ASSET_V,
            action: "/v2/abc",
            error: Some("Contrasenya incorrecta."),
        }
        .render()
        .unwrap();
        assert!(html.contains("action=\"/v2/abc\""));
        assert!(html.contains("Contrasenya incorrecta."));
    }
}
