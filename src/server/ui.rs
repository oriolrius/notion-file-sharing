//! Language of the web pages, per request.
//!
//! A middleware reads the `nfs_lang` cookie (set by the selector), else `Accept-Language`, else
//! Catalan, and keeps the result in a task-local value for the page renderers. The selector links
//! go to `/_/lang/{code}?next=<current page>`, which sets the cookie and goes back (no JavaScript).

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;

use super::AppState;
use crate::i18n::{Lang, Texts};

pub const LANG_COOKIE: &str = "nfs_lang";
const LANG_COOKIE_SECONDS: i64 = 365 * 24 * 3600;

#[derive(Clone, Debug, Default)]
pub struct Ui {
    pub lang: Lang,
    /// Current page (path + query), where the selector goes back to. GET pages only.
    pub here: String,
}

pub struct LangLink {
    pub code: &'static str,
    pub name: &'static str,
    pub href: String,
    pub current: bool,
}

impl Ui {
    pub fn t(&self) -> &'static Texts {
        self.lang.t()
    }

    pub fn links(&self) -> Vec<LangLink> {
        let next = utf8_percent_encode(&self.here, NON_ALPHANUMERIC).to_string();
        Lang::ALL
            .iter()
            .map(|&l| LangLink {
                code: l.code(),
                name: l.name(),
                href: format!("/_/lang/{}?next={next}", l.code()),
                current: l == self.lang,
            })
            .collect()
    }
}

tokio::task_local! {
    static UI: Ui;
}

/// Language and page of the request being served (default outside a request).
pub fn current() -> Ui {
    UI.try_with(Ui::clone).unwrap_or_default()
}

pub fn lang() -> Lang {
    UI.try_with(|u| u.lang).unwrap_or_default()
}

pub fn detect(headers: &HeaderMap) -> Lang {
    let from_cookie = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| {
            let (k, v) = c.trim().split_once('=')?;
            (k == LANG_COOKIE).then(|| Lang::from_code(v)).flatten()
        });
    from_cookie
        .or_else(|| {
            headers
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok())
                .and_then(Lang::from_accept_language)
        })
        .unwrap_or_default()
}

/// Only local paths: never redirect to another site.
fn safe_next(next: &str) -> Option<&str> {
    let ok = next.starts_with('/')
        && !next.starts_with("//")
        && !next.starts_with("/\\")
        && !next.chars().any(|c| c.is_control());
    ok.then_some(next)
}

pub async fn layer(req: Request, next: Next) -> Response {
    let lang = detect(req.headers());
    // After a POST the selector goes back with a GET: the generator form, or the same link.
    let here = if req.method() == Method::GET {
        req.uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into())
    } else if req.uri().path().starts_with("/_/") {
        "/_/".into()
    } else {
        req.uri().path().to_string()
    };
    UI.scope(Ui { lang, here }, next.run(req)).await
}

#[derive(Deserialize)]
pub struct NextQuery {
    #[serde(default)]
    next: String,
}

/// `GET /_/lang/{code}?next=/path`
pub async fn set(
    State(st): State<AppState>,
    Path(code): Path<String>,
    Query(q): Query<NextQuery>,
    jar: CookieJar,
) -> Response {
    let target = safe_next(&q.next).unwrap_or("/_/").to_string();
    let Some(lang) = Lang::from_code(&code) else {
        return Redirect::to(&target).into_response();
    };
    let cookie = Cookie::build((LANG_COOKIE, lang.code()))
        .path("/")
        .http_only(true)
        .secure(st.secure_cookies)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(LANG_COOKIE_SECONDS));
    (jar.add(cookie), Redirect::to(&target)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn next_is_local_only() {
        assert_eq!(safe_next("/_/"), Some("/_/"));
        assert_eq!(safe_next("/v2/abc?x=1"), Some("/v2/abc?x=1"));
        assert_eq!(safe_next("//evil.example/"), None);
        assert_eq!(safe_next("/\\evil.example"), None);
        assert_eq!(safe_next("https://evil.example/"), None);
        assert_eq!(safe_next(""), None);
    }

    #[test]
    fn cookie_wins_over_accept_language() {
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US,en"),
        );
        assert_eq!(detect(&h), Lang::En);
        h.insert(header::COOKIE, HeaderValue::from_static("a=1; nfs_lang=es"));
        assert_eq!(detect(&h), Lang::Es);
        h.insert(header::COOKIE, HeaderValue::from_static("nfs_lang=fr"));
        assert_eq!(detect(&h), Lang::En);
        assert_eq!(detect(&HeaderMap::new()), Lang::Ca);
    }

    #[test]
    fn selector_links_return_to_the_page() {
        let ui = Ui {
            lang: Lang::Es,
            here: "/v2/ab_c?x=1".into(),
        };
        let links = ui.links();
        assert_eq!(links.len(), 3);
        assert_eq!(links[2].href, "/_/lang/en?next=%2Fv2%2Fab%5Fc%3Fx%3D1");
        assert!(links[1].current && !links[0].current);
    }
}

#[cfg(test)]
mod http_tests {
    use super::super::{router, test_support};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    async fn get(
        app: &axum::Router,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let mut req = Request::get(uri);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let h = resp.headers().clone();
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, h, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn pages_follow_the_language() {
        let app = router(test_support::state("http://127.0.0.1:9"));
        let (s, _, body) = get(&app, "/.env", &[]).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert!(body.contains("<html lang=\"ca\">") && body.contains("Enllaç no trobat"));

        let (_, _, body) = get(&app, "/.env", &[("accept-language", "es-ES,es;q=0.9")]).await;
        assert!(body.contains("<html lang=\"es\">") && body.contains("Enlace no encontrado"));

        let (_, _, body) = get(
            &app,
            "/.env",
            &[("accept-language", "es"), ("cookie", "nfs_lang=en")],
        )
        .await;
        assert!(body.contains("<html lang=\"en\">") && body.contains("Link not found"));
        // The selector returns to the same page.
        assert!(body.contains("href=\"/_/lang/ca?next=%2F%2Eenv\""));
    }

    #[tokio::test]
    async fn selector_sets_the_cookie_and_goes_back() {
        let app = router(test_support::state("http://127.0.0.1:9"));
        let (s, h, _) = get(&app, "/_/lang/es?next=%2Fv2%2Fabc", &[]).await;
        assert_eq!(s, StatusCode::SEE_OTHER);
        assert_eq!(h[header::LOCATION], "/v2/abc");
        let c = h[header::SET_COOKIE].to_str().unwrap();
        assert!(
            c.starts_with("nfs_lang=es")
                && c.contains("Path=/")
                && c.contains("HttpOnly")
                && c.contains("Secure"),
            "{c}"
        );

        let (_, h, _) = get(&app, "/_/lang/en?next=%2F%2Fevil.example%2F", &[]).await;
        assert_eq!(h[header::LOCATION], "/_/");
        let (_, h, _) = get(&app, "/_/lang/fr?next=%2Fx", &[]).await;
        assert_eq!(h[header::LOCATION], "/x");
        assert!(h.get(header::SET_COOKIE).is_none());
    }
}
