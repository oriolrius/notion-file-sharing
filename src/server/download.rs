//! Public side: resolve a secure link and stream the file (no authentication).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, Form, Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::AppState;
use super::metrics::inc;
use super::pages::{self, ASSET_V, PasswordPage};
use crate::notion::{NotionError, Source};
use crate::token::{self, LinkError, V1Link};

const UNLOCK_SECONDS: i64 = 12 * 3600;

/// `GET /<sig>/<cid>/<exp>/<cipher>` — legacy v1 links (fallback route).
pub async fn v1(
    State(st): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return pages::not_found();
    }
    let path = percent_encoding::percent_decode_str(uri.path())
        .decode_utf8_lossy()
        .to_string();
    let Some(link) = V1Link::parse(&path) else {
        inc(&st.metrics.links_not_found);
        return pages::not_found();
    };
    match token::v1_decode(&st.keys, &link, token::now()) {
        Ok(block_id) => serve_block(&st, &block_id, &headers).await,
        Err(e) => link_error(&st, e, &link.sig),
    }
}

fn link_error(st: &AppState, e: LinkError, id: &str) -> Response {
    let short = &id[..id.len().min(8)];
    match e {
        LinkError::Expired => {
            inc(&st.metrics.links_expired);
            tracing::info!(link = short, "expired link");
            pages::expired()
        }
        _ => {
            inc(&st.metrics.links_not_found);
            tracing::info!(link = short, reason = %e, "rejected link");
            pages::not_found()
        }
    }
}

fn unlock_cookie_name(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!("nfs_pw_{}", &hex::encode(digest)[..16])
}

fn is_unlocked(jar: &PrivateCookieJar, token: &str) -> bool {
    jar.get(&unlock_cookie_name(token))
        .and_then(|c| c.value().parse::<i64>().ok())
        .is_some_and(|until| until > token::now())
}

/// `GET /v2/<token>`
pub async fn v2_get(
    State(st): State<AppState>,
    Path(tok): Path<String>,
    jar: PrivateCookieJar,
    headers: HeaderMap,
) -> Response {
    let payload = match token::v2_decode(&st.keys, &tok, token::now()) {
        Ok(p) => p,
        Err(e) => return link_error(&st, e, &tok),
    };
    if payload.p.is_some() && !is_unlocked(&jar, &tok) {
        let action = format!("/v2/{tok}");
        return pages::render(
            StatusCode::OK,
            &PasswordPage {
                v: ASSET_V,
                action: &action,
                error: None,
            },
        );
    }
    serve_block(&st, &payload.b, &headers).await
}

#[derive(Deserialize)]
pub struct PasswordForm {
    #[serde(default)]
    password: String,
}

/// `POST /v2/<token>` — password form.
pub async fn v2_post(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(tok): Path<String>,
    jar: PrivateCookieJar,
    Form(form): Form<PasswordForm>,
) -> Response {
    let payload = match token::v2_decode(&st.keys, &tok, token::now()) {
        Ok(p) => p,
        Err(e) => return link_error(&st, e, &tok),
    };
    let action = format!("/v2/{tok}");
    let Some(hash) = payload.p else {
        return Redirect::to(&action).into_response();
    };
    let ip = client_ip(&headers, peer);
    if !st.limiter.allow(ip) {
        let page = PasswordPage {
            v: ASSET_V,
            action: &action,
            error: Some("Massa intents. Torna-ho a provar d'aquí a uns minuts."),
        };
        return pages::render(StatusCode::TOO_MANY_REQUESTS, &page);
    }
    let pw = form.password;
    let ok = tokio::task::spawn_blocking(move || hash.verify(&pw))
        .await
        .unwrap_or(false);
    if !ok {
        inc(&st.metrics.password_failures);
        tracing::info!(link = &tok[..8.min(tok.len())], %ip, "wrong password");
        let page = PasswordPage {
            v: ASSET_V,
            action: &action,
            error: Some("Contrasenya incorrecta."),
        };
        return pages::render(StatusCode::UNAUTHORIZED, &page);
    }
    let until = (token::now() + UNLOCK_SECONDS).min(payload.e);
    let cookie = Cookie::build((unlock_cookie_name(&tok), until.to_string()))
        .path(action.clone())
        .http_only(true)
        .secure(st.secure_cookies)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(until - token::now()));
    (jar.add(cookie), Redirect::to(&action)).into_response()
}

/// Client address: `X-Real-IP` from the reverse proxy, else the TCP peer.
fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(peer.ip())
}

/// Password attempts: 10 per IP per 10 minutes.
#[derive(Default)]
pub struct Limiter(Mutex<HashMap<IpAddr, (u32, Instant)>>);

impl Limiter {
    const MAX: u32 = 10;
    const WINDOW: Duration = Duration::from_secs(600);

    pub fn allow(&self, ip: IpAddr) -> bool {
        let mut map = self.0.lock().expect("limiter lock");
        let now = Instant::now();
        if map.len() > 10_000 {
            map.retain(|_, (_, start)| now.duration_since(*start) < Self::WINDOW);
        }
        let entry = map.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= Self::WINDOW {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0 <= Self::MAX
    }
}

async fn serve_block(st: &AppState, block_id: &str, headers: &HeaderMap) -> Response {
    for attempt in 0..2 {
        let resolved = match st.notion.resolve(block_id).await {
            Ok((r, cached)) => {
                inc(if cached {
                    &st.metrics.notion_cache_hits
                } else {
                    &st.metrics.notion_cache_misses
                });
                r
            }
            Err(NotionError::NotFound) | Err(NotionError::NotAFile(_)) => {
                inc(&st.metrics.links_not_found);
                tracing::warn!(
                    block = &block_id[..8.min(block_id.len())],
                    "block not available in Notion"
                );
                return pages::not_found();
            }
            Err(NotionError::RateLimited(secs)) => {
                inc(&st.metrics.notion_rate_limited);
                let mut r = pages::message(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Torna-ho a provar",
                    "Servei ocupat. Torna-ho a provar en uns segons.",
                );
                r.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(secs));
                return r;
            }
            Err(e) => {
                inc(&st.metrics.upstream_errors);
                tracing::error!(error = %e, "Notion resolution failed");
                return pages::message(
                    StatusCode::BAD_GATEWAY,
                    "Error temporal",
                    "No s'ha pogut obtenir el fitxer. Torna-ho a provar.",
                );
            }
        };
        let url = match &resolved.source {
            Source::External { url } => {
                return (StatusCode::FOUND, [(header::LOCATION, url.as_str())]).into_response();
            }
            Source::Hosted { url } => url.clone(),
        };

        let mut req = st.files.get(&url);
        for name in [header::RANGE, header::IF_RANGE] {
            if let Some(v) = headers.get(&name) {
                req = req.header(name, v);
            }
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                inc(&st.metrics.upstream_errors);
                tracing::error!(error = %e.without_url(), "file request failed");
                return pages::message(
                    StatusCode::BAD_GATEWAY,
                    "Error temporal",
                    "No s'ha pogut obtenir el fitxer. Torna-ho a provar.",
                );
            }
        };
        let status = resp.status().as_u16();
        // A 403 from S3 means the pre-signed URL expired early: resolve again once.
        if status == 403 && attempt == 0 {
            st.notion.forget(block_id).await;
            continue;
        }
        let status = match status {
            200 => {
                inc(&st.metrics.downloads_full);
                StatusCode::OK
            }
            206 => {
                inc(&st.metrics.downloads_partial);
                StatusCode::PARTIAL_CONTENT
            }
            416 => StatusCode::RANGE_NOT_SATISFIABLE,
            404 => return pages::not_found(),
            other => {
                inc(&st.metrics.upstream_errors);
                tracing::error!(status = other, "unexpected status from file host");
                return pages::message(
                    StatusCode::BAD_GATEWAY,
                    "Error temporal",
                    "No s'ha pogut obtenir el fitxer. Torna-ho a provar.",
                );
            }
        };

        let mut builder = Response::builder().status(status);
        let out = builder.headers_mut().expect("builder ok");
        for name in [
            header::CONTENT_LENGTH,
            header::CONTENT_RANGE,
            header::ETAG,
            header::LAST_MODIFIED,
        ] {
            if let Some(v) = resp.headers().get(&name) {
                out.insert(name, v.clone());
            }
        }
        out.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        out.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        out.insert(
            header::CONTENT_DISPOSITION,
            content_disposition(&resolved.file_name),
        );
        out.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, max-age=0"),
        );
        out.insert(
            HeaderName::from_static("x-robots-tag"),
            HeaderValue::from_static("noindex"),
        );

        let st2 = st.clone();
        let stream = resp.bytes_stream().map(move |chunk| {
            if let Ok(b) = &chunk {
                st2.metrics
                    .bytes_sent
                    .fetch_add(b.len() as u64, std::sync::atomic::Ordering::Relaxed);
            }
            chunk
        });
        return builder
            .body(Body::from_stream(stream))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    inc(&st.metrics.upstream_errors);
    pages::message(
        StatusCode::BAD_GATEWAY,
        "Error temporal",
        "No s'ha pogut obtenir el fitxer. Torna-ho a provar.",
    )
}

/// `attachment; filename="ascii"; filename*=UTF-8''percent-encoded`
pub fn content_disposition(name: &str) -> HeaderValue {
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    const SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    let encoded = percent_encoding::utf8_percent_encode(name, SET);
    HeaderValue::from_str(&format!(
        "attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{router, test_support};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use wiremock::matchers::{header as hdr, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const BLOCK: &str = "416c413b2a6881ba87eaebad1f979d66";

    async fn mock_notion(server: &MockServer, file_url: String) {
        Mock::given(method("GET"))
            .and(path(format!("/v1/blocks/{BLOCK}")))
            .and(hdr("authorization", "Bearer secret_test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "block", "type": "video",
                "video": { "type": "file", "name": "vaga s12.mp4",
                    "file": { "url": file_url, "expiry_time": "2100-01-01T00:00:00.000Z" } }
            })))
            .expect(1) // second request must hit the cache
            .mount(server)
            .await;
    }

    fn request(uri: &str, range: Option<&str>) -> axum::http::Request<Body> {
        let mut b = axum::http::Request::builder().uri(uri);
        if let Some(r) = range {
            b = b.header("range", r);
        }
        let mut req = b.body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))));
        req
    }

    #[tokio::test]
    async fn v1_link_streams_with_range_and_cache() {
        let server = MockServer::start().await;
        mock_notion(&server, format!("{}/s3/vaga.mp4?sig=1", server.uri())).await;
        Mock::given(method("GET"))
            .and(path("/s3/vaga.mp4"))
            .and(hdr("range", "bytes=0-3"))
            .respond_with(
                ResponseTemplate::new(206)
                    .insert_header("content-range", "bytes 0-3/10")
                    .set_body_bytes(b"0123".to_vec()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/s3/vaga.mp4"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"0123456789".to_vec()))
            .mount(&server)
            .await;

        let st = test_support::state(&server.uri());
        let link = crate::token::v1_encode(&st.keys, "1", 4102444800, BLOCK).path();
        let app = router(st);

        let resp = app
            .clone()
            .oneshot(request(&link, Some("bytes=0-3")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.headers()["content-range"], "bytes 0-3/10");
        assert_eq!(resp.headers()["accept-ranges"], "bytes");
        assert_eq!(resp.headers()["content-type"], "application/octet-stream");
        assert!(
            resp.headers()["content-disposition"]
                .to_str()
                .unwrap()
                .contains("vaga%20s12.mp4")
        );
        assert_eq!(
            &resp.into_body().collect().await.unwrap().to_bytes()[..],
            b"0123"
        );

        let resp = app.oneshot(request(&link, None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            &resp.into_body().collect().await.unwrap().to_bytes()[..],
            b"0123456789"
        );
    }

    #[tokio::test]
    async fn bad_and_expired_links() {
        let server = MockServer::start().await;
        let st = test_support::state(&server.uri());
        let expired = crate::token::v1_encode(&st.keys, "1", 1000, BLOCK).path();
        let good = crate::token::v1_encode(&st.keys, "1", 4102444800, BLOCK).path();
        let tampered = good.replacen("/1/", "/2/", 1);
        let app = router(st);
        assert_eq!(
            app.clone()
                .oneshot(request(&expired, None))
                .await
                .unwrap()
                .status(),
            StatusCode::GONE
        );
        assert_eq!(
            app.clone()
                .oneshot(request(&tampered, None))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            app.clone()
                .oneshot(request("/.env", None))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            app.oneshot(request("/v2/AAAA", None))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn password_link_requires_password() {
        let server = MockServer::start().await;
        mock_notion(&server, format!("{}/s3/vaga.mp4?sig=1", server.uri())).await;
        Mock::given(method("GET"))
            .and(path("/s3/vaga.mp4"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"data".to_vec()))
            .mount(&server)
            .await;
        let st = test_support::state(&server.uri());
        let link = crate::links::secure_path(&st.keys, "1", 4102444800, BLOCK, Some("s3cret"));
        assert!(link.starts_with("/v2/"));
        let app = router(st);

        // no cookie: password page, no file
        let resp = app.clone().oneshot(request(&link, None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );

        let post = |pw: &str| {
            let mut req = axum::http::Request::builder()
                .method("POST")
                .uri(&link)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("password={pw}")))
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))));
            req
        };
        assert_eq!(
            app.clone().oneshot(post("wrong")).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let ok = app.clone().oneshot(post("s3cret")).await.unwrap();
        assert_eq!(ok.status(), StatusCode::SEE_OTHER);
        let cookie = ok.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        let mut req = request(&link, None);
        req.headers_mut()
            .insert("cookie", HeaderValue::from_str(&cookie).unwrap());
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "application/octet-stream");
        assert_eq!(
            &resp.into_body().collect().await.unwrap().to_bytes()[..],
            b"data"
        );
    }

    #[test]
    fn disposition_header() {
        let v = content_disposition("Vaga \"S12\" àè.mp4");
        assert_eq!(
            v,
            "attachment; filename=\"Vaga _S12_ __.mp4\"; filename*=UTF-8''Vaga%20%22S12%22%20%C3%A0%C3%A8.mp4"
        );
    }

    #[test]
    fn limiter_blocks_after_ten() {
        let l = Limiter::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!((0..10).all(|_| l.allow(ip)));
        assert!(!l.allow(ip));
        assert!(l.allow("10.0.0.2".parse().unwrap()));
    }
}
