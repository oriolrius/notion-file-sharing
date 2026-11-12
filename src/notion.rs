//! Notion API client: block id → downloadable file, with a cache.
//!
//! Notion-hosted file URLs are valid for one hour (`expiry_time`), and the API allows ~3 requests/s.
//! A video player sends many `Range` requests, so the resolution is cached until shortly before the
//! URL expires, and concurrent misses for the same block share one API call.

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::links::normalize_block_id;

/// Refresh a cached URL this long before Notion's expiry.
const SAFETY_MARGIN: i64 = 5 * 60;
/// Fallback validity when the API gives no `expiry_time`.
const DEFAULT_VALIDITY: i64 = 55 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// File hosted by Notion (S3 pre-signed URL).
    Hosted { url: String },
    /// External URL (YouTube, …): we redirect, we never proxy it.
    External { url: String },
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub source: Source,
    pub file_name: String,
    pub block_type: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum NotionError {
    #[error("block not found or not shared with the integration")]
    NotFound,
    #[error("the block has no file ({0})")]
    NotAFile(String),
    #[error("Notion rate limit, retry after {0}s")]
    RateLimited(u64),
    #[error("Notion API error: {0}")]
    Upstream(String),
}

#[derive(Clone)]
pub struct Notion {
    http: reqwest::Client,
    api_url: String,
    api_key: String,
    version: String,
    cache: Cache<String, Arc<Resolved>>,
}

impl Notion {
    pub fn new(http: reqwest::Client, api_url: String, api_key: String, version: String) -> Self {
        Self {
            http,
            api_url,
            api_key,
            version,
            cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(3600))
                .build(),
        }
    }

    /// Resolve a block, from the cache when the cached URL is still fresh.
    /// Returns the value and whether it came from the cache.
    pub async fn resolve(&self, block_id: &str) -> Result<(Arc<Resolved>, bool), NotionError> {
        let key = normalize_block_id(block_id);
        for _ in 0..2 {
            let mut fetched = false;
            let value = self
                .cache
                .try_get_with(key.clone(), async {
                    fetched = true;
                    self.fetch(&key).await.map(Arc::new)
                })
                .await
                .map_err(|e: Arc<NotionError>| (*e).clone())?;
            if value.expires_at - SAFETY_MARGIN > crate::token::now() {
                return Ok((value, !fetched));
            }
            self.cache.invalidate(&key).await;
        }
        Err(NotionError::Upstream(
            "Notion returned an already expired URL".into(),
        ))
    }

    /// Drop a cached entry (e.g. the file URL answered 403).
    pub async fn forget(&self, block_id: &str) {
        self.cache.invalidate(&normalize_block_id(block_id)).await;
    }

    async fn fetch(&self, block_id: &str) -> Result<Resolved, NotionError> {
        let resp = self
            .http
            .get(format!("{}{}", self.api_url, block_id))
            .bearer_auth(&self.api_key)
            .header("Notion-Version", &self.version)
            .send()
            .await
            .map_err(|e| NotionError::Upstream(e.without_url().to_string()))?;
        let status = resp.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(5);
            return Err(NotionError::RateLimited(retry));
        }
        if status == reqwest::StatusCode::NOT_FOUND
            || status == reqwest::StatusCode::BAD_REQUEST
            || status == reqwest::StatusCode::FORBIDDEN
        {
            return Err(NotionError::NotFound);
        }
        if !status.is_success() {
            return Err(NotionError::Upstream(format!("HTTP {status}")));
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|e| NotionError::Upstream(e.without_url().to_string()))?;
        parse_block(&body, crate::token::now())
    }
}

/// Extract the file of a block object (`video`, `audio`, `file`, `pdf`, `image`, …).
pub fn parse_block(body: &Value, now: i64) -> Result<Resolved, NotionError> {
    let block_type = body["type"].as_str().unwrap_or_default().to_string();
    let obj = &body[&block_type];
    let kind = obj["type"].as_str().unwrap_or_default();
    let name_field = obj["name"]
        .as_str()
        .filter(|n| !n.is_empty())
        .map(str::to_string);
    match kind {
        "file" | "file_upload" => {
            let file = if kind == "file" {
                &obj["file"]
            } else {
                &obj["file_upload"]
            };
            let url = file["url"]
                .as_str()
                .ok_or_else(|| NotionError::NotAFile(block_type.clone()))?
                .to_string();
            let expires_at = file["expiry_time"]
                .as_str()
                .and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
                .map(|t| t.unix_timestamp())
                .unwrap_or(now + DEFAULT_VALIDITY);
            let file_name = name_field
                .or_else(|| file_name_from_url(&url))
                .unwrap_or_else(|| "file".into());
            Ok(Resolved {
                source: Source::Hosted { url },
                file_name,
                block_type,
                expires_at,
            })
        }
        "external" => {
            let url = obj["external"]["url"]
                .as_str()
                .ok_or_else(|| NotionError::NotAFile(block_type.clone()))?
                .to_string();
            let file_name = name_field
                .or_else(|| file_name_from_url(&url))
                .unwrap_or_else(|| "file".into());
            Ok(Resolved {
                source: Source::External { url },
                file_name,
                block_type,
                expires_at: i64::MAX,
            })
        }
        _ => Err(NotionError::NotAFile(if block_type.is_empty() {
            "unknown".into()
        } else {
            block_type
        })),
    }
}

/// Last path segment of the URL, percent-decoded (what the Lua server sent as file name).
pub fn file_name_from_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let last = parsed.path_segments()?.next_back()?;
    let name = percent_encoding::percent_decode_str(last)
        .decode_utf8_lossy()
        .to_string();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hosted_video() {
        let body = json!({
            "object": "block", "type": "video",
            "video": { "caption": [], "type": "file", "name": "vaga s12.mp4",
                "file": { "url": "https://prod-files-secure.s3.us-west-2.amazonaws.com/a/b/vaga%20s12.mp4?X-Amz-Signature=x",
                          "expiry_time": "2100-01-01T00:00:00.000Z" } }
        });
        let r = parse_block(&body, 0).unwrap();
        assert_eq!(r.block_type, "video");
        assert_eq!(r.file_name, "vaga s12.mp4");
        assert_eq!(r.expires_at, 4_102_444_800);
        assert!(matches!(r.source, Source::Hosted { .. }));
    }

    #[test]
    fn name_from_url_when_missing() {
        let body = json!({ "type": "file", "file": { "type": "file",
            "file": { "url": "https://s3.example/x/y/Informe%20final.pdf?sig=1" } } });
        let r = parse_block(&body, 100).unwrap();
        assert_eq!(r.file_name, "Informe final.pdf");
        assert_eq!(r.expires_at, 100 + DEFAULT_VALIDITY);
    }

    #[test]
    fn external_and_errors() {
        let ext = json!({ "type": "video", "video": { "type": "external", "external": { "url": "https://youtu.be/abc" } } });
        assert_eq!(
            parse_block(&ext, 0).unwrap().source,
            Source::External {
                url: "https://youtu.be/abc".into()
            }
        );
        let para = json!({ "type": "paragraph", "paragraph": { "rich_text": [] } });
        assert!(matches!(parse_block(&para, 0), Err(NotionError::NotAFile(t)) if t == "paragraph"));
    }
}
