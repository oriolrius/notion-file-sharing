//! Kutt URL shortener (u.joor.net) API v2.

use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
pub enum KuttError {
    #[error("{0}")]
    Rejected(String),
    #[error("Kutt API error: {0}")]
    Upstream(String),
}

#[derive(Clone)]
pub struct Kutt {
    http: reqwest::Client,
    api_url: String,
    api_key: String,
}

pub struct ShortLink {
    pub id: String,
    pub link: String,
}

impl Kutt {
    pub fn new(http: reqwest::Client, api_url: String, api_key: String) -> Self {
        Self {
            http,
            api_url,
            api_key,
        }
    }

    /// Create a short link. `expire_in` uses Kutt's format (`"90 minutes"`); `None` = never.
    pub async fn create(
        &self,
        target: &str,
        slug: Option<&str>,
        expire_in: Option<&str>,
        description: &str,
    ) -> Result<ShortLink, KuttError> {
        let mut body = json!({ "target": target, "description": description, "reuse": false });
        if let Some(s) = slug.filter(|s| !s.is_empty()) {
            body["customurl"] = json!(s);
        }
        if let Some(e) = expire_in {
            body["expire_in"] = json!(e);
        }
        let resp = self
            .http
            .post(&self.api_url)
            .header("X-API-KEY", &self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| KuttError::Upstream(e.without_url().to_string()))?;
        let status = resp.status();
        let value: Value = resp.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            let link = value["link"]
                .as_str()
                .ok_or_else(|| KuttError::Upstream("response without link".into()))?;
            let id = value["id"].as_str().unwrap_or_default();
            return Ok(ShortLink {
                id: id.to_string(),
                link: link.to_string(),
            });
        }
        let msg = value["error"].as_str().unwrap_or("").to_string();
        if status.is_client_error() && !msg.is_empty() {
            Err(KuttError::Rejected(msg))
        } else {
            Err(KuttError::Upstream(format!("HTTP {status} {msg}")))
        }
    }

    /// Delete a short link by id (used by tests and cleanup).
    pub async fn delete(&self, id: &str) -> Result<(), KuttError> {
        let resp = self
            .http
            .delete(format!("{}/{}", self.api_url.trim_end_matches('/'), id))
            .header("X-API-KEY", &self.api_key)
            .send()
            .await
            .map_err(|e| KuttError::Upstream(e.without_url().to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(KuttError::Upstream(format!("HTTP {}", resp.status())))
        }
    }
}

/// Follow one redirect of a short URL and return its target (`Location`).
pub async fn unshorten(
    http_no_redirect: &reqwest::Client,
    short_url: &str,
) -> anyhow::Result<String> {
    let resp = http_no_redirect.get(short_url).send().await?;
    if !resp.status().is_redirection() {
        anyhow::bail!("{short_url} is not a redirect (HTTP {})", resp.status());
    }
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("redirect without Location"))?;
    Ok(location.to_string())
}
