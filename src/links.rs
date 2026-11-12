//! Shared link-building logic (CLI and web generator).

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::token::{self, Keys, PasswordHash, V2Payload};

/// Seconds in the units the old CLI accepted (`y` = 365 days, as in the Lua code).
const MINUTE: i64 = 60;
const HOUR: i64 = 60 * MINUTE;
const DAY: i64 = 24 * HOUR;
const YEAR: i64 = 365 * DAY;

/// Links that live this long or longer get a short URL without expiry.
pub const NO_LIMIT_THRESHOLD: i64 = 10 * YEAR;

/// Parse `+30m`, `+24h`, `+7d`, `+2w`, `+50y` or an RFC 3339 / ISO date (`2026-12-31T23:59:59Z`).
pub fn parse_expire(spec: &str, now: i64) -> Result<i64, String> {
    let spec = spec.trim();
    if let Some(rel) = spec.strip_prefix('+') {
        let (num, unit) = rel.split_at(rel.len().saturating_sub(1));
        let n: i64 = num
            .parse()
            .map_err(|_| format!("invalid duration: {spec}"))?;
        if n <= 0 {
            return Err(format!("duration must be positive: {spec}"));
        }
        let mult = match unit {
            "m" => MINUTE,
            "h" => HOUR,
            "d" => DAY,
            "w" => 7 * DAY,
            "y" => YEAR,
            _ => return Err(format!("unknown unit in {spec} (use m, h, d, w or y)")),
        };
        return n
            .checked_mul(mult)
            .and_then(|d| d.checked_add(now))
            .ok_or_else(|| "duration too long".into());
    }
    let ts = OffsetDateTime::parse(spec, &Rfc3339)
        .map_err(|_| format!("invalid date: {spec} (use +24h, +7d, +1y or 2026-12-31T23:59:59Z)"))?
        .unix_timestamp();
    if ts <= now {
        return Err("the expiry date is in the past".into());
    }
    Ok(ts)
}

/// Kutt `expire_in` value for a link valid until `expire`, or `None` for "no limit".
pub fn kutt_expire_in(expire: i64, now: i64) -> Option<String> {
    let secs = expire - now;
    if secs >= NO_LIMIT_THRESHOLD {
        return None;
    }
    let minutes = (secs + MINUTE - 1) / MINUTE;
    Some(format!("{} minutes", minutes.max(1)))
}

/// Extract the block id from a Notion "copy link to block" URL (`…#<block_id>`).
/// Accepts 32 hex chars or a dashed UUID; returns it as given (lowercase).
pub fn block_id_from_url(input: &str) -> Result<String, String> {
    let url = url::Url::parse(input.trim()).map_err(|_| "not a valid URL".to_string())?;
    if url.scheme() != "https" {
        return Err("the URL must start with https://".into());
    }
    let host = url.host_str().unwrap_or_default();
    let notion = ["notion.so", "notion.com", "notion.site"]
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")));
    if !notion {
        return Err("it is not a Notion URL (notion.so / notion.com)".into());
    }
    let fragment = url.fragment().unwrap_or_default();
    if fragment.is_empty() {
        return Err(
            "the URL has no block id (#…): copy the link to the block, not to the page".into(),
        );
    }
    let id = fragment.to_ascii_lowercase();
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    let ok = hex.len() == 32
        && hex.chars().all(|c| c.is_ascii_hexdigit())
        && (id.len() == 32 || id.len() == 36);
    if !ok {
        return Err(format!("“#{fragment}” is not a Notion block id"));
    }
    Ok(id)
}

/// Normalized block id (32 lowercase hex), used as cache key and for API calls.
pub fn normalize_block_id(id: &str) -> String {
    id.chars()
        .filter(|c| *c != '-')
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Build the path of a new secure link: v1 without password (frozen format), v2 with password.
pub fn secure_path(
    keys: &Keys,
    customer_id: &str,
    expire: i64,
    block_id: &str,
    password: Option<&str>,
) -> String {
    match password.filter(|p| !p.is_empty()) {
        None => token::v1_encode(keys, customer_id, expire, block_id).path(),
        Some(pw) => {
            let payload = V2Payload {
                b: block_id.to_string(),
                c: customer_id.to_string(),
                e: expire,
                p: Some(PasswordHash::new(pw)),
            };
            format!("/v2/{}", token::v2_encode(keys, &payload))
        }
    }
}

/// Slug rules for the short URL (Kutt custom URL).
pub fn validate_slug(slug: &str) -> Result<(), String> {
    let ok = (3..=64).contains(&slug.len())
        && slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err("the alias must have 3–64 characters: letters, digits, - or _".into())
    }
}

pub fn format_ts(ts: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| ts.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expire_relative_and_absolute() {
        let now = 1_000_000;
        assert_eq!(parse_expire("+24h", now).unwrap(), now + 86_400);
        assert_eq!(parse_expire("+7d", now).unwrap(), now + 7 * 86_400);
        assert_eq!(parse_expire("+50y", now).unwrap(), now + 50 * 365 * 86_400);
        assert_eq!(parse_expire("+30m", now).unwrap(), now + 1_800);
        assert_eq!(
            parse_expire("2100-01-01T00:00:00Z", now).unwrap(),
            4_102_444_800
        );
        assert!(parse_expire("+0d", now).is_err());
        assert!(parse_expire("+5x", now).is_err());
        assert!(parse_expire("1970-01-02T00:00:00Z", now).is_err());
        assert!(parse_expire("tomorrow", now).is_err());
    }

    #[test]
    fn kutt_expiry() {
        assert_eq!(
            kutt_expire_in(1000 + 86_400, 1000).as_deref(),
            Some("1440 minutes")
        );
        assert_eq!(
            kutt_expire_in(1000 + 61, 1000).as_deref(),
            Some("2 minutes")
        );
        assert_eq!(kutt_expire_in(1000 + 50 * YEAR, 1000), None);
    }

    #[test]
    fn block_ids() {
        let u = "https://app.notion.com/p/oriolrius/2026-11-11-dimecres-Vaga-General-S-esade-S12-412c413b2a6881be828afdf80b770d68?source=copy_link#416c413b2a6881ba87eaebad1f979d66";
        assert_eq!(
            block_id_from_url(u).unwrap(),
            "416c413b2a6881ba87eaebad1f979d66"
        );
        assert_eq!(
            block_id_from_url("https://www.notion.so/x#1C2D3E4F-5A6B-7C8D-9E0F-A1B2C3D4E5F6")
                .unwrap(),
            "1c2d3e4f-5a6b-7c8d-9e0f-a1b2c3d4e5f6"
        );
        assert!(
            block_id_from_url("https://www.notion.so/page-412c413b2a6881be828afdf80b770d68")
                .is_err()
        );
        assert!(
            block_id_from_url("https://evil.example/x#416c413b2a6881ba87eaebad1f979d66").is_err()
        );
        assert!(
            block_id_from_url("http://www.notion.so/x#416c413b2a6881ba87eaebad1f979d66").is_err()
        );
        assert!(block_id_from_url("https://www.notion.so/x#zz").is_err());
        assert_eq!(
            normalize_block_id("1C2D3E4F-5A6B-7C8D-9E0F-A1B2C3D4E5F6"),
            "1c2d3e4f5a6b7c8d9e0fa1b2c3d4e5f6"
        );
    }

    #[test]
    fn slugs() {
        assert!(validate_slug("vaga-s12").is_ok());
        assert!(validate_slug("ab").is_err());
        assert!(validate_slug("a b c").is_err());
    }
}
