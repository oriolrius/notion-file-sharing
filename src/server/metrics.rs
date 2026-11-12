//! Prometheus counters (text exposition format), served on the admin listener.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub downloads_full: AtomicU64,
    pub downloads_partial: AtomicU64,
    pub links_not_found: AtomicU64,
    pub links_expired: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub notion_cache_hits: AtomicU64,
    pub notion_cache_misses: AtomicU64,
    pub notion_rate_limited: AtomicU64,
    pub links_created: AtomicU64,
    pub password_failures: AtomicU64,
    pub logins: AtomicU64,
}

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

impl Metrics {
    pub fn render(&self) -> String {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let mut out = String::new();
        let mut counter = |name: &str, help: &str, rows: &[(&str, u64)]| {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
            for (labels, v) in rows {
                let _ = writeln!(out, "{name}{labels} {v}");
            }
        };
        counter(
            "nfs_link_requests_total",
            "Requests to secure links by result.",
            &[
                ("{result=\"full\"}", g(&self.downloads_full)),
                ("{result=\"partial\"}", g(&self.downloads_partial)),
                ("{result=\"not_found\"}", g(&self.links_not_found)),
                ("{result=\"expired\"}", g(&self.links_expired)),
                ("{result=\"upstream_error\"}", g(&self.upstream_errors)),
            ],
        );
        counter(
            "nfs_bytes_sent_total",
            "File bytes streamed to clients.",
            &[("", g(&self.bytes_sent))],
        );
        counter(
            "nfs_notion_resolutions_total",
            "Block resolutions by source.",
            &[
                ("{source=\"cache\"}", g(&self.notion_cache_hits)),
                ("{source=\"api\"}", g(&self.notion_cache_misses)),
                ("{source=\"rate_limited\"}", g(&self.notion_rate_limited)),
            ],
        );
        counter(
            "nfs_links_created_total",
            "Links created with the web generator.",
            &[("", g(&self.links_created))],
        );
        counter(
            "nfs_password_failures_total",
            "Wrong passwords on protected links.",
            &[("", g(&self.password_failures))],
        );
        counter(
            "nfs_logins_total",
            "Successful generator logins.",
            &[("", g(&self.logins))],
        );
        out.push_str("# HELP nfs_build_info Build information.\n# TYPE nfs_build_info gauge\n");
        let _ = writeln!(
            out,
            "nfs_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );
        out
    }
}
