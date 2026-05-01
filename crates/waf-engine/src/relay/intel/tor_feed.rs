//! FR-007 phase-04 — Tor exit list refresh feed.
//!
//! HTTP GET against the Tor Project list w/ `If-None-Match`, atomic file
//! swap on 200, no-op on 304, error retain on other. Air-gap: when
//! `url=None`, refresh is a no-op — operator drops the file by hand and
//! the watcher (phase-05) picks it up.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use reqwest::Client;
use url::Url;

use super::atomic_swap::SizeBounds;
use super::feed_helpers::http_etag_swap;
use super::{IntelProvider, RefreshOutcome};
use crate::relay::providers::tor_exit::TorSet;

/// Sanity bounds for Tor exit list (text). Real list ~50KB; allow 10KB
/// floor (catches truncated/empty drops) and 10MB ceiling (catches
/// runaway/poisoned feeds).
const TOR_LIST_BOUNDS: SizeBounds = 10 * 1024..=10 * 1024 * 1024;

pub struct TorFeed {
    url: Option<Url>,
    list_path: PathBuf,
    set: Arc<ArcSwap<TorSet>>,
    last_etag: Mutex<Option<String>>,
    http: Client,
}

impl TorFeed {
    #[must_use]
    pub const fn new(url: Option<Url>, list_path: PathBuf, set: Arc<ArcSwap<TorSet>>, http: Client) -> Self {
        Self {
            url,
            list_path,
            set,
            last_etag: Mutex::new(None),
            http,
        }
    }

    pub async fn fetch_once(&self) -> Result<RefreshOutcome> {
        let outcome = http_etag_swap(
            self.url.as_ref(),
            &self.list_path,
            &self.http,
            &self.last_etag,
            &TOR_LIST_BOUNDS,
            "tor_feed",
        )
        .await?;

        // On Updated, reload the set from the new file and publish.
        if matches!(outcome, RefreshOutcome::Updated) {
            match TorSet::load(&self.list_path) {
                Ok(set) => self.set.store(Arc::new(set)),
                Err(e) => return Ok(RefreshOutcome::Failed(e)),
            }
        }
        Ok(outcome)
    }
}

#[async_trait::async_trait]
impl IntelProvider for TorFeed {
    fn name(&self) -> &'static str {
        "tor_feed"
    }

    async fn refresh(&self) -> Result<RefreshOutcome> {
        self.fetch_once().await
    }
}

/// Validate that, if a refresh URL is configured, it uses HTTPS. Refresh
/// payload is integrity-critical (controls who is flagged as Tor exit) —
/// plain HTTP is unacceptable.
pub fn require_https(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        bail!("tor_feed refresh URL must be https, got {}", url.scheme());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::intel::http::build_client;

    #[tokio::test]
    async fn airgap_mode_returns_not_modified() {
        let feed = TorFeed::new(
            None,
            PathBuf::from("/tmp/nonexistent-tor.txt"),
            Arc::new(ArcSwap::from(Arc::new(TorSet::default()))),
            build_client(None).expect("client"),
        );
        let out = feed.fetch_once().await.expect("ok");
        assert!(matches!(out, RefreshOutcome::NotModified));
    }

    #[test]
    fn require_https_rejects_http() {
        let u = Url::parse("http://example.com/tor.txt").expect("url");
        assert!(require_https(&u).is_err());
        let u2 = Url::parse("https://example.com/tor.txt").expect("url");
        assert!(require_https(&u2).is_ok());
    }
}
