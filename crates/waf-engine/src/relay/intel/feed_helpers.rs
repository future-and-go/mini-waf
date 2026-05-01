//! FR-007 phase-04 — shared HTTP-fetch + `ETag` + atomic-swap routine.
//!
//! `tor_feed` and the ASN feeds repeat the same dance: build request with
//! `If-None-Match`, dispatch on status code, atomic swap on 200, retain on
//! 304/error. Extracted here so each feed is just a config-and-bounds
//! shim.

use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use parking_lot::Mutex;
use reqwest::Client;
use reqwest::header::{ETAG, HeaderValue, IF_NONE_MATCH};
use url::Url;

use super::RefreshOutcome;
use super::atomic_swap::{SizeBounds, write_atomic};

/// Fetch `url` (if Some) with `If-None-Match: <last_etag>`, atomically
/// swap the body into `target`, update `last_etag`. Air-gap (`url=None`)
/// short-circuits to `NotModified`.
pub async fn http_etag_swap(
    url: Option<&Url>,
    target: &Path,
    http: &Client,
    last_etag: &Mutex<Option<String>>,
    bounds: &SizeBounds,
    feed_name: &str,
) -> Result<RefreshOutcome> {
    let Some(url) = url else {
        return Ok(RefreshOutcome::NotModified);
    };

    let started = Instant::now();
    let mut req = http.get(url.clone());
    let cached_etag = last_etag.lock().clone();
    if let Some(tag) = cached_etag
        && let Ok(hv) = HeaderValue::from_str(&tag)
    {
        req = req.header(IF_NONE_MATCH, hv);
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(feed = feed_name, error = %e, "refresh: request failed");
            return Ok(RefreshOutcome::Failed(e.into()));
        }
    };

    match resp.status().as_u16() {
        304 => {
            tracing::debug!(feed = feed_name, "304 not modified");
            Ok(RefreshOutcome::NotModified)
        }
        200 => {
            let new_etag = resp
                .headers()
                .get(ETAG)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);

            if let Err(e) = write_atomic(target, resp, bounds).await {
                tracing::warn!(feed = feed_name, error = %e, "write_atomic failed");
                return Ok(RefreshOutcome::Failed(e));
            }
            *last_etag.lock() = new_etag;
            tracing::info!(
                feed = feed_name,
                path = %target.display(),
                elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "feed updated"
            );
            Ok(RefreshOutcome::Updated)
        }
        other => {
            let err = anyhow::anyhow!("feed {feed_name} unexpected status {other}");
            Ok(RefreshOutcome::Failed(err))
        }
    }
}
