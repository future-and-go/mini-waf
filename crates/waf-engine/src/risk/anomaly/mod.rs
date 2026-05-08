//! FR-025 Phase 5: Anomaly detection layer (L2).
//!
//! Inline synchronous anomaly detectors for per-request evaluation.
//! Each detector emits risk deltas based on request characteristics.
//!
//! Detectors:
//! - JA4↔UA mismatch: TLS fingerprint vs User-Agent family mismatch (+20)
//! - XFF chain sanity: X-Forwarded-For chain anomalies (+10 cap)
//! - Header sanity: Missing/impossible HTTP headers (+15 cap)

pub mod header_sanity;
pub mod ja4_ua_mismatch;
pub mod xff_chain;

use std::collections::HashMap;

use crate::risk::state::Contributor;

/// Combined anomaly layer that runs all detectors.
#[derive(Debug, Default)]
pub struct AnomalyLayer;

/// Input context for anomaly detection.
pub struct AnomalyCtx<'a> {
    /// JA4 fingerprint string (if available).
    pub ja4: Option<&'a str>,
    /// User-Agent header value.
    pub user_agent: &'a str,
    /// X-Forwarded-For header value (if present).
    pub xff: Option<&'a str>,
    /// All request headers (lowercase keys).
    pub headers: &'a HashMap<String, String>,
}

impl<'a> AnomalyCtx<'a> {
    #[must_use]
    pub const fn new(
        ja4: Option<&'a str>,
        user_agent: &'a str,
        xff: Option<&'a str>,
        headers: &'a HashMap<String, String>,
    ) -> Self {
        Self {
            ja4,
            user_agent,
            xff,
            headers,
        }
    }
}

impl AnomalyLayer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Evaluate all anomaly detectors and collect contributors.
    ///
    /// Returns a list of contributors from all triggered detectors.
    /// Empty list means no anomalies detected.
    #[must_use]
    pub fn evaluate(&self, ctx: &AnomalyCtx<'_>, now_ms: i64) -> Vec<Contributor> {
        let mut contributors = Vec::with_capacity(3);

        // JA4↔UA mismatch check
        if let Some(c) = ja4_ua_mismatch::evaluate(ctx.ja4, ctx.user_agent, now_ms) {
            contributors.push(c);
        }

        // XFF chain sanity check
        if let Some(c) = xff_chain::evaluate(ctx.xff, now_ms) {
            contributors.push(c);
        }

        // Header sanity check
        if let Some(c) = header_sanity::evaluate(ctx.headers, ctx.user_agent, now_ms) {
            contributors.push(c);
        }

        contributors
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn browser_ua() -> String {
        "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0.0.0 Safari/537.36".to_string()
    }

    fn make_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn evaluate_clean_request() {
        let layer = AnomalyLayer::new();
        let headers = make_headers(&[("accept", "text/html"), ("accept-language", "en-US")]);
        let ua = browser_ua();
        let ctx = AnomalyCtx::new(None, &ua, None, &headers);

        let contributors = layer.evaluate(&ctx, 1000);
        assert!(contributors.is_empty());
    }

    #[test]
    fn evaluate_multiple_anomalies() {
        let layer = AnomalyLayer::new();
        let headers = make_headers(&[]);
        let ua = browser_ua();
        let ctx = AnomalyCtx::new(None, &ua, Some("8.8.8.8, 10.0.0.1"), &headers);

        let contributors = layer.evaluate(&ctx, 1000);
        // Should have header sanity + XFF violations
        assert!(contributors.len() >= 2);
    }

    #[test]
    fn evaluate_xff_only_anomaly() {
        let layer = AnomalyLayer::new();
        let headers = make_headers(&[("accept", "text/html"), ("accept-language", "en-US")]);
        let ua = browser_ua();
        let ctx = AnomalyCtx::new(None, &ua, Some("203.0.113.1, 192.168.1.1"), &headers);

        let contributors = layer.evaluate(&ctx, 1000);
        assert_eq!(contributors.len(), 1);
        assert_eq!(contributors[0].delta, xff_chain::XFF_VIOLATION_DELTA);
    }
}
