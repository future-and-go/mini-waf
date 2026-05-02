//! Authentication brute-force (FR-018) — stub registered by Phase 00.
//!
//! Real detection lands in Phase 07. The request-phase `check()` always
//! returns `None`; the production state machine lives entirely in
//! `on_response()` (status-code-only v1) so wiring it now keeps the engine
//! pipeline backwards-compatible while reserving the slot.

use waf_common::{DetectionResult, RequestCtx};

use super::Check;

/// Stub brute-force checker.
///
/// Phase 07 (FR-018) replaces `on_response()` with a sliding-window counter
/// keyed on `(username_hash, ip)`, sourced from the upstream's `401`/`403`
/// status. The request-phase `check()` stays a no-op because the detection
/// signal only exists after the upstream replies.
pub struct BruteForceCheck;

impl BruteForceCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for BruteForceCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for BruteForceCheck {
    fn check(&self, _ctx: &RequestCtx) -> Option<DetectionResult> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::HostConfig;

    fn make_ctx() -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "POST".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/login".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
        }
    }

    #[test]
    fn stub_returns_none() {
        let checker = BruteForceCheck::new();
        let ctx = make_ctx();
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn on_response_stub_is_no_op() {
        // Stub inherits the trait's default no-op; pin it so Phase 07 has a
        // visible regression target when it overrides.
        let checker = BruteForceCheck::new();
        let ctx = make_ctx();
        checker.on_response(&ctx, 401);
    }
}
