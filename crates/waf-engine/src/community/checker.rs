use std::sync::Arc;

use waf_common::{DetectionResult, Phase, RequestCtx};

use crate::checks::Check;

use super::blocklist::CommunityBlocklistSync;

/// WAF checker that looks up the client IP against the community blocklist.
///
/// Runs as part of the detection pipeline, similar to `CrowdSecChecker`,
/// performing a synchronous O(1) `DashMap` lookup.
pub struct CommunityChecker {
    blocklist: Arc<CommunityBlocklistSync>,
}

impl CommunityChecker {
    pub const fn new(blocklist: Arc<CommunityBlocklistSync>) -> Self {
        Self { blocklist }
    }
}

impl Check for CommunityChecker {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let decision = self.blocklist.check_ip(&ctx.client_ip)?;

        Some(DetectionResult {
            rule_id: Some(format!("community:{}", decision.source)),
            rule_name: "Community Blocklist".to_string(),
            phase: Phase::Community,
            detail: format!(
                "Community blocklist hit for {} (reason: {}, source: {})",
                ctx.client_ip, decision.reason, decision.source,
            ),
            rule_action: None,
            action_status: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::community::client::CommunityClient;
    use bytes::Bytes;
    use std::collections::HashMap;
    use waf_common::HostConfig;

    fn ctx_with_ip(ip: &str) -> RequestCtx {
        RequestCtx {
            req_id: "t".to_string(),
            client_ip: ip.parse().expect("ip"),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
        }
    }

    #[test]
    fn empty_blocklist_yields_no_detection() {
        let client = Arc::new(CommunityClient::new("http://localhost").expect("client"));
        let bl = Arc::new(CommunityBlocklistSync::new(client, "k".to_string(), 60, None));
        let checker = CommunityChecker::new(bl);
        let ctx = ctx_with_ip("1.2.3.4");
        assert!(checker.check(&ctx).is_none());
    }
}
