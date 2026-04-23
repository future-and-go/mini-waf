use waf_common::{DetectionResult, Phase, RequestCtx};

use super::sql_injection_patterns::{SQLI_DESCS, SQLI_SET};
use super::{Check, request_targets};

/// SQL injection detection checker.
pub struct SqlInjectionCheck;

impl SqlInjectionCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for SqlInjectionCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for SqlInjectionCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.sqli {
            return None;
        }

        for (location, value) in request_targets(ctx) {
            let matches = SQLI_SET.matches(&value);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                let desc = SQLI_DESCS.get(idx).copied().unwrap_or("SQL Injection pattern");
                return Some(DetectionResult {
                    rule_id: Some(format!("SQLI-{:03}", idx + 1)),
                    rule_name: "SQL Injection".to_string(),
                    phase: Phase::SqlInjection,
                    detail: format!("{desc} detected in {location}"),
                });
            }
        }
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
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx(query: &str, body: &str) -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 12345,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: query.to_string(),
            headers: HashMap::new(),
            body_preview: Bytes::from(body.to_string()),
            content_length: body.len() as u64,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                defense_config: DefenseConfig {
                    sqli: true,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
        }
    }

    #[test]
    fn detects_union_select() {
        let checker = SqlInjectionCheck::new();
        let ctx = make_ctx("id=1 UNION SELECT 1,2,3--", "");
        assert!(checker.check(&ctx).is_some(), "Should detect UNION SELECT");
    }

    #[test]
    fn detects_sleep() {
        let checker = SqlInjectionCheck::new();
        let ctx = make_ctx("id=1 AND SLEEP(5)--", "");
        assert!(checker.check(&ctx).is_some(), "Should detect SLEEP()");
    }

    #[test]
    fn detects_tautology() {
        let checker = SqlInjectionCheck::new();
        // Both sides properly quoted: ' OR '1'='1' (trailing quote required by pattern)
        let ctx = make_ctx("", "username=admin' OR '1'='1' --");
        assert!(checker.check(&ctx).is_some(), "Should detect OR tautology");
    }

    #[test]
    fn allows_clean_request() {
        let checker = SqlInjectionCheck::new();
        let ctx = make_ctx("name=alice&page=2", "");
        assert!(checker.check(&ctx).is_none(), "Should allow clean request");
    }

    #[test]
    fn skips_when_disabled() {
        let checker = SqlInjectionCheck::new();
        let mut ctx = make_ctx("id=1 UNION SELECT 1,2,3--", "");
        Arc::make_mut(&mut ctx.host_config).defense_config.sqli = false;
        assert!(checker.check(&ctx).is_none(), "Should skip when disabled");
    }
}
