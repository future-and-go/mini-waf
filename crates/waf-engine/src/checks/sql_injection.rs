use std::sync::Arc;

use arc_swap::ArcSwap;
use waf_common::config::SqliScanConfig;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::sql_injection_patterns::{SQLI_DESCS, SQLI_SET};
use super::sql_injection_scanners::{scan_headers, scan_json_body, scan_query_params};
use super::{Check, request_targets};

/// SQL injection detection checker with hot-reloadable config.
pub struct SqlInjectionCheck {
    cfg: Arc<ArcSwap<SqliScanConfig>>,
}

impl SqlInjectionCheck {
    pub fn new() -> Self {
        Self {
            cfg: Arc::new(ArcSwap::from_pointee(SqliScanConfig::default())),
        }
    }

    pub fn with_config(cfg: SqliScanConfig) -> Self {
        Self {
            cfg: Arc::new(ArcSwap::from_pointee(cfg)),
        }
    }

    pub fn reload_config(&self, cfg: SqliScanConfig) {
        self.cfg.store(Arc::new(cfg));
    }

    pub fn config_handle(&self) -> Arc<ArcSwap<SqliScanConfig>> {
        Arc::clone(&self.cfg)
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

        let cfg = self.cfg.load();

        // 1. Per-parameter query string scan for precise attribution
        if !ctx.query.is_empty()
            && let Some((location, idx)) = scan_query_params(&ctx.query, &SQLI_SET)
        {
            let desc = SQLI_DESCS.get(idx).copied().unwrap_or("SQL Injection pattern");
            return Some(DetectionResult {
                rule_id: Some(format!("SQLI-{:03}", idx + 1)),
                rule_name: "SQL Injection".to_string(),
                phase: Phase::SqlInjection,
                detail: format!("{desc} detected in {location}"),
            });
        }

        // 2. JSON body scan if Content-Type indicates JSON
        let is_json = ctx
            .headers
            .get("content-type")
            .is_some_and(|ct| ct.contains("application/json"));
        if !ctx.body_preview.is_empty()
            && is_json
            && let Some((location, idx)) = scan_json_body(&ctx.body_preview, &SQLI_SET, cfg.json_parse_cap)
        {
            let desc = SQLI_DESCS.get(idx).copied().unwrap_or("SQL Injection pattern");
            return Some(DetectionResult {
                rule_id: Some(format!("SQLI-{:03}", idx + 1)),
                rule_name: "SQL Injection".to_string(),
                phase: Phase::SqlInjection,
                detail: format!("{desc} detected in {location}"),
            });
        }

        // 3. Header scan (respects allowlist/denylist and cap)
        if let Some((location, idx)) = scan_headers(&ctx.headers, &cfg, &SQLI_SET) {
            let desc = SQLI_DESCS.get(idx).copied().unwrap_or("SQL Injection pattern");
            return Some(DetectionResult {
                rule_id: Some(format!("SQLI-{:03}", idx + 1)),
                rule_name: "SQL Injection".to_string(),
                phase: Phase::SqlInjection,
                detail: format!("{desc} detected in {location}"),
            });
        }

        // 4. Fallback: generic scan (path, raw query, cookie, non-JSON body)
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
        make_ctx_with_headers(query, body, HashMap::new())
    }

    fn make_ctx_with_headers(query: &str, body: &str, headers: HashMap<String, String>) -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 12345,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: query.to_string(),
            headers,
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

    #[test]
    fn detects_json_nested_sqli() {
        let checker = SqlInjectionCheck::new();
        let mut ctx = make_ctx("", r#"{"user":{"name":"' OR '1'='1'"}}"#);
        ctx.headers
            .insert("content-type".to_string(), "application/json".to_string());
        let result = checker.check(&ctx);
        assert!(result.is_some(), "Should detect SQLi in JSON body");
        let detail = result.unwrap().detail;
        assert!(
            detail.contains("body.user.name"),
            "Should attribute to JSON path: {detail}"
        );
    }

    #[test]
    fn detects_query_param_sqli() {
        let checker = SqlInjectionCheck::new();
        let ctx = make_ctx("id=1+UNION+SELECT+1,2", "");
        let result = checker.check(&ctx);
        assert!(result.is_some(), "Should detect SQLi in query param");
        let detail = result.unwrap().detail;
        assert!(detail.contains("query.id"), "Should attribute to query param: {detail}");
    }

    #[test]
    fn json_malformed_falls_back_to_raw() {
        let checker = SqlInjectionCheck::new();
        let mut ctx = make_ctx("", "not json ' OR '1'='1'");
        ctx.headers
            .insert("content-type".to_string(), "application/json".to_string());
        let result = checker.check(&ctx);
        assert!(result.is_some(), "Should fallback to raw body scan");
        let detail = result.unwrap().detail;
        assert!(detail.contains("body"), "Should detect in raw body: {detail}");
    }

    #[test]
    fn detects_sqli_in_user_agent_header() {
        let checker = SqlInjectionCheck::new();
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "'; DROP TABLE users--".to_string());
        let ctx = make_ctx_with_headers("", "", headers);
        let result = checker.check(&ctx);
        assert!(result.is_some(), "Should detect SQLi in User-Agent header");
        let detail = result.unwrap().detail;
        assert!(
            detail.contains("header.user-agent"),
            "Should attribute to header: {detail}"
        );
    }

    #[test]
    fn skips_denylisted_header() {
        let checker = SqlInjectionCheck::new();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "'; DROP TABLE users--".to_string());
        let ctx = make_ctx_with_headers("", "", headers);
        let result = checker.check(&ctx);
        assert!(result.is_none(), "Should skip denylisted content-type header");
    }

    #[test]
    fn hot_reload_config_changes_behavior() {
        let checker = SqlInjectionCheck::new();
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "'; DROP TABLE users--".to_string());
        let ctx = make_ctx_with_headers("", "", headers);

        // Initial: header scan enabled (default)
        assert!(checker.check(&ctx).is_some(), "Should detect with default config");

        // Reload: disable header scan
        checker.reload_config(SqliScanConfig {
            scan_headers: false,
            ..Default::default()
        });
        assert!(
            checker.check(&ctx).is_none(),
            "Should not detect after disabling header scan"
        );

        // Reload: re-enable
        checker.reload_config(SqliScanConfig::default());
        assert!(checker.check(&ctx).is_some(), "Should detect after re-enabling");
    }
}
