//! TDD scaffold — §5 Mandatory Observability Headers (Interop Contract v2.3).
//!
//! Locks the Phase 2 injector API (`CacheStatus`, `WafHeaderValues`,
//! `inject_waf_observability_headers`) and asserts the contract-mandatory
//! behaviour every egress path will depend on:
//!
//! * all six `X-WAF-*` headers emitted with contract-exact names + values
//! * `risk_score` clamped to `0..=100`
//! * `rule_id` `None` and CR/LF-bearing inputs both collapse to `"none"`
//!   (response-splitting defense)
//! * `CacheStatus::default() == Bypass` (fail-safe)
//! * idempotency — repeat injection replaces, never appends
//! * `WafAction::as_contract_str()` covers every variant exactly
//!
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use gateway::waf_observability_headers::{CacheStatus, WafHeaderValues, inject_waf_observability_headers};

// ── helpers ─────────────────────────────────────────────────────────────────

fn build_resp() -> pingora_http::ResponseHeader {
    pingora_http::ResponseHeader::build(200, None).expect("build resp")
}

fn header_value<'a>(resp: &'a pingora_http::ResponseHeader, name: &str) -> Option<&'a str> {
    resp.headers
        .get(name)
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
}

fn header_count(resp: &pingora_http::ResponseHeader, name: &str) -> usize {
    resp.headers.get_all(name).iter().count()
}

const fn baseline_values<'a>() -> WafHeaderValues<'a> {
    WafHeaderValues {
        request_id: "11111111-2222-3333-4444-555555555555",
        risk_score: 42,
        action: "block",
        rule_id: Some("R-1"),
        mode: "enforce",
        cache: CacheStatus::Miss,
    }
}

// ── unit tests: injector emits all 6 headers with contract names + values ───

#[test]
fn injects_all_six_headers_with_contract_names_and_values() {
    let mut resp = build_resp();
    inject_waf_observability_headers(&mut resp, &baseline_values()).expect("inject");

    assert_eq!(
        header_value(&resp, "x-waf-request-id"),
        Some("11111111-2222-3333-4444-555555555555")
    );
    assert_eq!(header_value(&resp, "x-waf-risk-score"), Some("42"));
    assert_eq!(header_value(&resp, "x-waf-action"), Some("block"));
    assert_eq!(header_value(&resp, "x-waf-rule-id"), Some("R-1"));
    assert_eq!(header_value(&resp, "x-waf-cache"), Some("MISS"));
    assert_eq!(header_value(&resp, "x-waf-mode"), Some("enforce"));
}

// ── risk_score clamp (red-team F11) ─────────────────────────────────────────

#[test]
fn risk_score_clamped_to_100_when_input_above_range() {
    let mut resp = build_resp();
    let vals = WafHeaderValues {
        risk_score: 200,
        ..baseline_values()
    };
    inject_waf_observability_headers(&mut resp, &vals).expect("inject");
    assert_eq!(header_value(&resp, "x-waf-risk-score"), Some("100"));
}

#[test]
fn risk_score_passes_through_within_range() {
    for score in [0u8, 1, 50, 99, 100] {
        let mut resp = build_resp();
        let vals = WafHeaderValues {
            risk_score: score,
            ..baseline_values()
        };
        inject_waf_observability_headers(&mut resp, &vals).expect("inject");
        assert_eq!(
            header_value(&resp, "x-waf-risk-score"),
            Some(score.to_string().as_str())
        );
    }
}

// ── rule_id fallback + CR/LF defense (red-team F12) ─────────────────────────

#[test]
fn rule_id_none_renders_as_literal_none_not_empty() {
    let mut resp = build_resp();
    let vals = WafHeaderValues {
        rule_id: None,
        ..baseline_values()
    };
    inject_waf_observability_headers(&mut resp, &vals).expect("inject");
    assert_eq!(header_value(&resp, "x-waf-rule-id"), Some("none"));
}

#[test]
fn rule_id_with_crlf_collapses_to_none_response_splitting_defense() {
    let mut resp = build_resp();
    let vals = WafHeaderValues {
        rule_id: Some("r\r\nX-Evil: 1"),
        ..baseline_values()
    };
    inject_waf_observability_headers(&mut resp, &vals).expect("inject");

    assert_eq!(
        header_value(&resp, "x-waf-rule-id"),
        Some("none"),
        "CRLF-bearing rule_id must NOT pass through"
    );
    assert!(
        resp.headers.get("x-evil").is_none(),
        "response-splitting: smuggled header must not appear"
    );
}

#[test]
fn rule_id_with_bare_lf_collapses_to_none() {
    let mut resp = build_resp();
    let vals = WafHeaderValues {
        rule_id: Some("r\nevil"),
        ..baseline_values()
    };
    inject_waf_observability_headers(&mut resp, &vals).expect("inject");
    assert_eq!(header_value(&resp, "x-waf-rule-id"), Some("none"));
}

#[test]
fn rule_id_with_bare_cr_collapses_to_none() {
    let mut resp = build_resp();
    let vals = WafHeaderValues {
        rule_id: Some("r\revil"),
        ..baseline_values()
    };
    inject_waf_observability_headers(&mut resp, &vals).expect("inject");
    assert_eq!(header_value(&resp, "x-waf-rule-id"), Some("none"));
}

// ── CacheStatus rendering + fail-safe default ───────────────────────────────

#[test]
fn cache_status_renders_hit_miss_bypass() {
    for (status, expected) in [
        (CacheStatus::Hit, "HIT"),
        (CacheStatus::Miss, "MISS"),
        (CacheStatus::Bypass, "BYPASS"),
    ] {
        let mut resp = build_resp();
        let vals = WafHeaderValues {
            cache: status,
            ..baseline_values()
        };
        inject_waf_observability_headers(&mut resp, &vals).expect("inject");
        assert_eq!(header_value(&resp, "x-waf-cache"), Some(expected));
    }
}

#[test]
fn cache_status_default_is_bypass_never_falsely_advertises_hit() {
    assert_eq!(CacheStatus::default(), CacheStatus::Bypass);
}

// ── mode rendering ──────────────────────────────────────────────────────────

#[test]
fn mode_renders_enforce_and_log_only_as_passed() {
    for mode in ["enforce", "log_only"] {
        let mut resp = build_resp();
        let vals = WafHeaderValues {
            mode,
            ..baseline_values()
        };
        inject_waf_observability_headers(&mut resp, &vals).expect("inject");
        assert_eq!(header_value(&resp, "x-waf-mode"), Some(mode));
    }
}

// ── idempotency: repeated injection replaces, never appends ─────────────────

#[test]
fn injector_is_idempotent_each_header_appears_exactly_once() {
    let mut resp = build_resp();

    inject_waf_observability_headers(&mut resp, &baseline_values()).expect("inject 1");
    let v2 = WafHeaderValues {
        request_id: "second-rid",
        risk_score: 7,
        action: "rate_limit",
        rule_id: Some("R-2"),
        mode: "log_only",
        cache: CacheStatus::Hit,
    };
    inject_waf_observability_headers(&mut resp, &v2).expect("inject 2");

    for name in [
        "x-waf-request-id",
        "x-waf-risk-score",
        "x-waf-action",
        "x-waf-rule-id",
        "x-waf-cache",
        "x-waf-mode",
    ] {
        assert_eq!(
            header_count(&resp, name),
            1,
            "{name} must be inserted (replace), not appended"
        );
    }
    // Latest values win.
    assert_eq!(header_value(&resp, "x-waf-request-id"), Some("second-rid"));
    assert_eq!(header_value(&resp, "x-waf-risk-score"), Some("7"));
    assert_eq!(header_value(&resp, "x-waf-action"), Some("rate_limit"));
    assert_eq!(header_value(&resp, "x-waf-rule-id"), Some("R-2"));
    assert_eq!(header_value(&resp, "x-waf-cache"), Some("HIT"));
    assert_eq!(header_value(&resp, "x-waf-mode"), Some("log_only"));
}

// ── WafAction → contract string coverage (every variant) ────────────────────

#[test]
#[allow(deprecated)]
fn waf_action_as_contract_str_covers_every_variant() {
    use waf_common::WafAction;

    assert_eq!(WafAction::Allow.as_contract_str(), "allow");
    assert_eq!(
        WafAction::Block {
            status: 403,
            body: None
        }
        .as_contract_str(),
        "block"
    );
    assert_eq!(WafAction::Challenge.as_contract_str(), "challenge");
    assert_eq!(
        WafAction::RateLimit {
            status: 429,
            body: None
        }
        .as_contract_str(),
        "rate_limit"
    );
    assert_eq!(WafAction::Timeout { status: 504 }.as_contract_str(), "timeout");
    assert_eq!(
        WafAction::CircuitBreaker {
            status: 503,
            body: None
        }
        .as_contract_str(),
        "circuit_breaker"
    );
    // Redirect + LogOnly both collapse to "allow" on the contract wire.
    assert_eq!(
        WafAction::Redirect { url: "/landing".into() }.as_contract_str(),
        "allow"
    );
    assert_eq!(WafAction::LogOnly.as_contract_str(), "allow");
}

// ── Phase 3: ctx snapshot Default must be `allow`, not "" (red-team F13) ────

#[test]
fn waf_decision_meta_default_action_is_allow_not_empty_string() {
    use gateway::context::WafDecisionMeta;
    let meta = WafDecisionMeta::default();
    assert_eq!(meta.action, "allow", "default action MUST be \"allow\", never \"\"");
    assert_eq!(meta.risk_score, 0, "default risk_score MUST be 0");
    assert!(meta.rule_id.is_none(), "default rule_id MUST be None (no allocation)");
    assert_eq!(meta.mode, "enforce", "default mode MUST be \"enforce\"");
}

#[test]
fn waf_decision_meta_from_block_decision_carries_action_score_rule_and_mode() {
    use gateway::context::WafDecisionMeta;
    use waf_common::{DetectionResult, InteropMode, Phase, WafDecision};

    let result = DetectionResult {
        rule_id: Some("R-77".into()),
        rule_name: "test-rule".into(),
        phase: Phase::Scanner,
        detail: "synthetic".into(),
        rule_action: None,
        action_status: None,
    };
    let mut decision = WafDecision::block(403, Some("body".into()), result).with_risk_score(85);
    decision.mode = InteropMode::LogOnly;

    let meta = WafDecisionMeta::from_decision(&decision);
    assert_eq!(meta.action, "block");
    assert_eq!(meta.risk_score, 85);
    assert_eq!(meta.rule_id.as_deref(), Some("R-77"));
    assert_eq!(meta.mode, "log_only");
}

#[test]
fn waf_decision_meta_from_allow_decision_has_none_rule_id_no_alloc() {
    use gateway::context::WafDecisionMeta;
    use waf_common::WafDecision;

    let decision = WafDecision::allow();
    let meta = WafDecisionMeta::from_decision(&decision);
    assert_eq!(meta.action, "allow");
    assert_eq!(meta.risk_score, 0);
    assert!(meta.rule_id.is_none(), "allow path must not allocate a rule id");
    assert_eq!(meta.mode, "enforce");
}

#[test]
fn gateway_ctx_defaults_have_no_decision_meta_and_bypass_cache() {
    use gateway::context::GatewayCtx;
    use gateway::waf_observability_headers::CacheStatus;

    let ctx = GatewayCtx::default();
    assert!(
        ctx.waf_decision_meta.is_none(),
        "fresh ctx must carry no decision meta (request_filter populates it)"
    );
    assert_eq!(
        ctx.cache_status,
        CacheStatus::Bypass,
        "ctx.cache_status default MUST be Bypass (fail-safe — never falsely advertise HIT)"
    );
}

// ── Phase 6: pre-inspect + error-path injector helper ──────────────────────
//
// Unit-tests cover the shared `inject_for_pre_inspect_or_error` helper that
// every ctx-None / pre-`inspect()` egress site calls (access-gate 403,
// fail-closed 503, HTTP→HTTPS 301, health 200, transport 502/503/504).
//
// E2E integration tests over `request_filter` / `fail_to_proxy` are deferred
// to Phase 7 (and the Phase-6b test harness work that lifts the
// `WafEngine`-without-DB seam restriction).

mod phase6 {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use bytes::Bytes;
    use gateway::context::{GatewayCtx, WafDecisionMeta};
    use gateway::waf_observability_headers::inject_for_pre_inspect_or_error;
    use waf_common::tier::Tier;
    use waf_common::{HostConfig, RequestCtx};

    fn build_resp() -> pingora_http::ResponseHeader {
        pingora_http::ResponseHeader::build(200, None).expect("build resp")
    }

    fn header_val<'a>(resp: &'a pingora_http::ResponseHeader, name: &str) -> Option<&'a str> {
        resp.headers
            .get(name)
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
    }

    fn request_ctx_with(req_id: &str, log_only: bool) -> RequestCtx {
        let hc = HostConfig {
            log_only_mode: log_only,
            ..HostConfig::default()
        };
        RequestCtx {
            req_id: req_id.into(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            client_port: 1234,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            path: "/p".into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(hc),
            geo: None,
            tier: Tier::CatchAll,
            tier_policy: RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
            device_fp: None,
            tx_velocity_token: None,
        }
    }

    fn ctx_with_request(req_id: &str, log_only: bool) -> GatewayCtx {
        let rc = request_ctx_with(req_id, log_only);
        let hc = Arc::clone(&rc.host_config);
        GatewayCtx {
            request_ctx: Some(rc),
            host_config: Some(hc),
            ..GatewayCtx::default()
        }
    }

    fn ctx_without_request_with_host(log_only: bool) -> GatewayCtx {
        let hc = HostConfig {
            log_only_mode: log_only,
            ..HostConfig::default()
        };
        GatewayCtx {
            request_ctx: None,
            host_config: Some(Arc::new(hc)),
            ..GatewayCtx::default()
        }
    }

    // ── access-gate 403 (block, ctx.request_ctx Some) ─────────────────────────
    #[test]
    fn access_gate_403_emits_six_observability_headers() {
        let ctx = ctx_with_request("req-gate-1", false);
        let mut resp = build_resp();
        inject_for_pre_inspect_or_error(&mut resp, &ctx, "block", "ignored-fallback").expect("inject");

        assert_eq!(header_val(&resp, "x-waf-request-id"), Some("req-gate-1"));
        assert_eq!(header_val(&resp, "x-waf-risk-score"), Some("0"));
        assert_eq!(header_val(&resp, "x-waf-action"), Some("block"));
        assert_eq!(header_val(&resp, "x-waf-rule-id"), Some("none"));
        assert_eq!(header_val(&resp, "x-waf-cache"), Some("BYPASS"));
        assert_eq!(header_val(&resp, "x-waf-mode"), Some("enforce"));
    }

    // ── fail-closed 503: request_ctx None → fresh-UUID fallback ───────────────
    #[test]
    fn fail_closed_503_emits_six_observability_headers_with_fallback_uuid() {
        let ctx = ctx_without_request_with_host(false);
        let fallback = "00000000-0000-4000-8000-000000000abc";
        let mut resp = build_resp();
        inject_for_pre_inspect_or_error(&mut resp, &ctx, "circuit_breaker", fallback).expect("inject");

        assert_eq!(
            header_val(&resp, "x-waf-request-id"),
            Some(fallback),
            "ctx-None path MUST emit the fallback UUID so X-WAF-Request-Id is never absent"
        );
        assert_eq!(header_val(&resp, "x-waf-action"), Some("circuit_breaker"));
        assert_eq!(header_val(&resp, "x-waf-cache"), Some("BYPASS"));
        assert_eq!(header_val(&resp, "x-waf-mode"), Some("enforce"));
        assert_eq!(header_val(&resp, "x-waf-rule-id"), Some("none"));
        assert_eq!(header_val(&resp, "x-waf-risk-score"), Some("0"));
    }

    // ── HTTP → HTTPS 301 redirect (allow action) ─────────────────────────────
    #[test]
    fn http_to_https_301_redirect_emits_six_observability_headers() {
        let ctx = ctx_with_request("req-redir-1", false);
        let mut resp = pingora_http::ResponseHeader::build(301, None).expect("build");
        resp.insert_header("location", "https://example.com/").expect("loc");
        inject_for_pre_inspect_or_error(&mut resp, &ctx, "allow", "unused").expect("inject");

        assert_eq!(header_val(&resp, "x-waf-action"), Some("allow"));
        assert_eq!(header_val(&resp, "x-waf-request-id"), Some("req-redir-1"));
        assert_eq!(header_val(&resp, "x-waf-cache"), Some("BYPASS"));
        // 301 should still carry the location header alongside.
        assert_eq!(header_val(&resp, "location"), Some("https://example.com/"));
    }

    // ── fail_to_proxy: timeout (504) and circuit_breaker (503) actions ────────
    #[test]
    fn fail_to_proxy_transport_error_emits_six_observability_headers() {
        for action in ["timeout", "circuit_breaker", "block"] {
            let ctx = ctx_with_request("req-fp-1", false);
            let mut resp = build_resp();
            inject_for_pre_inspect_or_error(&mut resp, &ctx, action, "unused").expect("inject");

            assert_eq!(header_val(&resp, "x-waf-action"), Some(action));
            assert_eq!(header_val(&resp, "x-waf-cache"), Some("BYPASS"));
            assert_eq!(header_val(&resp, "x-waf-request-id"), Some("req-fp-1"));
        }
    }

    // ── health 200 (allow, BYPASS) ───────────────────────────────────────────
    #[test]
    fn health_endpoint_200_emits_six_observability_headers() {
        let ctx = ctx_with_request("req-health-1", false);
        let mut resp = build_resp();
        inject_for_pre_inspect_or_error(&mut resp, &ctx, "allow", "unused").expect("inject");

        assert_eq!(header_val(&resp, "x-waf-action"), Some("allow"));
        assert_eq!(header_val(&resp, "x-waf-cache"), Some("BYPASS"));
        assert_eq!(header_val(&resp, "x-waf-mode"), Some("enforce"));
    }

    // ── log_only mode propagation through pre-inspect path (red-team F8) ─────
    #[test]
    fn pre_inspect_mode_falls_back_to_host_config_log_only_not_hardcoded_enforce() {
        let ctx = ctx_with_request("req-lo", true);
        let mut resp = build_resp();
        inject_for_pre_inspect_or_error(&mut resp, &ctx, "block", "unused").expect("inject");

        assert_eq!(
            header_val(&resp, "x-waf-mode"),
            Some("log_only"),
            "mode MUST derive from host_config.log_only_mode, never hardcoded enforce"
        );
    }

    // ── log_only mode propagation through ctx-None path (host_config still set) ─
    #[test]
    fn pre_inspect_ctx_none_mode_derives_from_host_config() {
        let ctx = ctx_without_request_with_host(true);
        let mut resp = build_resp();
        inject_for_pre_inspect_or_error(&mut resp, &ctx, "circuit_breaker", "fallback-uuid").expect("inject");

        assert_eq!(header_val(&resp, "x-waf-mode"), Some("log_only"));
        assert_eq!(header_val(&resp, "x-waf-request-id"), Some("fallback-uuid"));
    }

    // ── waf_decision_meta.risk_score wins over default 0 (transport error after inspect) ─
    #[test]
    fn pre_inspect_uses_decision_meta_risk_score_when_present() {
        let mut ctx = ctx_with_request("req-rs", false);
        ctx.waf_decision_meta = Some(WafDecisionMeta {
            action: "allow",
            risk_score: 73,
            rule_id: None,
            mode: "enforce",
        });
        let mut resp = build_resp();
        inject_for_pre_inspect_or_error(&mut resp, &ctx, "timeout", "unused").expect("inject");

        assert_eq!(header_val(&resp, "x-waf-risk-score"), Some("73"));
        assert_eq!(header_val(&resp, "x-waf-action"), Some("timeout"));
    }

    // ── no host_config: mode falls back to "enforce" ─────────────────────────
    #[test]
    fn pre_inspect_no_host_config_mode_falls_back_to_enforce() {
        let ctx = GatewayCtx::default();
        let mut resp = build_resp();
        inject_for_pre_inspect_or_error(&mut resp, &ctx, "circuit_breaker", "fallback").expect("inject");

        assert_eq!(header_val(&resp, "x-waf-mode"), Some("enforce"));
        assert_eq!(header_val(&resp, "x-waf-request-id"), Some("fallback"));
    }
}

// ── Phase 5: passthrough + cache-HIT egress paths ───────────────────────────

mod phase5 {
    #![allow(clippy::too_many_lines)]

    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use bytes::Bytes;
    use gateway::cache::CachedResponse;
    use gateway::context::{GatewayCtx, WafDecisionMeta};
    use gateway::response_cache_integration::write_cached_entry;
    use gateway::waf_observability_headers::{CacheStatus, inject_for_passthrough};
    use pingora_proxy::Session;
    use waf_common::tier::Tier;
    use waf_common::{HostConfig, RequestCtx};

    fn build_resp_with_extra(headers: &[(&str, &str)]) -> pingora_http::ResponseHeader {
        let mut resp = pingora_http::ResponseHeader::build(200, None).expect("build resp");
        for (k, v) in headers {
            resp.insert_header((*k).to_string(), *v).expect("insert");
        }
        resp
    }

    fn header_val<'a>(resp: &'a pingora_http::ResponseHeader, name: &str) -> Option<&'a str> {
        resp.headers
            .get(name)
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
    }

    fn request_ctx_with(req_id: &str, log_only: bool) -> RequestCtx {
        let hc = HostConfig {
            log_only_mode: log_only,
            ..HostConfig::default()
        };
        RequestCtx {
            req_id: req_id.into(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            client_port: 1234,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            path: "/p".into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(hc),
            geo: None,
            tier: Tier::CatchAll,
            tier_policy: RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
            device_fp: None,
            tx_velocity_token: None,
        }
    }

    fn ctx_with(meta: Option<WafDecisionMeta>, req_id: &str, cache: CacheStatus, log_only: bool) -> GatewayCtx {
        let req_ctx = request_ctx_with(req_id, log_only);
        let host_config = Arc::clone(&req_ctx.host_config);
        GatewayCtx {
            request_ctx: Some(req_ctx),
            host_config: Some(host_config),
            waf_decision_meta: meta,
            cache_status: cache,
            ..GatewayCtx::default()
        }
    }

    // (a) allow → upstream MISS: six headers driven from ctx snapshot
    #[test]
    fn inject_for_passthrough_emits_six_headers_from_ctx_snapshot_with_cache_miss() {
        let meta = WafDecisionMeta {
            action: "allow",
            risk_score: 12,
            rule_id: None,
            mode: "enforce",
        };
        let ctx = ctx_with(Some(meta), "req-abc-123", CacheStatus::Miss, false);
        let mut resp = build_resp_with_extra(&[]);

        inject_for_passthrough(&mut resp, &ctx).expect("inject");

        assert_eq!(header_val(&resp, "x-waf-request-id"), Some("req-abc-123"));
        assert_eq!(header_val(&resp, "x-waf-risk-score"), Some("12"));
        assert_eq!(header_val(&resp, "x-waf-action"), Some("allow"));
        assert_eq!(header_val(&resp, "x-waf-rule-id"), Some("none"));
        assert_eq!(header_val(&resp, "x-waf-cache"), Some("MISS"));
        assert_eq!(header_val(&resp, "x-waf-mode"), Some("enforce"));
    }

    // (c) access-bypass passthrough: action=allow even though engine never ran
    #[test]
    fn inject_for_passthrough_uses_meta_action_allow_on_access_bypass() {
        let meta = WafDecisionMeta::default(); // action="allow"
        let ctx = ctx_with(Some(meta), "req-bypass", CacheStatus::Bypass, false);
        let mut resp = build_resp_with_extra(&[]);

        inject_for_passthrough(&mut resp, &ctx).expect("inject");

        assert_eq!(header_val(&resp, "x-waf-action"), Some("allow"));
        assert_eq!(header_val(&resp, "x-waf-cache"), Some("BYPASS"));
    }

    // Red-team F9: preserve log_only intended action through passthrough.
    #[test]
    fn inject_for_passthrough_preserves_log_only_action_not_hardcoded_allow() {
        let meta = WafDecisionMeta {
            action: "block",
            risk_score: 87,
            rule_id: Some("R-LO".into()),
            mode: "log_only",
        };
        let ctx = ctx_with(Some(meta), "req-lo", CacheStatus::Miss, true);
        let mut resp = build_resp_with_extra(&[]);

        inject_for_passthrough(&mut resp, &ctx).expect("inject");

        assert_eq!(header_val(&resp, "x-waf-action"), Some("block"));
        assert_eq!(header_val(&resp, "x-waf-mode"), Some("log_only"));
        assert_eq!(header_val(&resp, "x-waf-rule-id"), Some("R-LO"));
        assert_eq!(header_val(&resp, "x-waf-risk-score"), Some("87"));
    }

    // Snapshot-None fallback: should not occur but contract demands all 6 anyway.
    // Red-team F8: mode comes from host_config, NOT hardcoded "enforce".
    #[test]
    fn inject_for_passthrough_falls_back_when_meta_is_none_with_log_only_host() {
        let ctx = ctx_with(None, "req-none", CacheStatus::Bypass, true);
        let mut resp = build_resp_with_extra(&[]);

        inject_for_passthrough(&mut resp, &ctx).expect("inject");

        assert_eq!(header_val(&resp, "x-waf-action"), Some("allow"));
        assert_eq!(header_val(&resp, "x-waf-risk-score"), Some("0"));
        assert_eq!(header_val(&resp, "x-waf-rule-id"), Some("none"));
        assert_eq!(header_val(&resp, "x-waf-cache"), Some("BYPASS"));
        assert_eq!(
            header_val(&resp, "x-waf-mode"),
            Some("log_only"),
            "fallback mode MUST derive from host_config.log_only_mode, not be hardcoded enforce"
        );
    }

    // ── cache HIT path via duplex Session ─────────────────────────────────────

    fn http1_request_bytes() -> Vec<u8> {
        b"GET /p HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()
    }

    async fn session_over_duplex() -> (Session, tokio::task::JoinHandle<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (server_side, mut client_side) = tokio::io::duplex(64 * 1024);
        client_side.write_all(&http1_request_bytes()).await.expect("write");
        let drain = tokio::spawn(async move {
            let mut out = Vec::new();
            let _ = client_side.read_to_end(&mut out).await;
            out
        });
        let mut session = Session::new_h1(Box::new(server_side));
        let ok = session.read_request().await.expect("read_request");
        assert!(ok);
        (session, drain)
    }

    fn cached_response_with(headers: &[(&str, &str)]) -> Arc<CachedResponse> {
        Arc::new(CachedResponse {
            status: 200,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            body: Bytes::from_static(b"cached-body"),
            max_age: 60,
        })
    }

    // (b) cache HIT injects all 6 with X-WAF-Cache: HIT + fresh req_id from ctx.
    #[tokio::test]
    async fn write_cached_entry_emits_six_headers_with_cache_hit_and_fresh_req_id() {
        let meta = WafDecisionMeta {
            action: "allow",
            risk_score: 5,
            rule_id: None,
            mode: "enforce",
        };
        let ctx = ctx_with(Some(meta), "req-hit-FRESH", CacheStatus::Hit, false);
        let entry = cached_response_with(&[("content-type", "text/plain")]);

        let (mut session, drain) = session_over_duplex().await;
        write_cached_entry(&mut session, &entry, &ctx).await.expect("write hit");

        drop(session);
        let bytes = drain.await.expect("drain");
        let wire = String::from_utf8_lossy(&bytes);

        assert!(wire.starts_with("HTTP/1.1 200"), "wire: {wire}");
        assert!(wire.contains("cached-body"), "wire: {wire}");
        // Six observability headers present with HIT.
        let lower = wire.to_ascii_lowercase();
        for needle in [
            "x-waf-request-id: req-hit-fresh",
            "x-waf-risk-score: 5",
            "x-waf-action: allow",
            "x-waf-rule-id: none",
            "x-waf-cache: hit",
            "x-waf-mode: enforce",
        ] {
            assert!(lower.contains(needle), "missing `{needle}` in wire: {wire}");
        }
    }

    // Red-team F9: write_cached_entry must NOT hardcode action="allow" — preserves meta.action.
    #[tokio::test]
    async fn write_cached_entry_preserves_meta_action_not_hardcoded_allow() {
        let meta = WafDecisionMeta {
            action: "block",
            risk_score: 99,
            rule_id: Some("R-X".into()),
            mode: "log_only",
        };
        let ctx = ctx_with(Some(meta), "req-lo-hit", CacheStatus::Hit, true);
        let entry = cached_response_with(&[]);

        let (mut session, drain) = session_over_duplex().await;
        write_cached_entry(&mut session, &entry, &ctx).await.expect("write hit");

        drop(session);
        let bytes = drain.await.expect("drain");
        let lower = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        assert!(lower.contains("x-waf-action: block"));
        assert!(lower.contains("x-waf-mode: log_only"));
        assert!(lower.contains("x-waf-rule-id: r-x"));
        assert!(lower.contains("x-waf-risk-score: 99"));
        assert!(lower.contains("x-waf-cache: hit"));
    }

    // Red-team F3/F6: cache HIT must NOT replay any x-waf-* baked into the stored
    // headers (defense-in-depth — capture should have stripped them, but here we
    // verify write_cached_entry's inject overrides via insert_header semantics).
    #[tokio::test]
    async fn write_cached_entry_does_not_replay_stale_x_waf_headers_from_entry() {
        let meta = WafDecisionMeta {
            action: "allow",
            risk_score: 1,
            rule_id: None,
            mode: "enforce",
        };
        let ctx = ctx_with(Some(meta), "req-FRESH", CacheStatus::Hit, false);
        // Stale headers somehow stored in cache (older buggy build).
        let entry = cached_response_with(&[
            ("x-waf-request-id", "STALE-from-different-client"),
            ("x-waf-cache", "MISS"),
            ("x-waf-action", "block"),
        ]);

        let (mut session, drain) = session_over_duplex().await;
        write_cached_entry(&mut session, &entry, &ctx).await.expect("write");

        drop(session);
        let bytes = drain.await.expect("drain");
        let wire = String::from_utf8_lossy(&bytes);
        let lower = wire.to_ascii_lowercase();

        assert!(
            !lower.contains("stale-from-different-client"),
            "stale request id from prior client must NOT replay on HIT: {wire}"
        );
        assert!(lower.contains("x-waf-request-id: req-fresh"));
        assert!(lower.contains("x-waf-cache: hit"));
        assert!(lower.contains("x-waf-action: allow"));
        // Ensure only one of each header on the wire (insert, not append).
        for name in ["x-waf-request-id", "x-waf-cache", "x-waf-action"] {
            let count = lower.matches(&format!("{name}:")).count();
            assert_eq!(count, 1, "{name} must appear exactly once, got {count} in: {wire}");
        }
    }
}

// ── Phase 7: contract-compliance gate over the FULL egress inventory ────────
//
// Asserts cross-cutting invariants required by Interop Contract v2.3 §5 that
// span more than a single egress path:
//
//  * FR-035 `HeaderFilterConfig::default().preserve_prefixes` keeps `x-waf-`
//    so injected observability headers survive the global outbound scrub.
//  * `HostConfig::default().header_blocklist` does NOT enumerate any
//    `x-waf-*` name — protects against silent strip by the per-host filter.
//  * Risk-score wiring is real (non-hardcoded): when `RiskConfig.enabled`
//    is `true`, a Contributor delta produces a non-zero `ScorerResult.score`,
//    so `WafDecision::with_risk_score` does not return the always-zero stub.
//  * Every public injector helper emits exactly six contract headers — used
//    as a tripwire if a future variant change breaks the surface count.
//  * Idempotency holds across mixed helper calls (cache HIT re-inject must
//    not append).

mod phase7 {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use bytes::Bytes;
    use gateway::context::{GatewayCtx, WafDecisionMeta};
    use gateway::waf_observability_headers::{
        CacheStatus, WafHeaderValues, inject_for_passthrough, inject_for_passthrough_with_cache,
        inject_for_pre_inspect_or_error, inject_waf_observability_headers,
    };
    use waf_common::config::HeaderFilterConfig;
    use waf_common::tier::Tier;
    use waf_common::{HostConfig, RequestCtx};

    const CONTRACT_HEADERS: &[&str] = &[
        "x-waf-request-id",
        "x-waf-risk-score",
        "x-waf-action",
        "x-waf-rule-id",
        "x-waf-cache",
        "x-waf-mode",
    ];

    fn build_resp() -> pingora_http::ResponseHeader {
        pingora_http::ResponseHeader::build(200, None).expect("build resp")
    }

    fn observability_header_count(resp: &pingora_http::ResponseHeader) -> usize {
        CONTRACT_HEADERS
            .iter()
            .filter(|n| resp.headers.get(**n).is_some())
            .count()
    }

    fn ctx_with_request_id(req_id: &str, log_only: bool) -> GatewayCtx {
        let hc = HostConfig {
            log_only_mode: log_only,
            ..HostConfig::default()
        };
        let host_config = Arc::new(hc);
        let request_ctx = RequestCtx {
            req_id: req_id.into(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            client_port: 1234,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            path: "/p".into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::clone(&host_config),
            geo: None,
            tier: Tier::CatchAll,
            tier_policy: RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
            device_fp: None,
            tx_velocity_token: None,
        };
        GatewayCtx {
            request_ctx: Some(request_ctx),
            host_config: Some(host_config),
            ..GatewayCtx::default()
        }
    }

    // ── FR-035 + blocklist survival ──────────────────────────────────────────

    #[test]
    fn fr_035_default_preserves_x_waf_prefix_so_observability_headers_survive_strip() {
        let cfg = HeaderFilterConfig::default();
        assert!(
            cfg.preserve_prefixes.iter().any(|p| p.eq_ignore_ascii_case("x-waf-")),
            "HeaderFilterConfig::default().preserve_prefixes MUST contain `x-waf-` so \
             FR-035 cannot strip injected observability headers (red-team F2)"
        );
    }

    #[test]
    fn default_host_header_blocklist_does_not_strip_x_waf_observability_headers() {
        let hc = HostConfig::default();
        for name in CONTRACT_HEADERS {
            let listed = hc.header_blocklist.iter().any(|b| b.eq_ignore_ascii_case(name));
            assert!(
                !listed,
                "default header_blocklist must not enumerate `{name}` — \
                 doing so would silently delete a contract-mandatory observability header"
            );
        }
    }

    // ── Scorer reality: enabled config yields non-zero score (red-team F-RT05) ─

    #[tokio::test]
    async fn risk_scorer_with_enabled_config_yields_non_zero_score_not_hardcoded_zero() {
        use std::sync::Arc;
        use waf_engine::risk::config::RiskConfig;
        use waf_engine::risk::scorer::Scorer;
        use waf_engine::risk::state::{Contributor, ContributorKind};
        use waf_engine::risk::store::memory::MemoryRiskStore;

        let cfg = RiskConfig {
            enabled: true,
            ..RiskConfig::default()
        };
        let cfg = Arc::new(arc_swap::ArcSwap::from_pointee(cfg));
        let store: Arc<MemoryRiskStore> = Arc::new(MemoryRiskStore::new());
        let scorer = Scorer::new(store, cfg);

        // Build a request ctx that produces a non-empty RiskKey (IP-keyed).
        let hc = Arc::new(HostConfig::default());
        let ctx = RequestCtx {
            req_id: "rs-test".into(),
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            client_port: 9000,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            path: "/p".into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: hc,
            geo: None,
            tier: Tier::CatchAll,
            tier_policy: RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
            device_fp: None,
            tx_velocity_token: None,
        };

        // A non-trivial sync delta drives the score up so the scorer must emit
        // a non-zero result. If the engine ever stops threading the result into
        // WafDecision.risk_score, the X-WAF-Risk-Score wire value silently
        // collapses to `0` — this test catches that regression at the source.
        let deltas = vec![Contributor::new(ContributorKind::Rule("R-42".into()), 40, 0)];

        let result = scorer
            .score(&ctx, None, &deltas, None, 0)
            .await
            .expect("scorer must not error");

        assert!(
            result.score > 0,
            "RiskConfig.enabled=true with a 40-point delta must produce score>0; \
             got {} — risk_score wiring is broken (red-team F-RT05)",
            result.score
        );
        assert!(
            result.score <= 100,
            "scorer must clamp to 0..=100; got {}",
            result.score
        );
    }

    // ── Six-header contract surface count (helper-coverage tripwire) ──────────

    #[test]
    fn raw_injector_emits_exactly_six_observability_headers() {
        let mut resp = build_resp();
        let vals = WafHeaderValues {
            request_id: "rid",
            risk_score: 17,
            action: "block",
            rule_id: Some("R-1"),
            mode: "enforce",
            cache: CacheStatus::Miss,
        };
        inject_waf_observability_headers(&mut resp, &vals).expect("inject");
        assert_eq!(
            observability_header_count(&resp),
            6,
            "raw injector MUST emit all six contract headers"
        );
    }

    #[test]
    fn passthrough_injector_emits_exactly_six_observability_headers() {
        let mut ctx = ctx_with_request_id("rid-pt", false);
        ctx.waf_decision_meta = Some(WafDecisionMeta::default());
        ctx.cache_status = CacheStatus::Miss;
        let mut resp = build_resp();
        inject_for_passthrough(&mut resp, &ctx).expect("inject");
        assert_eq!(observability_header_count(&resp), 6);
    }

    #[test]
    fn passthrough_with_cache_override_emits_exactly_six_observability_headers() {
        let mut ctx = ctx_with_request_id("rid-hit", false);
        ctx.waf_decision_meta = Some(WafDecisionMeta::default());
        let mut resp = build_resp();
        inject_for_passthrough_with_cache(&mut resp, &ctx, CacheStatus::Hit).expect("inject");
        assert_eq!(observability_header_count(&resp), 6);
        assert_eq!(
            resp.headers
                .get("x-waf-cache")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok()),
            Some("HIT")
        );
    }

    #[test]
    fn pre_inspect_or_error_injector_emits_exactly_six_observability_headers() {
        let ctx = ctx_with_request_id("rid-err", false);
        let mut resp = build_resp();
        inject_for_pre_inspect_or_error(&mut resp, &ctx, "circuit_breaker", "unused").expect("inject");
        assert_eq!(observability_header_count(&resp), 6);
    }

    // ── Idempotency across mixed helpers (cache HIT re-inject scenario) ──────

    #[test]
    fn mixed_helper_calls_never_append_each_header_appears_exactly_once() {
        let mut ctx = ctx_with_request_id("rid-mix", true);
        ctx.waf_decision_meta = Some(WafDecisionMeta {
            action: "block",
            risk_score: 88,
            rule_id: Some("R-mix".into()),
            mode: "log_only",
        });
        let mut resp = build_resp();

        // First pass: passthrough with MISS (response_filter path).
        inject_for_passthrough_with_cache(&mut resp, &ctx, CacheStatus::Miss).expect("p1");
        // Second pass: cache HIT writer re-runs the injector with HIT.
        inject_for_passthrough_with_cache(&mut resp, &ctx, CacheStatus::Hit).expect("p2");

        for name in [
            "x-waf-request-id",
            "x-waf-risk-score",
            "x-waf-action",
            "x-waf-rule-id",
            "x-waf-cache",
            "x-waf-mode",
        ] {
            assert_eq!(
                resp.headers.get_all(name).iter().count(),
                1,
                "{name} must appear exactly once after mixed helper calls"
            );
        }
        // Latest values must win (insert, not append).
        assert_eq!(
            resp.headers
                .get("x-waf-cache")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok()),
            Some("HIT")
        );
        assert_eq!(
            resp.headers
                .get("x-waf-mode")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok()),
            Some("log_only")
        );
    }

    // ── log_only end-to-end: intended action propagated, not rewritten ───────

    #[test]
    fn log_only_mode_reports_intended_block_action_without_enforcing() {
        let mut ctx = ctx_with_request_id("rid-lo-e2e", true);
        ctx.waf_decision_meta = Some(WafDecisionMeta {
            action: "block",
            risk_score: 65,
            rule_id: Some("R-LO-e2e".into()),
            mode: "log_only",
        });
        let mut resp = build_resp();
        inject_for_passthrough(&mut resp, &ctx).expect("inject");

        // The wire-level promise §5 makes about log_only: the gateway STILL
        // reports what the engine WOULD have done (action=block), but the
        // `X-WAF-Mode: log_only` tells operators no enforcement happened.
        assert_eq!(
            resp.headers
                .get("x-waf-action")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok()),
            Some("block"),
            "log_only must NOT collapse intended action to allow (red-team F9)"
        );
        assert_eq!(
            resp.headers
                .get("x-waf-mode")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok()),
            Some("log_only")
        );
    }
}
