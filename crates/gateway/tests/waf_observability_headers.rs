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

fn baseline_values<'a>() -> WafHeaderValues<'a> {
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

// ── Phase 3 stub: ctx snapshot Default must be `allow`, not "" (red-team F13)

#[test]
#[ignore = "Phase 3 dependency: WafDecisionMeta lands with ctx snapshot — assert Default::action == \"allow\""]
fn waf_decision_meta_default_action_is_allow_not_empty_string() {
    // Phase 3 will introduce `WafDecisionMeta` (snapshot stored on `GatewayCtx`).
    // Its `Default` impl MUST yield `action == "allow"`, never `""`, otherwise
    // pre-inspect / fast-path egress will emit a contract-illegal blank action.
    //
    // Replace this stub with:
    //   use gateway::context::WafDecisionMeta;
    //   assert_eq!(WafDecisionMeta::default().action, "allow");
    panic!("Phase 3 stub: replace with WafDecisionMeta::default() assertion");
}

// ── Phase 6 stubs: pre-inspect / error-page paths exist in test surface ─────

#[test]
#[ignore = "Phase 6 dependency: access-gate 403 path must inject six X-WAF-* headers"]
fn access_gate_403_emits_six_observability_headers() {
    panic!("Phase 6 stub: implement once `request_filter` access-gate writes the injector");
}

#[test]
#[ignore = "Phase 6 dependency: fail-closed 503 path (request_ctx == None) must inject six headers + minimal audit stub"]
fn fail_closed_503_emits_six_observability_headers_with_fallback_uuid() {
    panic!("Phase 6 stub: implement once `request_filter` fail-closed arm writes the injector");
}

#[test]
#[ignore = "Phase 6 dependency: HTTP→HTTPS 301 redirect path must inject six headers"]
fn http_to_https_301_redirect_emits_six_observability_headers() {
    panic!("Phase 6 stub: implement once `request_filter` early-redirect arm writes the injector");
}

#[test]
#[ignore = "Phase 6 dependency: fail_to_proxy transport error (502/503/timeout/circuit_breaker) must inject six headers"]
fn fail_to_proxy_transport_error_emits_six_observability_headers() {
    panic!("Phase 6 stub: implement once `fail_to_proxy` writes the injector");
}

#[test]
#[ignore = "Phase 6 dependency: health endpoint 200 must inject six headers (action=allow, cache=BYPASS)"]
fn health_endpoint_200_emits_six_observability_headers() {
    panic!("Phase 6 stub: implement once `request_filter` health arm writes the injector");
}

// ── Phase 5 stubs: passthrough + cache-HIT egress paths ─────────────────────

#[test]
#[ignore = "Phase 5 dependency: allow → upstream (MISS) response must inject six headers as final response_filter step"]
fn allow_upstream_miss_emits_six_observability_headers_with_cache_miss() {
    // Must inject AFTER FR-035 strip + cache-capture so per-request X-WAF-*
    // never enters the cache snapshot (cross-request leak guard).
    panic!("Phase 5 stub: implement once `response_filter` writes the injector last");
}

#[test]
#[ignore = "Phase 5 dependency: challenge-passed / access-bypass passthrough must inject six headers (action=allow)"]
fn challenge_passed_passthrough_emits_six_observability_headers() {
    panic!("Phase 5 stub: implement once passthrough arm of `response_filter` writes the injector");
}

#[test]
#[ignore = "Phase 5 dependency: cache HIT response must inject six headers with X-WAF-Cache: HIT"]
fn cache_hit_emits_six_observability_headers_with_cache_hit() {
    // `write_cached_entry` (response_cache_integration.rs) must call the
    // injector with `CacheStatus::Hit` so served-from-cache responses still
    // advertise the contract surface.
    panic!("Phase 5 stub: implement once `write_cached_entry` writes the injector");
}
