//! Phase 05: tier compiled-rule edge cases.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::approx_constant,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use http::{HeaderMap, HeaderValue, Method};

use gateway::tiered::{CompileError, MethodSet, compile_rule, compile_rules};
use waf_common::tier::{HttpMethod, Tier, TierClassifierRule};
use waf_common::tier_match::{HeaderMatch, HostMatch, PathMatch};

fn rule(priority: u32, tier: Tier) -> TierClassifierRule {
    TierClassifierRule {
        priority,
        tier,
        host: None,
        path: None,
        method: None,
        headers: None,
    }
}

#[test]
fn method_set_insert_and_contains() {
    let mut s = MethodSet::empty();
    s.insert(HttpMethod::Get);
    s.insert(HttpMethod::Post);
    assert!(s.contains(HttpMethod::Get));
    assert!(s.contains(HttpMethod::Post));
    assert!(!s.contains(HttpMethod::Delete));
    assert!(s.contains_http(&Method::GET));
    assert!(s.contains_http(&Method::POST));
    assert!(!s.contains_http(&Method::DELETE));
}

#[test]
fn method_set_unknown_extension_method_never_matches() {
    let mut s = MethodSet::empty();
    s.insert(HttpMethod::Get);
    let weird = Method::from_bytes(b"PROPFIND").expect("valid extension method");
    assert!(!s.contains_http(&weird));
}

#[test]
fn method_set_all_methods_round_trip() {
    let mut s = MethodSet::empty();
    for m in [
        HttpMethod::Get,
        HttpMethod::Head,
        HttpMethod::Post,
        HttpMethod::Put,
        HttpMethod::Delete,
        HttpMethod::Connect,
        HttpMethod::Options,
        HttpMethod::Trace,
        HttpMethod::Patch,
    ] {
        s.insert(m);
        assert!(s.contains(m));
    }
    for m in [
        Method::GET,
        Method::HEAD,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::CONNECT,
        Method::OPTIONS,
        Method::TRACE,
        Method::PATCH,
    ] {
        assert!(s.contains_http(&m), "{m} should match");
    }
}

#[test]
fn compile_rule_with_invalid_regex_path_errors() {
    let mut r = rule(10, Tier::Critical);
    r.path = Some(PathMatch::Regex { value: "[".to_string() });
    let err = compile_rule(0, &r).expect_err("bad regex must error");
    assert!(matches!(err, CompileError::BadRegex { idx: 0, .. }));
}

#[test]
fn compile_rule_with_invalid_regex_host_errors() {
    let mut r = rule(10, Tier::Critical);
    r.host = Some(HostMatch::Regex { value: "[".to_string() });
    let err = compile_rule(7, &r).expect_err("bad host regex must error");
    assert!(matches!(err, CompileError::BadRegex { idx: 7, .. }));
}

#[test]
fn compile_rule_bad_header_name_errors() {
    let mut r = rule(10, Tier::Critical);
    r.headers = Some(vec![HeaderMatch {
        name: "bad header\n".to_string(),
        value: "v".to_string(),
    }]);
    let err = compile_rule(3, &r).expect_err("bad name must error");
    assert!(matches!(err, CompileError::BadHeaderName { idx: 3, .. }));
}

#[test]
fn compile_rule_bad_header_value_errors() {
    let mut r = rule(10, Tier::Critical);
    r.headers = Some(vec![HeaderMatch {
        name: "x-good".to_string(),
        value: "bad\nvalue".to_string(),
    }]);
    let err = compile_rule(2, &r).expect_err("bad value must error");
    assert!(matches!(err, CompileError::BadHeaderValue { idx: 2, .. }));
}

#[test]
fn compiled_rule_matches_full_combination() {
    let mut r = rule(50, Tier::High);
    r.host = Some(HostMatch::Exact {
        value: "Api.Example.Com".to_string(),
    });
    r.path = Some(PathMatch::Prefix {
        value: "/v1/".to_string(),
    });
    r.method = Some(vec![HttpMethod::Get]);
    r.headers = Some(vec![HeaderMatch {
        name: "x-api-key".to_string(),
        value: "abc".to_string(),
    }]);
    let cr = compile_rule(0, &r).expect("compile");
    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-api-key", HeaderValue::from_static("abc"));
    assert!(cr.matches("api.example.com", "/v1/users", &Method::GET, &hdrs));
    // wrong method
    assert!(!cr.matches("api.example.com", "/v1/users", &Method::POST, &hdrs));
    // wrong path
    assert!(!cr.matches("api.example.com", "/v2/users", &Method::GET, &hdrs));
    // wrong host
    assert!(!cr.matches("other.com", "/v1/users", &Method::GET, &hdrs));
    // missing required header
    let empty = HeaderMap::new();
    assert!(!cr.matches("api.example.com", "/v1/users", &Method::GET, &empty));
    // wrong header value
    let mut bad = HeaderMap::new();
    bad.insert("x-api-key", HeaderValue::from_static("nope"));
    assert!(!cr.matches("api.example.com", "/v1/users", &Method::GET, &bad));
}

#[test]
fn host_match_suffix_lowercased_at_compile() {
    let mut r = rule(1, Tier::Medium);
    r.host = Some(HostMatch::Suffix {
        value: ".EXAMPLE.com".to_string(),
    });
    let cr = compile_rule(0, &r).expect("compile");
    let hdrs = HeaderMap::new();
    assert!(cr.matches("api.example.com", "/", &Method::GET, &hdrs));
    assert!(!cr.matches("example.org", "/", &Method::GET, &hdrs));
}

#[test]
fn path_match_regex_compiles_and_matches() {
    let mut r = rule(1, Tier::Medium);
    r.path = Some(PathMatch::Regex {
        value: "^/admin/.*$".to_string(),
    });
    let cr = compile_rule(0, &r).expect("compile");
    let hdrs = HeaderMap::new();
    assert!(cr.matches("h", "/admin/x", &Method::GET, &hdrs));
    assert!(!cr.matches("h", "/public", &Method::GET, &hdrs));
}

#[test]
fn host_match_regex_compiles() {
    let mut r = rule(1, Tier::Medium);
    r.host = Some(HostMatch::Regex {
        value: "^api[0-9]+\\.example$".to_string(),
    });
    let cr = compile_rule(0, &r).expect("compile");
    let hdrs = HeaderMap::new();
    assert!(cr.matches("api1.example", "/", &Method::GET, &hdrs));
    assert!(!cr.matches("api.example", "/", &Method::GET, &hdrs));
}

#[test]
fn path_match_exact() {
    let mut r = rule(1, Tier::Medium);
    r.path = Some(PathMatch::Exact {
        value: "/healthz".to_string(),
    });
    let cr = compile_rule(0, &r).expect("compile");
    let hdrs = HeaderMap::new();
    assert!(cr.matches("h", "/healthz", &Method::GET, &hdrs));
    assert!(!cr.matches("h", "/healthz/x", &Method::GET, &hdrs));
}

#[test]
fn compile_rules_sorts_by_priority_desc() {
    let rules = vec![rule(5, Tier::Medium), rule(100, Tier::Critical), rule(50, Tier::High)];
    let compiled = compile_rules(&rules).expect("compile");
    assert_eq!(compiled[0].priority, 100);
    assert_eq!(compiled[1].priority, 50);
    assert_eq!(compiled[2].priority, 5);
}

#[test]
fn compile_rules_propagates_first_error() {
    let mut bad = rule(1, Tier::Critical);
    bad.path = Some(PathMatch::Regex { value: "[".to_string() });
    let rules = vec![rule(10, Tier::Medium), bad];
    let err = compile_rules(&rules).expect_err("must propagate");
    assert!(matches!(err, CompileError::BadRegex { idx: 1, .. }));
}

#[test]
fn empty_rule_matches_anything() {
    let r = rule(1, Tier::CatchAll);
    let cr = compile_rule(0, &r).expect("compile");
    let hdrs = HeaderMap::new();
    assert!(cr.matches("anyhost", "/anything", &Method::GET, &hdrs));
    assert!(cr.matches("other", "/", &Method::POST, &hdrs));
}

#[test]
fn method_set_default_empty() {
    let s = MethodSet::default();
    assert!(!s.contains(HttpMethod::Get));
    assert!(!s.contains_http(&Method::GET));
}
