//! Coverage for `checks::mod` shared helpers — exercises the request_targets
//! decoder branches (path / query / cookie / body × raw / decoded / recursive)
//! through `SqlInjectionCheck` which calls them as fallback step 4.

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

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use waf_common::{DefenseConfig, HostConfig, RequestCtx};
use waf_engine::checks::Check;
use waf_engine::checks::SqlInjectionCheck;

fn make_ctx() -> RequestCtx {
    let host_config = Arc::new(HostConfig {
        code: "t".into(),
        host: "h".into(),
        defense_config: DefenseConfig {
            sqli: true,
            ..DefenseConfig::default()
        },
        ..HostConfig::default()
    });
    RequestCtx {
        req_id: "t".into(),
        client_ip: "1.2.3.4".parse().unwrap(),
        client_port: 0,
        method: "GET".into(),
        host: "h".into(),
        port: 80,
        path: "/".into(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config,
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: waf_common::RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
        tx_velocity_token: None,
    }
}

#[test]
fn t_sqli_in_url_encoded_body() {
    let c = SqlInjectionCheck::new();
    let mut ctx = make_ctx();
    // %27%20OR%201%3D1 → ' OR 1=1 → request_targets includes body(decoded)
    ctx.body_preview = Bytes::from("q=%27%20OR%201%3D1");
    assert!(c.check(&mut ctx).is_some(), "must url-decode body");
}

#[test]
fn t_sqli_in_double_encoded_body() {
    let c = SqlInjectionCheck::new();
    let mut ctx = make_ctx();
    ctx.body_preview = Bytes::from("q=%2527%2520OR%25201%253D1");
    assert!(
        c.check(&mut ctx).is_some(),
        "recursive decode must catch double-encoded SQLi"
    );
}

#[test]
fn t_sqli_in_double_encoded_query() {
    let c = SqlInjectionCheck::new();
    let mut ctx = make_ctx();
    ctx.query = "id=%2527%2520OR%25201%253D1".into();
    assert!(c.check(&mut ctx).is_some());
}

#[test]
fn t_sqli_in_double_encoded_path() {
    let c = SqlInjectionCheck::new();
    let mut ctx = make_ctx();
    ctx.path = "/api/%2527%2520OR%25201%253D1".into();
    assert!(c.check(&mut ctx).is_some());
}

#[test]
fn t_clean_request_no_match() {
    let c = SqlInjectionCheck::new();
    let mut ctx = make_ctx();
    ctx.path = "/api/users".into();
    ctx.query = "page=2&limit=20".into();
    ctx.body_preview = Bytes::from("name=alice");
    assert!(c.check(&mut ctx).is_none(), "clean request must not match");
}

#[test]
fn t_empty_query_skipped() {
    let c = SqlInjectionCheck::new();
    let mut ctx = make_ctx();
    ctx.path = "/api/list".into();
    ctx.query.clear();
    assert!(c.check(&mut ctx).is_none());
}

#[test]
fn t_empty_body_skipped() {
    let c = SqlInjectionCheck::new();
    let mut ctx = make_ctx();
    assert!(c.check(&mut ctx).is_none());
}

#[test]
fn t_sqli_disabled_returns_none() {
    let c = SqlInjectionCheck::new();
    let host_config = Arc::new(HostConfig {
        code: "t".into(),
        host: "h".into(),
        defense_config: DefenseConfig {
            sqli: false,
            ..DefenseConfig::default()
        },
        ..HostConfig::default()
    });
    let mut ctx = make_ctx();
    ctx.host_config = host_config;
    ctx.path = "/api/%2527%2520OR%25201%253D1".into();
    assert!(
        c.check(&mut ctx).is_none(),
        "disabled sqli must skip even on attack input"
    );
}
