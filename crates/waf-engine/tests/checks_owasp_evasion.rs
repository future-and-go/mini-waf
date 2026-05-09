//! Coverage for `checks::owasp` URL-decode evasion paths in single-field
//! regex and the `field=all` recursive matcher (skip routing headers,
//! query/body/header coverage).

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

#[path = "support/owasp_helpers.rs"]
mod helpers;

use bytes::Bytes;
use helpers::make_ctx;
use waf_engine::checks::Check;
use waf_engine::checks::OWASPCheck;

#[test]
fn t_regex_single_field_url_decoded_evasion() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-SF-RE
    name: single-field regex with URL evasion
    category: misc
    severity: critical
    paranoia: 1
    field: query
    operator: regex
    value: "<script>"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.query = "q=%3Cscript%3E".into();
    assert!(c.check(&ctx).is_some(), "single-field regex must url-decode");
}

#[test]
fn t_regex_single_field_recursive_decode() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-SF-REC
    name: single-field recursive decode
    category: misc
    severity: critical
    paranoia: 1
    field: query
    operator: regex
    value: "evil"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.query = "x=%2565vil".into();
    assert!(c.check(&ctx).is_some());
}

#[test]
fn t_regex_single_field_no_match_returns_false() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-SF-NO
    name: no match
    category: misc
    severity: critical
    paranoia: 1
    field: query
    operator: regex
    value: "evil"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.query = "name=alice".into();
    assert!(c.check(&ctx).is_none());
}

#[test]
fn t_regex_all_field_skips_routing_headers() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-ALL-RE
    name: ssrf-style
    category: misc
    severity: critical
    paranoia: 1
    field: all
    operator: regex
    value: "localhost"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.headers.insert("host".into(), "localhost:8080".into());
    assert!(c.check(&ctx).is_none(), "host header should be skipped");
}

#[test]
fn t_regex_all_field_fires_on_non_routing_header() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-ALL-HDR
    name: header attack
    category: misc
    severity: critical
    paranoia: 1
    field: all
    operator: regex
    value: "evilpayload"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.headers.insert("x-custom".into(), "evilpayload".into());
    assert!(c.check(&ctx).is_some());
}

#[test]
fn t_regex_all_field_body_match() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-ALL-BODY
    name: body attack
    category: misc
    severity: critical
    paranoia: 1
    field: all
    operator: regex
    value: "evilbody"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.body_preview = Bytes::from("payload=evilbody");
    assert!(c.check(&ctx).is_some());
}

#[test]
fn t_regex_all_field_query_decoded_match() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-ALL-Q
    name: query encoded
    category: misc
    severity: critical
    paranoia: 1
    field: all
    operator: regex
    value: "<script>"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.query = "x=%3Cscript%3E".into();
    assert!(c.check(&ctx).is_some());
}
