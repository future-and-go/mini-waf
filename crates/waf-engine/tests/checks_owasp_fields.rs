//! Coverage for `checks::owasp` field-extractor branches: content_type,
//! user_agent, body, path_length, query_arg_count, unknown.

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
fn t_field_extractors_all_branches() {
    let cases = [
        ("content_type", "evil"),
        ("header_content_type", "evil"),
        ("user_agent", "evil"),
        ("header_user_agent", "evil"),
        ("body", "evil"),
        ("path_length", "100"),
        ("query_arg_count", "5"),
    ];
    for (field, val) in cases {
        let yaml = format!(
            r#"
version: "1.0"
rules:
  - id: T-{field}
    name: Test {field}
    category: misc
    severity: critical
    paranoia: 1
    field: {field}
    operator: contains
    value: "{val}"
    action: block
"#
        );
        let c = OWASPCheck::from_yaml(&yaml);
        assert_eq!(c.rule_count(), 1, "rule must compile for field={field}");
    }
}

#[test]
fn t_field_content_type_match() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-CT
    name: bad ct
    category: misc
    severity: critical
    paranoia: 1
    field: content_type
    operator: contains
    value: "evil"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.headers.insert("content-type".into(), "application/evil".into());
    assert!(c.check(&ctx).is_some());
}

#[test]
fn t_field_path_length_gt() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-PL
    name: long path
    category: misc
    severity: critical
    paranoia: 1
    field: path_length
    operator: gt
    value: 10
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.path = "/abcdefghijklmnop".into();
    assert!(c.check(&ctx).is_some());
}

#[test]
fn t_field_query_arg_count_gt() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-QC
    name: many args
    category: misc
    severity: critical
    paranoia: 1
    field: query_arg_count
    operator: gt
    value: 3
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.query = "a=1&b=2&c=3&d=4&e=5".into();
    assert!(c.check(&ctx).is_some());
    let mut ctx2 = make_ctx();
    ctx2.query = "a=1".into();
    assert!(c.check(&ctx2).is_none());
}

#[test]
fn t_field_unknown_returns_none() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-UNK
    name: unknown field
    category: misc
    severity: critical
    paranoia: 1
    field: nonexistent_field
    operator: contains
    value: "x"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let ctx = make_ctx();
    assert!(c.check(&ctx).is_none());
}

#[test]
fn t_field_body_match() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-BODY
    name: body field
    category: misc
    severity: critical
    paranoia: 1
    field: body
    operator: contains
    value: "evilpayload"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.body_preview = Bytes::from("data=evilpayload");
    assert!(c.check(&ctx).is_some());
}

#[test]
fn t_field_user_agent_match() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-UA
    name: ua field
    category: misc
    severity: critical
    paranoia: 1
    field: user_agent
    operator: contains
    value: "sqlmap"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.headers.insert("user-agent".into(), "sqlmap/1.0".into());
    assert!(c.check(&ctx).is_some());
}
