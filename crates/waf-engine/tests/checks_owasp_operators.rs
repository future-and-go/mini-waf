//! Coverage for `checks::owasp` operator branches: `contains`, `lt`, `gt`,
//! `not_in`, `regex`, plus malformed/unsupported operator skip paths.

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

use helpers::make_ctx;
use waf_engine::checks::Check;
use waf_engine::checks::OWASPCheck;

#[test]
fn t_contains_matches_query() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-CONTAINS
    name: Contains test
    category: misc
    severity: critical
    paranoia: 1
    field: query
    operator: contains
    value: "evil-token"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    assert_eq!(c.rule_count(), 1);
    let mut ctx = make_ctx();
    ctx.query = "x=1&payload=evil-token&y=2".into();
    assert!(c.check(&mut ctx).is_some());
    let mut ctx2 = make_ctx();
    ctx2.query = "x=1".into();
    assert!(c.check(&mut ctx2).is_none());
}

#[test]
fn t_contains_with_non_string_value_skipped() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-BADCONTAINS
    name: Contains with int value
    category: misc
    severity: critical
    paranoia: 1
    field: query
    operator: contains
    value: 42
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    assert_eq!(c.rule_count(), 0, "non-string value for contains must be skipped");
}

#[test]
fn t_lt_operator_blocks_below_threshold() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-LT
    name: content_length lt 5
    category: misc
    severity: critical
    paranoia: 1
    field: content_length
    operator: lt
    value: 5
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let mut ctx = make_ctx();
    ctx.content_length = 2;
    assert!(c.check(&mut ctx).is_some());
    ctx.content_length = 50;
    assert!(c.check(&mut ctx).is_none());
}

#[test]
fn t_lt_with_non_int_skipped() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-BADLT
    name: lt with string
    category: misc
    severity: critical
    paranoia: 1
    field: content_length
    operator: lt
    value: "not-a-number"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    assert_eq!(c.rule_count(), 0);
}

#[test]
fn t_gt_with_non_int_skipped() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-BADGT
    name: gt with list
    category: misc
    severity: critical
    paranoia: 1
    field: content_length
    operator: gt
    value: ["a","b"]
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    assert_eq!(c.rule_count(), 0);
}

#[test]
fn t_not_in_with_non_list_skipped() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-BADNI
    name: not_in with str
    category: misc
    severity: critical
    paranoia: 1
    field: method
    operator: not_in
    value: "GET"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    assert_eq!(c.rule_count(), 0);
}

#[test]
fn t_regex_with_non_string_skipped() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-BADRE
    name: regex with int
    category: misc
    severity: critical
    paranoia: 1
    field: query
    operator: regex
    value: 99
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    assert_eq!(c.rule_count(), 0);
}

#[test]
fn t_invalid_regex_skipped() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-INVALIDRE
    name: invalid regex
    category: misc
    severity: critical
    paranoia: 1
    field: query
    operator: regex
    value: "[invalid("
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    assert_eq!(c.rule_count(), 0);
}

#[test]
fn t_unsupported_operator_skipped() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-UNSUP
    name: ne operator
    category: misc
    severity: critical
    paranoia: 1
    field: method
    operator: "matrix_multiply"
    value: "x"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    assert_eq!(c.rule_count(), 0);
}
