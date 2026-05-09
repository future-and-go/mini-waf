//! Coverage for `checks::owasp` loaders: `from_yaml`, `from_directory`,
//! `from_file_or_default`, `default()`, plus paranoia/disabled gating.

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

use helpers::{make_ctx, make_ctx_owasp_disabled};
use waf_engine::checks::Check;
use waf_engine::checks::OWASPCheck;

#[test]
fn t_owasp_disabled_returns_none() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-DIS
    name: dummy
    category: misc
    severity: critical
    paranoia: 1
    field: method
    operator: contains
    value: "GET"
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    let ctx = make_ctx_owasp_disabled();
    assert!(c.check(&ctx).is_none(), "disabled owasp must skip");
}

#[test]
fn t_from_yaml_invalid_returns_empty() {
    let c = OWASPCheck::from_yaml("not: valid: yaml: !@#");
    assert_eq!(c.rule_count(), 0);
}

#[test]
fn t_from_directory_walks_subdirs() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let sub = tmp.path().join("sub");
    std::fs::create_dir(&sub).expect("mkdir");
    let yaml = r#"
version: "1.0"
rules:
  - id: T-DIR1
    name: dir test
    category: misc
    severity: critical
    paranoia: 1
    field: query
    operator: contains
    value: "x"
    action: block
"#;
    std::fs::write(sub.join("rules.yaml"), yaml).expect("write");
    std::fs::write(tmp.path().join("README.txt"), "hi").expect("write txt");
    let c = OWASPCheck::from_directory(tmp.path());
    assert_eq!(c.rule_count(), 1);
}

#[test]
fn t_from_directory_skips_non_ruleset_yaml() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    std::fs::write(tmp.path().join("config.yaml"), "key: value\nnested: {a: 1}\n").expect("write");
    let c = OWASPCheck::from_directory(tmp.path());
    assert_eq!(c.rule_count(), 0, "non-ruleset YAML must be skipped");
}

#[test]
fn t_from_directory_nonexistent_dir() {
    let c = OWASPCheck::from_directory(std::path::Path::new("/no/such/dir/xyz123"));
    assert_eq!(c.rule_count(), 0);
}

#[test]
fn t_from_file_or_default_with_existing_file() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("rules.yaml");
    let yaml = r#"
version: "1.0"
rules:
  - id: T-FILE
    name: file test
    category: misc
    severity: critical
    paranoia: 1
    field: query
    operator: contains
    value: "hit"
    action: block
"#;
    std::fs::write(&path, yaml).expect("write");
    let c = OWASPCheck::from_file_or_default(&path);
    assert!(c.rule_count() >= 1);
}

#[test]
fn t_default_constructor_works() {
    let c = OWASPCheck::default();
    assert!(c.rule_count() >= 1, "default must have at least the embedded rules");
}

#[test]
fn t_paranoia_level_4_rule_skipped_at_default_pl1() {
    let yaml = r#"
version: "1.0"
rules:
  - id: T-PL4
    name: PL4 only
    category: misc
    severity: critical
    paranoia: 4
    field: method
    operator: not_in
    value:
      - GET
    action: block
"#;
    let c = OWASPCheck::from_yaml(yaml);
    assert_eq!(c.rule_count(), 1);
    let mut ctx = make_ctx();
    ctx.method = "POST".into();
    assert!(c.check(&ctx).is_none(), "PL4 rule must be skipped at PL1");
}
