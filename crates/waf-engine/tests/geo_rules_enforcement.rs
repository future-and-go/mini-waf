//! Geo rules loaded from the admin API's file shape are enforced by the
//! engine: block rules block, deletions clear, allow rows union into a
//! single allow-only rule. Uses the deterministic `load_geo_rules` path —
//! watcher timing is covered by the reloader's own unit tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use std::io::Write;
use std::path::Path;

use common::{make_ctx, start_engine};
use waf_common::GeoIpInfo;
use waf_engine::checks::Check;

fn write_file(path: &Path, contents: &str) {
    let mut f = std::fs::File::create(path).expect("create rules file");
    f.write_all(contents.as_bytes()).expect("write rules file");
}

fn geo_ctx(iso: &str, country: &str) -> waf_common::RequestCtx {
    let mut ctx = make_ctx("test", "/", "203.0.113.7");
    ctx.geo = Some(GeoIpInfo {
        country: country.to_string(),
        iso_code: iso.to_string(),
        ..Default::default()
    });
    ctx
}

#[tokio::test(flavor = "multi_thread")]
async fn block_rule_from_file_is_enforced_and_delete_clears_it() {
    let fx = start_engine().await;
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("geo-rules.yaml");

    // Exact row shape the admin API persists.
    write_file(
        &path,
        r#"rules:
  - id: 1
    iso_code: "KP"
    action: "block"
    scope: "global"
    enabled: true
    country_name: "North Korea"
"#,
    );
    fx.engine.load_geo_rules(&path);

    let mut blocked = geo_ctx("KP", "North Korea");
    assert!(
        fx.engine.geo_check().check(&mut blocked).is_some(),
        "request from blocked country must be detected"
    );
    let mut allowed = geo_ctx("US", "United States");
    assert!(
        fx.engine.geo_check().check(&mut allowed).is_none(),
        "request from unlisted country must pass"
    );

    // Delete the rule (API rewrites the file without it) → enforcement stops.
    write_file(&path, "rules: []\n");
    fx.engine.load_geo_rules(&path);
    let mut after_delete = geo_ctx("KP", "North Korea");
    assert!(
        fx.engine.geo_check().check(&mut after_delete).is_none(),
        "deleted rule must no longer block"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_rows_union_into_single_allow_only_rule() {
    let fx = start_engine().await;
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("geo-rules.yaml");

    write_file(
        &path,
        r#"rules:
  - { id: 1, iso_code: "US", action: "allow", scope: "global", enabled: true }
  - { id: 2, iso_code: "CA", action: "allow", scope: "global", enabled: true }
"#,
    );
    fx.engine.load_geo_rules(&path);

    // Both listed countries pass — proves the rows became ONE AllowOnly rule
    // (per-row rules would each block the other listed country).
    let mut us = geo_ctx("US", "United States");
    assert!(fx.engine.geo_check().check(&mut us).is_none(), "US must be allowed");
    let mut ca = geo_ctx("CA", "Canada");
    assert!(fx.engine.geo_check().check(&mut ca).is_none(), "CA must be allowed");

    let mut kp = geo_ctx("KP", "North Korea");
    assert!(
        fx.engine.geo_check().check(&mut kp).is_some(),
        "country outside the allow list must be blocked"
    );
}
