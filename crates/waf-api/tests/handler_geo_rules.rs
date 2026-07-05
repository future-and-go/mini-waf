// Integration tests for /api/geoip/rules CRUD ↔ engine-loader contract and
// /api/geoip/lookup. The file the API writes must parse into the Block rule
// the engine enforces — that locks the API-writes/engine-reads path agreement.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::doc_markdown
)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server_with_main_config, url_for};
use serde_json::json;
use waf_engine::checks::{GeoRuleMode, parse_geo_rules};

#[tokio::test(flavor = "multi_thread")]
async fn created_rule_persists_to_file_the_engine_loader_parses() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let main_cfg = dir.path().join("config/waf.yaml");
    let s = start_test_server_with_main_config(main_cfg.to_str().unwrap()).await;

    // Create a block rule (lowercase iso — API must uppercase it).
    let created: serde_json::Value = client()
        .post(url_for(s.addr, "/api/geoip/rules"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "iso_code": "kp", "country_name": "North Korea" }))
        .send()
        .await
        .expect("create send")
        .json()
        .await
        .expect("create json");
    assert_eq!(created["success"], true);
    assert_eq!(created["data"]["iso_code"], "KP");
    assert_eq!(created["data"]["action"], "block");
    assert_eq!(created["data"]["enabled"], true);

    // GET confirms persistence through the handler.
    let listed: serde_json::Value = client()
        .get(url_for(s.addr, "/api/geoip/rules"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("list send")
        .json()
        .await
        .expect("list json");
    assert_eq!(listed["total"], 1);
    assert_eq!(listed["data"][0]["iso_code"], "KP");

    // The file the API wrote must be at the path the engine watches and must
    // parse into the enforced Block rule.
    let rules_file = dir.path().join("configs/geo-rules.yaml");
    assert!(rules_file.exists(), "API must persist to configs/geo-rules.yaml");
    let map = parse_geo_rules(&rules_file).expect("engine loader parses API file");
    let rules = map.get("*").expect("global host rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].mode, GeoRuleMode::Block);
    assert!(rules[0].iso_codes.contains("KP"));
}

#[tokio::test(flavor = "multi_thread")]
async fn deleted_rule_leaves_file_that_parses_empty() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let main_cfg = dir.path().join("config/waf.yaml");
    let s = start_test_server_with_main_config(main_cfg.to_str().unwrap()).await;

    let created: serde_json::Value = client()
        .post(url_for(s.addr, "/api/geoip/rules"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "iso_code": "IR" }))
        .send()
        .await
        .expect("create send")
        .json()
        .await
        .expect("create json");
    let id = created["data"]["id"].as_i64().expect("rule id");

    let del = client()
        .delete(url_for(s.addr, &format!("/api/geoip/rules/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("delete send");
    assert_eq!(del.status(), 200);

    let rules_file = dir.path().join("configs/geo-rules.yaml");
    let map = parse_geo_rules(&rules_file).expect("engine loader parses API file");
    assert!(map.is_empty(), "deleted rule must leave no enforceable rules");
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_returns_stub_when_no_geoip_database() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let main_cfg = dir.path().join("config/waf.yaml");
    let s = start_test_server_with_main_config(main_cfg.to_str().unwrap()).await;

    let body: serde_json::Value = client()
        .post(url_for(s.addr, "/api/geoip/lookup"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "ip": "8.8.8.8" }))
        .send()
        .await
        .expect("lookup send")
        .json()
        .await
        .expect("lookup json");
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["ip"], "8.8.8.8");
    assert_eq!(body["data"]["iso_code"], "XX", "no xdb loaded → stub fallback");
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_rejects_invalid_ip() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let main_cfg = dir.path().join("config/waf.yaml");
    let s = start_test_server_with_main_config(main_cfg.to_str().unwrap()).await;

    let resp = client()
        .post(url_for(s.addr, "/api/geoip/lookup"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "ip": "not-an-ip" }))
        .send()
        .await
        .expect("lookup send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn fail_closed_round_trips_through_create_and_patch() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let main_cfg = dir.path().join("config/waf.yaml");
    let s = start_test_server_with_main_config(main_cfg.to_str().unwrap()).await;

    let created: serde_json::Value = client()
        .post(url_for(s.addr, "/api/geoip/rules"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "iso_code": "US", "action": "allow", "fail_closed": true }))
        .send()
        .await
        .expect("create send")
        .json()
        .await
        .expect("create json");
    assert_eq!(created["data"]["fail_closed"], true);
    let id = created["data"]["id"].as_i64().expect("rule id");

    let listed: serde_json::Value = client()
        .get(url_for(s.addr, "/api/geoip/rules"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("list send")
        .json()
        .await
        .expect("list json");
    assert_eq!(listed["data"][0]["fail_closed"], true);

    // The persisted file must map to a fail-closed AllowOnly rule.
    let rules_file = dir.path().join("configs/geo-rules.yaml");
    let map = parse_geo_rules(&rules_file).expect("engine loader parses API file");
    let rules = map.get("*").expect("global host rules");
    assert_eq!(rules[0].mode, GeoRuleMode::AllowOnly);
    assert!(rules[0].fail_closed);

    // PATCH toggles it back to fail-open.
    let patched: serde_json::Value = client()
        .patch(url_for(s.addr, &format!("/api/geoip/rules/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "fail_closed": false }))
        .send()
        .await
        .expect("patch send")
        .json()
        .await
        .expect("patch json");
    assert_eq!(patched["data"]["fail_closed"], false);

    let map = parse_geo_rules(&rules_file).expect("engine loader parses patched file");
    let rules = map.get("*").expect("global host rules");
    assert!(!rules[0].fail_closed);
}

/// Actions the engine has no geo implementation for ("challenge", "log")
/// must be rejected with 400 by create and patch — never persisted and
/// echoed back as honored while `parse_geo_rules` coerces them to Block.
#[tokio::test(flavor = "multi_thread")]
async fn unsupported_action_is_rejected_not_silently_coerced_to_block() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let main_cfg = dir.path().join("config/waf.yaml");
    let s = start_test_server_with_main_config(main_cfg.to_str().unwrap()).await;

    for bad in ["challenge", "log"] {
        let resp = client()
            .post(url_for(s.addr, "/api/geoip/rules"))
            .bearer_auth(&s.admin_token)
            .json(&json!({ "iso_code": "US", "action": bad }))
            .send()
            .await
            .expect("create send");
        assert_eq!(resp.status(), 400, "create with action {bad:?} must be rejected");
    }

    // Nothing was persisted by the rejected creates.
    let rules_file = dir.path().join("configs/geo-rules.yaml");
    assert!(
        parse_geo_rules(&rules_file).map_or(true, |m| m.is_empty()),
        "rejected creates must not write rules"
    );

    // A valid rule can be created, but cannot be patched to an unsupported action.
    let created: serde_json::Value = client()
        .post(url_for(s.addr, "/api/geoip/rules"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "iso_code": "US", "action": "allow" }))
        .send()
        .await
        .expect("create send")
        .json()
        .await
        .expect("create json");
    let id = created["data"]["id"].as_i64().expect("rule id");

    let resp = client()
        .patch(url_for(s.addr, &format!("/api/geoip/rules/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "action": "challenge" }))
        .send()
        .await
        .expect("patch send");
    assert_eq!(resp.status(), 400, "patch to an unsupported action must be rejected");

    // The stored rule still parses as the allow rule the engine enforces.
    let map = parse_geo_rules(&rules_file).expect("engine loader parses API file");
    let rules = map.get("*").expect("global host rules");
    assert_eq!(rules[0].mode, GeoRuleMode::AllowOnly);
}
