// Integration tests for /__waf_control/* interop endpoints.
//
// Tests are grouped into a few large test functions to minimize
// testcontainer starts (each `start_test_server()` boots a full
// Postgres container). Within each group, assertions are sequential
// against a single shared server.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::undocumented_unsafe_blocks,
    clippy::doc_markdown,
    clippy::redundant_clone
)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server, url_for};
use reqwest::StatusCode;
use serde_json::{Value, json};

const SECRET_HEADER: &str = "x-benchmark-secret";
const VALID_SECRET: &str = "waf-hackathon-2026-ctrl";
const WRONG_SECRET: &str = "wrong-secret";

// ── Helpers ──────────────────────────────────────────────────────────────────

fn ctrl_url(s: &common::TestServer, path: &str) -> String {
    url_for(s.addr, &format!("/__waf_control{path}"))
}

async fn get_capabilities(s: &common::TestServer) -> Value {
    client()
        .get(ctrl_url(s, "/capabilities"))
        .header(SECRET_HEADER, VALID_SECRET)
        .send()
        .await
        .expect("capabilities send")
        .json()
        .await
        .expect("capabilities json")
}

async fn post_set_profile(s: &common::TestServer, body: Value) -> (StatusCode, Value) {
    let resp = client()
        .post(ctrl_url(s, "/set_profile"))
        .header(SECRET_HEADER, VALID_SECRET)
        .json(&body)
        .send()
        .await
        .expect("set_profile send");
    let status = resp.status();
    let body: Value = resp.json().await.expect("set_profile json");
    (status, body)
}

async fn post_reset(s: &common::TestServer) -> Value {
    client()
        .post(ctrl_url(s, "/reset_state"))
        .header(SECRET_HEADER, VALID_SECRET)
        .send()
        .await
        .expect("reset send")
        .json()
        .await
        .expect("reset json")
}

async fn post_flush(s: &common::TestServer) -> Value {
    client()
        .post(ctrl_url(s, "/flush_cache"))
        .header(SECRET_HEADER, VALID_SECRET)
        .send()
        .await
        .expect("flush send")
        .json()
        .await
        .expect("flush json")
}

// ── Auth: 403 without/wrong secret, success with correct secret ─────────────

#[tokio::test(flavor = "multi_thread")]
async fn auth_enforcement() {
    let s = start_test_server().await;

    // All 4 endpoints return 403 without X-Benchmark-Secret header
    let endpoints = vec![
        ("GET", "/__waf_control/capabilities"),
        ("POST", "/__waf_control/reset_state"),
        ("POST", "/__waf_control/set_profile"),
        ("POST", "/__waf_control/flush_cache"),
    ];
    for (method, path) in &endpoints {
        let url = url_for(s.addr, path);
        let resp = match *method {
            "GET" => client().get(&url).send().await.expect("send"),
            _ => client().post(&url).json(&json!({})).send().await.expect("send"),
        };
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} should be 403 without secret"
        );
        let body: Value = resp.json().await.expect("json");
        assert_eq!(body["ok"], false);
    }

    // All 4 endpoints return 403 with wrong secret
    for (method, path) in &endpoints {
        let url = url_for(s.addr, path);
        let resp = match *method {
            "GET" => client()
                .get(&url)
                .header(SECRET_HEADER, WRONG_SECRET)
                .send()
                .await
                .expect("send"),
            _ => client()
                .post(&url)
                .header(SECRET_HEADER, WRONG_SECRET)
                .json(&json!({}))
                .send()
                .await
                .expect("send"),
        };
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} should be 403 with wrong secret"
        );
    }

    // All 4 endpoints succeed (non-403) with correct secret
    let resp = client()
        .get(ctrl_url(&s, "/capabilities"))
        .header(SECRET_HEADER, VALID_SECRET)
        .send()
        .await
        .expect("send");
    assert_ne!(resp.status(), StatusCode::FORBIDDEN, "capabilities should not be 403");

    let resp = client()
        .post(ctrl_url(&s, "/reset_state"))
        .header(SECRET_HEADER, VALID_SECRET)
        .send()
        .await
        .expect("send");
    assert_ne!(resp.status(), StatusCode::FORBIDDEN, "reset_state should not be 403");

    let resp = client()
        .post(ctrl_url(&s, "/set_profile"))
        .header(SECRET_HEADER, VALID_SECRET)
        .json(&json!({"scope": "all", "mode": "enforce"}))
        .send()
        .await
        .expect("send");
    assert_ne!(resp.status(), StatusCode::FORBIDDEN, "set_profile should not be 403");

    let resp = client()
        .post(ctrl_url(&s, "/flush_cache"))
        .header(SECRET_HEADER, VALID_SECRET)
        .send()
        .await
        .expect("send");
    assert_ne!(resp.status(), StatusCode::FORBIDDEN, "flush_cache should not be 403");
}

// ── Capabilities: shape, features, fields, default state ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn capabilities_response_shape_and_defaults() {
    let s = start_test_server().await;
    let body = get_capabilities(&s).await;

    // ok, features, active present
    assert_eq!(body["ok"], true);
    assert!(body["features"].is_object(), "features must be object");
    assert!(body["active"].is_object(), "active must be object");

    // Core features present
    let features = &body["features"];
    let expected = [
        "access_control",
        "injection_control",
        "rate_limiting",
        "bot_detection",
        "owasp_rules",
        "ddos_protection",
        "geo_protection",
        "data_protection",
        "reputation",
        "custom_rules",
    ];
    for feat in expected {
        assert!(features[feat].is_object(), "feature '{feat}' must be present");
    }

    // Each feature has supported, toggleable, policies fields
    let ic = &features["injection_control"];
    assert!(ic["supported"].is_boolean(), "supported must be bool");
    assert!(ic["toggleable"].is_boolean(), "toggleable must be bool");
    assert!(ic["policies"].is_array(), "policies must be array");
    assert_eq!(ic["supported"], true);
    assert_eq!(ic["toggleable"], true);

    let policies: Vec<&str> = ic["policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(policies.contains(&"sqli"), "should have sqli");
    assert!(policies.contains(&"xss"), "should have xss");

    // Default active state: enforce with empty overrides
    let active = &body["active"];
    assert_eq!(active["default_mode"], "enforce");
    let overrides = active["overrides"].as_object().unwrap();
    assert!(overrides.is_empty(), "default should have no overrides");
}

// ── Set Profile: all scopes, validation errors, echo ────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn set_profile_all_and_validation() {
    let s = start_test_server().await;

    // scope "all" + mode "log_only": sets default, clears overrides
    let (status, body) = post_set_profile(&s, json!({"scope": "all", "mode": "log_only"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(body["action"], "set_profile");
    assert_eq!(body["applied"]["scope"], "all");
    assert_eq!(body["applied"]["mode"], "log_only");
    assert_eq!(body["active"]["default_mode"], "log_only");
    let overrides = body["active"]["overrides"].as_object().unwrap();
    assert!(overrides.is_empty(), "scope=all clears overrides");
    assert!(body["ts_ms"].is_i64(), "ts_ms must be integer");

    // scope "all" + mode "enforce" clears overrides even after feature-level set
    post_set_profile(
        &s,
        json!({
            "scope": "features", "mode": "log_only", "features": ["injection_control"]
        }),
    )
    .await;
    let (status, body) = post_set_profile(&s, json!({"scope": "all", "mode": "enforce"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active"]["default_mode"], "enforce");
    assert!(body["active"]["overrides"].as_object().unwrap().is_empty());

    // Invalid mode returns 400
    let (status, body) = post_set_profile(&s, json!({"scope": "all", "mode": "invalid_mode"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["ok"], false);
    assert!(body["error"].as_str().unwrap().contains("invalid mode"));

    // Invalid scope returns 400
    let (status, body) = post_set_profile(&s, json!({"scope": "invalid_scope", "mode": "enforce"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["ok"], false);
    assert!(body["error"].as_str().unwrap().contains("invalid scope"));

    // Features scope missing features array returns 400
    let (status, body) = post_set_profile(&s, json!({"scope": "features", "mode": "log_only"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["ok"], false);

    // Policies scope missing feature returns 400
    let (status, body) = post_set_profile(
        &s,
        json!({
            "scope": "policies", "mode": "log_only", "policies": ["sqli"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["ok"], false);

    // Policies scope missing policies returns 400
    let (status, body) = post_set_profile(
        &s,
        json!({
            "scope": "policies", "mode": "log_only", "feature": "injection_control"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["ok"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn set_profile_features_and_policies() {
    let s = start_test_server().await;

    // scope "features" applies listed features as overrides
    let (status, body) = post_set_profile(
        &s,
        json!({
            "scope": "features", "mode": "log_only",
            "features": ["injection_control", "bot_detection"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(body["applied"]["scope"], "features");
    let overrides = body["active"]["overrides"].as_object().unwrap();
    assert_eq!(overrides["injection_control"], "log_only");
    assert_eq!(overrides["bot_detection"], "log_only");
    assert_eq!(body["active"]["default_mode"], "enforce", "default unchanged");

    // Applied field echoes request
    assert_eq!(body["applied"]["mode"], "log_only");
    assert!(
        body["applied"]["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap() == "injection_control")
    );

    // Reset for clean slate
    post_reset(&s).await;

    // scope "policies" applies policies under a feature
    let (status, body) = post_set_profile(
        &s,
        json!({
            "scope": "policies", "mode": "log_only",
            "feature": "injection_control", "policies": ["sqli", "xss"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(body["applied"]["scope"], "policies");
    assert_eq!(body["applied"]["feature"], "injection_control");
    let overrides = body["active"]["overrides"].as_object().unwrap();
    assert_eq!(overrides["injection_control.sqli"], "log_only");
    assert_eq!(overrides["injection_control.xss"], "log_only");

    // Reset for clean slate
    post_reset(&s).await;

    // Unsupported features reported in unsupported[] array (still ok: true)
    let (status, body) = post_set_profile(
        &s,
        json!({
            "scope": "features", "mode": "log_only",
            "features": ["injection_control", "does_not_exist"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert!(
        body["unsupported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap() == "does_not_exist")
    );
}

// ── Reset State ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn reset_state_behavior() {
    let s = start_test_server().await;

    // Returns expected fields
    let body = post_reset(&s).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["action"], "reset_state");
    assert_eq!(body["audit_log_preserved"], true);
    assert!(body["ts_ms"].is_i64(), "ts_ms must be integer");

    // Set overrides, then reset clears them
    post_set_profile(
        &s,
        json!({
            "scope": "features", "mode": "log_only",
            "features": ["injection_control", "bot_detection"]
        }),
    )
    .await;
    let caps_before = get_capabilities(&s).await;
    assert!(
        !caps_before["active"]["overrides"].as_object().unwrap().is_empty(),
        "overrides should be set before reset"
    );

    post_reset(&s).await;
    let caps_after = get_capabilities(&s).await;
    assert_eq!(caps_after["active"]["default_mode"], "enforce");
    assert!(caps_after["active"]["overrides"].as_object().unwrap().is_empty());

    // Idempotent: double-reset returns same structure
    let r1 = post_reset(&s).await;
    let r2 = post_reset(&s).await;
    assert_eq!(r1["ok"], true);
    assert_eq!(r2["ok"], true);
    assert_eq!(r1["action"], "reset_state");
    assert_eq!(r2["action"], "reset_state");
}

// ── Flush Cache ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn flush_cache_behavior() {
    let s = start_test_server().await;

    // Returns expected fields
    let body = post_flush(&s).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["action"], "flush_cache");
    assert!(body["ts_ms"].is_i64(), "ts_ms must be integer");

    // Idempotent: double-flush returns same structure
    let r1 = post_flush(&s).await;
    let r2 = post_flush(&s).await;
    assert_eq!(r1["ok"], true);
    assert_eq!(r2["ok"], true);
    assert_eq!(r1["action"], "flush_cache");
    assert_eq!(r2["action"], "flush_cache");
}

// ── Concurrent: reads/writes don't panic or corrupt ─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_profile_and_capabilities() {
    let s = start_test_server().await;

    let mut handles = vec![];
    for i in 0..8 {
        let addr = s.addr;
        handles.push(tokio::spawn(async move {
            let c = client();
            let url_caps = url_for(addr, "/__waf_control/capabilities");
            let url_prof = url_for(addr, "/__waf_control/set_profile");
            if i % 2 == 0 {
                let resp = c
                    .post(&url_prof)
                    .header(SECRET_HEADER, VALID_SECRET)
                    .json(&json!({"scope": "all", "mode": "log_only"}))
                    .send()
                    .await
                    .expect("set_profile send");
                assert_eq!(resp.status(), StatusCode::OK);
            } else {
                let resp = c
                    .get(&url_caps)
                    .header(SECRET_HEADER, VALID_SECRET)
                    .send()
                    .await
                    .expect("capabilities send");
                assert_eq!(resp.status(), StatusCode::OK);
                let body: Value = resp.json().await.expect("json");
                assert_eq!(body["ok"], true);
            }
        }));
    }
    for h in handles {
        h.await.expect("task join");
    }
}

// ── Reset preserves static config ───────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn reset_preserves_static_config() {
    let s = start_test_server().await;

    let before = get_capabilities(&s).await;
    let features_before = before["features"].as_object().expect("features obj");
    let feature_count_before = features_before.len();

    post_reset(&s).await;

    let after = get_capabilities(&s).await;
    let features_after = after["features"].as_object().expect("features obj");
    assert_eq!(
        features_after.len(),
        feature_count_before,
        "feature catalog size unchanged after reset"
    );
    for key in features_before.keys() {
        assert!(
            features_after.contains_key(key),
            "feature '{key}' must survive reset"
        );
    }
}

// ── Lifecycle: full cycle, toggle-reset-toggle, coexisting overrides, timestamps

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_full_cycle() {
    let s = start_test_server().await;

    // 1. Default state: enforce, no overrides
    let caps = get_capabilities(&s).await;
    assert_eq!(caps["active"]["default_mode"], "enforce");
    assert!(caps["active"]["overrides"].as_object().unwrap().is_empty());

    // 2. Set injection_control to log_only
    let (status, _) = post_set_profile(
        &s,
        json!({
            "scope": "features", "mode": "log_only", "features": ["injection_control"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 3. Verify capabilities reflect the change
    let caps = get_capabilities(&s).await;
    assert_eq!(caps["active"]["overrides"]["injection_control"], "log_only");
    assert_eq!(caps["active"]["default_mode"], "enforce");

    // 4. Reset
    let reset_body = post_reset(&s).await;
    assert_eq!(reset_body["ok"], true);

    // 5. Verify clean slate
    let caps = get_capabilities(&s).await;
    assert_eq!(caps["active"]["default_mode"], "enforce");
    assert!(caps["active"]["overrides"].as_object().unwrap().is_empty());

    // 6. Toggle-reset-toggle idempotent cycle
    post_set_profile(&s, json!({"scope": "all", "mode": "log_only"})).await;
    let caps = get_capabilities(&s).await;
    assert_eq!(caps["active"]["default_mode"], "log_only");

    post_reset(&s).await;
    let caps = get_capabilities(&s).await;
    assert_eq!(caps["active"]["default_mode"], "enforce");

    post_set_profile(&s, json!({"scope": "all", "mode": "log_only"})).await;
    let caps = get_capabilities(&s).await;
    assert_eq!(caps["active"]["default_mode"], "log_only");

    post_reset(&s).await;
    let caps = get_capabilities(&s).await;
    assert_eq!(caps["active"]["default_mode"], "enforce");

    // 7. Policy-level and feature-level overrides coexist
    post_set_profile(
        &s,
        json!({
            "scope": "features", "mode": "log_only", "features": ["bot_detection"]
        }),
    )
    .await;
    post_set_profile(
        &s,
        json!({
            "scope": "policies", "mode": "log_only",
            "feature": "injection_control", "policies": ["sqli"]
        }),
    )
    .await;
    let caps = get_capabilities(&s).await;
    let overrides = caps["active"]["overrides"].as_object().unwrap();
    assert_eq!(overrides["bot_detection"], "log_only");
    assert_eq!(overrides["injection_control.sqli"], "log_only");
    assert_eq!(caps["active"]["default_mode"], "enforce");

    // 8. Timestamps monotonically increasing
    post_reset(&s).await;
    let (_, body1) = post_set_profile(&s, json!({"scope": "all", "mode": "log_only"})).await;
    let ts1 = body1["ts_ms"].as_i64().unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let body2 = post_reset(&s).await;
    let ts2 = body2["ts_ms"].as_i64().unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let body3 = post_flush(&s).await;
    let ts3 = body3["ts_ms"].as_i64().unwrap();

    assert!(ts1 > 0, "ts1 should be positive");
    assert!(ts2 >= ts1, "ts2 should be >= ts1");
    assert!(ts3 >= ts2, "ts3 should be >= ts2");
}
