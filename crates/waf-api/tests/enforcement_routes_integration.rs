// Integration tests for the JWT-guarded /api/enforcement/* routes.
//
// These routes mirror the secret-gated /__waf_control/* control plane. The
// tests assert: (1) byte-identical response shapes versus the secret plane,
// (2) writes hit the same mode_registry, (3) no JWT → 401, and (4) the routes
// do NOT accept X-Benchmark-Secret in place of a Bearer JWT.

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

fn enf_url(s: &common::TestServer, path: &str) -> String {
    url_for(s.addr, &format!("/api/enforcement{path}"))
}

fn ctrl_url(s: &common::TestServer, path: &str) -> String {
    url_for(s.addr, &format!("/__waf_control{path}"))
}

/// Strip the `ts_ms` field so two responses can be compared for shape equality
/// across calls (the timestamp legitimately differs between requests).
fn without_ts(mut v: Value) -> Value {
    if let Some(obj) = v.as_object_mut() {
        obj.remove("ts_ms");
    }
    v
}

#[tokio::test(flavor = "multi_thread")]
async fn enforcement_mirrors_control_plane() {
    let s = start_test_server().await;

    // Clean slate so JWT and secret snapshots compare equal.
    client()
        .post(ctrl_url(&s, "/reset_state"))
        .header(SECRET_HEADER, VALID_SECRET)
        .send()
        .await
        .expect("reset send");

    // 1. JWT capabilities equals secret-plane capabilities byte-for-byte
    //    (capabilities carries no timestamp).
    let jwt_caps: Value = client()
        .get(enf_url(&s, "/capabilities"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("jwt caps send")
        .json()
        .await
        .expect("jwt caps json");
    let secret_caps: Value = client()
        .get(ctrl_url(&s, "/capabilities"))
        .header(SECRET_HEADER, VALID_SECRET)
        .send()
        .await
        .expect("secret caps send")
        .json()
        .await
        .expect("secret caps json");
    assert_eq!(jwt_caps, secret_caps, "JWT and secret capabilities must be identical");
    assert_eq!(jwt_caps["ok"], true);
    assert_eq!(jwt_caps["active"]["default_mode"], "enforce");

    // 2. JWT set-profile applies to the shared mode_registry.
    let resp = client()
        .post(enf_url(&s, "/set-profile"))
        .bearer_auth(&s.admin_token)
        .json(&json!({"scope": "all", "mode": "log_only"}))
        .send()
        .await
        .expect("set-profile send");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("set-profile json");
    assert_eq!(body["ok"], true);
    assert_eq!(body["action"], "set_profile");
    assert_eq!(body["applied"], json!({"scope": "all", "mode": "log_only"}));
    assert_eq!(body["active"]["default_mode"], "log_only");
    assert_eq!(body["unsupported"], json!([]));
    assert!(body["ts_ms"].as_i64().unwrap() > 0);

    // 3. The write is visible through the secret plane → same registry instance.
    let secret_caps_after: Value = client()
        .get(ctrl_url(&s, "/capabilities"))
        .header(SECRET_HEADER, VALID_SECRET)
        .send()
        .await
        .expect("secret caps send")
        .json()
        .await
        .expect("secret caps json");
    assert_eq!(secret_caps_after["active"]["default_mode"], "log_only");

    // 4. reset-state and flush-cache shapes.
    let reset: Value = client()
        .post(enf_url(&s, "/reset-state"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("reset send")
        .json()
        .await
        .expect("reset json");
    assert_eq!(
        without_ts(reset),
        json!({"ok": true, "action": "reset_state", "audit_log_preserved": true})
    );

    let flush: Value = client()
        .post(enf_url(&s, "/flush-cache"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("flush send")
        .json()
        .await
        .expect("flush json");
    assert_eq!(without_ts(flush), json!({"ok": true, "action": "flush_cache"}));

    // 5. Invalid mode → 400 with the same error contract as the secret plane.
    let bad = client()
        .post(enf_url(&s, "/set-profile"))
        .bearer_auth(&s.admin_token)
        .json(&json!({"scope": "all", "mode": "bogus"}))
        .send()
        .await
        .expect("bad send");
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let bad_body: Value = bad.json().await.expect("bad json");
    assert_eq!(bad_body["ok"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn enforcement_requires_jwt_and_rejects_secret() {
    let s = start_test_server().await;

    let routes = [
        ("GET", "/capabilities"),
        ("POST", "/set-profile"),
        ("POST", "/reset-state"),
        ("POST", "/flush-cache"),
    ];

    for (method, path) in routes {
        // No credentials → 401.
        let req = if method == "GET" {
            client().get(enf_url(&s, path))
        } else {
            client().post(enf_url(&s, path)).json(&json!({}))
        };
        let resp = req.send().await.expect("no-auth send");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path} must reject without JWT"
        );

        // X-Benchmark-Secret without a Bearer JWT must NOT be accepted.
        let req = if method == "GET" {
            client().get(enf_url(&s, path))
        } else {
            client().post(enf_url(&s, path)).json(&json!({}))
        };
        let resp = req
            .header(SECRET_HEADER, VALID_SECRET)
            .send()
            .await
            .expect("secret-only send");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path} must not accept X-Benchmark-Secret"
        );
    }
}
