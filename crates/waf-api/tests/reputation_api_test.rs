//! Integration tests for the IP reputation editor API.

#![allow(
    dead_code,
    unsafe_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::doc_markdown,
    clippy::undocumented_unsafe_blocks
)]

mod common;

use chrono::{Duration, Utc};
use common::{TestServer, client, issue_viewer_token, start_test_server, url_for};
use serde_json::json;

fn valid_body() -> serde_json::Value {
    json!({
        "ip": "203.0.113.42",
        "score": -75,
        "source": "manual",
        "expires_at": (Utc::now() + Duration::hours(24)).to_rfc3339(),
        "notes": "abuse report"
    })
}

async fn upsert(s: &TestServer, body: &serde_json::Value) -> serde_json::Value {
    let resp = client()
        .post(url_for(s.addr, "/api/reputation"))
        .bearer_auth(&s.admin_token)
        .json(body)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200, "POST /api/reputation expected 200");
    resp.json().await.expect("json")
}

#[tokio::test(flavor = "multi_thread")]
async fn list_returns_empty_initially() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/reputation"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["total"], 0);
    assert_eq!(body["data"], json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn upsert_then_list_returns_entry() {
    let s = start_test_server().await;
    let created = upsert(&s, &valid_body()).await;
    let id = created["data"]["id"].as_i64().expect("id");
    assert!(id > 0);
    assert_eq!(created["data"]["ip"], "203.0.113.42");
    assert_eq!(created["data"]["score"], -75);

    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/reputation"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["total"], 1);
    assert_eq!(body["data"][0]["ip"], "203.0.113.42");
}

#[tokio::test(flavor = "multi_thread")]
async fn upsert_same_ip_and_source_collapses_via_unique() {
    let s = start_test_server().await;
    let first = upsert(&s, &valid_body()).await;
    let first_id = first["data"]["id"].as_i64().expect("id");

    let mut second = valid_body();
    second["score"] = json!(50); // change score, keep ip+source
    let second_resp = upsert(&s, &second).await;
    assert_eq!(
        second_resp["data"]["id"].as_i64(),
        Some(first_id),
        "UNIQUE must collapse"
    );
    assert_eq!(second_resp["data"]["score"], 50);

    let listing: serde_json::Value = client()
        .get(url_for(s.addr, "/api/reputation"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(listing["total"], 1, "must still be one row after UPSERT");
}

/// Every API-boundary rejection case folded into one test so the harness
/// spins up Postgres once. Each `(label, mutation)` covers one validation
/// path; if any case slips past the 400 we get the label in the panic.
#[tokio::test(flavor = "multi_thread")]
async fn upsert_rejects_each_boundary_violation() {
    let s = start_test_server().await;
    let past = json!((Utc::now() - Duration::hours(1)).to_rfc3339());
    #[allow(clippy::type_complexity)]
    let cases: &[(&str, &dyn Fn(&mut serde_json::Value))] = &[
        ("garbage ip", &|b| b["ip"] = json!("not-an-ip")),
        ("unspecified v4 ip", &|b| b["ip"] = json!("0.0.0.0")),
        ("unspecified v6 ip", &|b| b["ip"] = json!("::")),
        ("score above max", &|b| b["score"] = json!(150)),
        ("score below min", &|b| b["score"] = json!(-150)),
        ("unknown source", &|b| b["source"] = json!("typo_source")),
        ("expiry in past", &|b| b["expires_at"] = past.clone()),
    ];
    for (label, mutate) in cases {
        let mut bad = valid_body();
        mutate(&mut bad);
        let resp = client()
            .post(url_for(s.addr, "/api/reputation"))
            .bearer_auth(&s.admin_token)
            .json(&bad)
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status(), 400, "{label}: expected 400, got {}", resp.status());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn upsert_requires_admin_role() {
    let s = start_test_server().await;
    let viewer = issue_viewer_token(&s);
    let resp = client()
        .post(url_for(s.addr, "/api/reputation"))
        .bearer_auth(&viewer)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn update_unknown_id_returns_404() {
    let s = start_test_server().await;
    let resp = client()
        .put(url_for(s.addr, "/api/reputation/99999"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "score": 25 }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn update_applies_partial_patch() {
    let s = start_test_server().await;
    let created = upsert(&s, &valid_body()).await;
    let id = created["data"]["id"].as_i64().expect("id");

    let resp = client()
        .put(url_for(s.addr, &format!("/api/reputation/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "score": 10, "notes": "updated" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["data"]["score"], 10);
    assert_eq!(body["data"]["notes"], "updated");
    // Untouched field stays.
    assert_eq!(body["data"]["source"], "manual");
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_removes_entry_and_repeat_is_404() {
    let s = start_test_server().await;
    let created = upsert(&s, &valid_body()).await;
    let id = created["data"]["id"].as_i64().expect("id");

    let first = client()
        .delete(url_for(s.addr, &format!("/api/reputation/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(first.status(), 200);

    let again = client()
        .delete(url_for(s.addr, &format!("/api/reputation/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(again.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_requires_admin_role() {
    let s = start_test_server().await;
    let created = upsert(&s, &valid_body()).await;
    let id = created["data"]["id"].as_i64().expect("id");
    let viewer = issue_viewer_token(&s);

    let resp = client()
        .delete(url_for(s.addr, &format!("/api/reputation/{id}")))
        .bearer_auth(&viewer)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_filters_by_source_and_score_range() {
    let s = start_test_server().await;
    let body_a = valid_body();
    let _ = upsert(&s, &body_a).await;

    let mut body_b = valid_body();
    body_b["ip"] = json!("198.51.100.1");
    body_b["source"] = json!("crowdsec");
    body_b["score"] = json!(80);
    let _ = upsert(&s, &body_b).await;

    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/reputation?source=crowdsec&min_score=50"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["total"], 1);
    assert_eq!(body["data"][0]["ip"], "198.51.100.1");
}
