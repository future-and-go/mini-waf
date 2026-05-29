// Integration tests for the `protocol` field on tunnels endpoints.
// Covers: default-to-tcp on omission; closed-set accept for tcp/udp/ws/quic/http/grpc;
// 400 reject of an off-set value; persisted protocol surfaces in the list envelope;
// envelope ships both canonical `data`/`total` and deprecation alias `tunnels`.
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

use common::{client, start_test_server, url_for};

#[tokio::test(flavor = "multi_thread")]
async fn create_tunnel_defaults_protocol_to_tcp() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/tunnels"))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({
            "name": "t-default",
            "target_host": "127.0.0.1",
            "target_port": 8080,
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["protocol"], "tcp");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_tunnel_accepts_all_closed_set_members() {
    let s = start_test_server().await;
    for (i, p) in ["tcp", "udp", "ws", "quic", "http", "grpc"].iter().enumerate() {
        let offset = i64::try_from(i).expect("small loop index fits i64");
        let resp = client()
            .post(url_for(s.addr, "/api/tunnels"))
            .bearer_auth(&s.admin_token)
            .json(&serde_json::json!({
                "name": format!("t-{p}-{i}"),
                "target_host": "127.0.0.1",
                "target_port": 9000 + offset,
                "protocol": p,
            }))
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status(), 201, "protocol {p} should be accepted");
        let body: serde_json::Value = resp.json().await.expect("json");
        assert_eq!(body["protocol"], *p);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn create_tunnel_rejects_off_set_protocol_with_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/tunnels"))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({
            "name": "t-bad",
            "target_host": "127.0.0.1",
            "target_port": 8081,
            "protocol": "smtp",
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        400,
        "off-set protocol must be rejected at the API boundary"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn list_tunnels_envelope_carries_data_total_and_alias() {
    let s = start_test_server().await;

    // Seed one tunnel so the list is non-empty.
    let _ = client()
        .post(url_for(s.addr, "/api/tunnels"))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({
            "name": "t-list",
            "target_host": "127.0.0.1",
            "target_port": 9100,
            "protocol": "quic",
        }))
        .send()
        .await
        .expect("send");

    let resp = client()
        .get(url_for(s.addr, "/api/tunnels"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send list");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");

    assert_eq!(body["success"], true);
    let data = body["data"].as_array().expect("data array");
    assert!(!data.is_empty(), "seeded tunnel should appear");
    assert_eq!(body["total"], data.len());

    // Deprecation alias retained for one release.
    let alias = body["tunnels"].as_array().expect("tunnels alias array");
    assert_eq!(alias.len(), data.len());

    // Protocol round-trips on the listing.
    assert!(
        data.iter().any(|r| r["name"] == "t-list" && r["protocol"] == "quic"),
        "seeded protocol should surface in list"
    );
}
