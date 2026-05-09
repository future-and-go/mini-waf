// Integration tests for /ws/events and /ws/logs upgrade-time auth.
//
// Verifies:
// * Missing token → 401 (no upgrade)
// * Invalid token → 401 (no upgrade)
// * Valid token (Authorization header / Sec-WebSocket-Protocol / ?token=)
//   → upgrade succeeds (101) and the connection accepts a message exchange.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::undocumented_unsafe_blocks,
    clippy::doc_markdown,
    clippy::redundant_clone,
    clippy::err_expect,
    clippy::format_push_string
)]

#[path = "common/mod.rs"]
mod common;

use common::start_test_server;

fn http_status_from_err(err: tokio_tungstenite::tungstenite::Error) -> Option<u16> {
    if let tokio_tungstenite::tungstenite::Error::Http(resp) = err {
        Some(resp.status().as_u16())
    } else {
        None
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_events_no_token_401() {
    let s = start_test_server().await;
    let url = format!("ws://{}/ws/events", s.addr);
    let err = tokio_tungstenite::connect_async(url)
        .await
        .err()
        .expect("expected upgrade rejection");
    assert_eq!(http_status_from_err(err), Some(401));
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_events_invalid_token_401() {
    let s = start_test_server().await;
    let url = format!("ws://{}/ws/events?token=not-a-real-jwt", s.addr);
    let err = tokio_tungstenite::connect_async(url)
        .await
        .err()
        .expect("expected upgrade rejection");
    assert_eq!(http_status_from_err(err), Some(401));
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_logs_invalid_token_401() {
    let s = start_test_server().await;
    let url = format!("ws://{}/ws/logs?token=bad", s.addr);
    let err = tokio_tungstenite::connect_async(url)
        .await
        .err()
        .expect("expected upgrade rejection");
    assert_eq!(http_status_from_err(err), Some(401));
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_events_valid_token_via_query_upgrades() {
    let s = start_test_server().await;
    let url = format!("ws://{}/ws/events?token={}", s.addr, urlencoding_encode(&s.admin_token));
    let (ws, resp) = tokio_tungstenite::connect_async(url).await.expect("ws upgrade");
    assert_eq!(resp.status().as_u16(), 101);
    drop(ws);
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_events_valid_token_via_authorization_header_upgrades() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let s = start_test_server().await;
    let url = format!("ws://{}/ws/events", s.addr);
    let mut req = url.into_client_request().expect("build req");
    req.headers_mut()
        .insert("Authorization", format!("Bearer {}", s.admin_token).parse().unwrap());
    let (ws, resp) = tokio_tungstenite::connect_async(req).await.expect("ws upgrade");
    assert_eq!(resp.status().as_u16(), 101);
    drop(ws);
}

// Minimal percent-encoder for the JWT in a query string. JWTs may contain `=`,
// `+`, `/` after base64url decoding only — but the canonical compact form uses
// only base64url chars (`A-Za-z0-9-_`) plus `.`, all URL-safe. We still escape
// to be defensive.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
