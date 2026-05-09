//! Integration coverage for `protocol::detect_from_session`.
//!
//! Drives a Pingora `Session` via a `tokio_test::io::Mock` stream so we can
//! exercise the H1/H2/Websocket detection branches without a live socket.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods
)]

use pingora_proxy::Session;
use tokio_test::io::Builder;

use gateway::protocol::{Protocol, detect_from_session};

async fn session_for(req_bytes: &[u8]) -> Session {
    let mock = Builder::new().read(req_bytes).build();
    let mut session = Session::new_h1(Box::new(mock));
    let read = session.read_request().await.expect("read_request");
    assert!(read, "expected request to parse");
    session
}

#[tokio::test]
async fn detect_h1_plain_get() {
    let session = session_for(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert_eq!(detect_from_session(&session), Protocol::H1);
}

#[tokio::test]
async fn detect_websocket_upgrade_takes_precedence_over_h1() {
    // A WS handshake is just an HTTP/1.1 request with `Upgrade: websocket`.
    // `detect_from_session` must classify it as Websocket, not H1, so AC-22
    // counters bucket WS handshakes correctly.
    let req = b"GET /chat HTTP/1.1\r\n\
                Host: example.com\r\n\
                Connection: Upgrade\r\n\
                Upgrade: websocket\r\n\
                Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                Sec-WebSocket-Version: 13\r\n\r\n";
    let session = session_for(req).await;
    assert_eq!(detect_from_session(&session), Protocol::Websocket);
}

#[tokio::test]
async fn detect_websocket_is_case_insensitive() {
    // Per RFC 6455 §4.2.1 the `Upgrade` token is case-insensitive — the
    // `eq_ignore_ascii_case` branch must match `WebSocket`, `WEBSOCKET`, etc.
    let req = b"GET / HTTP/1.1\r\n\
                Host: example.com\r\n\
                Upgrade: WebSocket\r\n\
                Connection: Upgrade\r\n\r\n";
    let session = session_for(req).await;
    assert_eq!(detect_from_session(&session), Protocol::Websocket);
}

#[tokio::test]
async fn detect_h1_when_upgrade_header_is_not_websocket() {
    // `Upgrade: h2c` (clear-text H2 upgrade) must NOT be classified as
    // Websocket — it's plain H1 from the WAF's POV.
    let req = b"GET / HTTP/1.1\r\n\
                Host: example.com\r\n\
                Upgrade: h2c\r\n\
                Connection: Upgrade, HTTP2-Settings\r\n\
                HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n";
    let session = session_for(req).await;
    assert_eq!(detect_from_session(&session), Protocol::H1);
}
