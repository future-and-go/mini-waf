// Unit-level tests for waf-api notifications channel construction and
// channel_type reporting. These exercise `build_channel` directly without
// requiring a Postgres testcontainer.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use waf_api::notifications::{build_channel, new_rate_limiter};

#[test]
fn build_webhook_channel_ok() {
    let chan = build_channel("webhook", &json!({ "url": "https://example.com/h" })).expect("build webhook");
    assert_eq!(chan.channel_type(), "webhook");
}

#[test]
fn build_webhook_with_secret_ok() {
    let chan =
        build_channel("webhook", &json!({ "url": "https://example.com/h", "secret": "s" })).expect("build webhook");
    assert_eq!(chan.channel_type(), "webhook");
}

#[test]
fn build_webhook_missing_url_fails() {
    let err = build_channel("webhook", &json!({})).err().expect("must fail");
    let msg = err.to_string();
    assert!(msg.contains("url") || msg.contains("URL"), "msg = {msg}");
}

#[test]
fn build_webhook_private_url_fails_ssrf() {
    let err = build_channel("webhook", &json!({ "url": "http://127.0.0.1/h" }))
        .err()
        .expect("must fail SSRF");
    let msg = err.to_string();
    assert!(msg.contains("rejected") || msg.contains("private"), "msg = {msg}");
}

#[test]
fn build_telegram_channel_ok() {
    let chan = build_channel("telegram", &json!({ "bot_token": "123:abc", "chat_id": "1" })).expect("build telegram");
    assert_eq!(chan.channel_type(), "telegram");
}

#[test]
fn build_telegram_missing_token_fails() {
    let err = build_channel("telegram", &json!({ "chat_id": "1" }))
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("bot_token"));
}

#[test]
fn build_telegram_missing_chat_id_fails() {
    let err = build_channel("telegram", &json!({ "bot_token": "123:abc" }))
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("chat_id"));
}

#[test]
fn build_email_channel_ok() {
    let chan = build_channel(
        "email",
        &json!({
            "smtp_host": "127.0.0.1",
            "smtp_port": 25,
            "username": "u",
            "password": "p",
            "from": "noreply@example.com",
            "to": ["dest@example.com"],
        }),
    )
    .expect("build email");
    assert_eq!(chan.channel_type(), "email");
}

#[test]
fn build_email_missing_from_fails() {
    let err = build_channel("email", &json!({ "smtp_host": "127.0.0.1" }))
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("from"));
}

#[test]
fn build_email_uses_defaults_for_optional_fields() {
    // smtp_host/port/username/password all default. only `from` is required.
    let chan = build_channel("email", &json!({ "from": "x@example.com" })).expect("build email");
    assert_eq!(chan.channel_type(), "email");
}

#[test]
fn build_unknown_channel_type_fails() {
    let err = build_channel("smoke-signal", &json!({})).err().expect("must fail");
    assert!(err.to_string().contains("unknown channel type"));
}

#[test]
fn new_rate_limiter_starts_empty() {
    let rl = new_rate_limiter();
    assert!(rl.is_empty());
}
