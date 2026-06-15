//! Integration tests for the JSONL audit file sink (interop v2.3 §6/§8/§10).
//!
//! Drives the real `AuditSender -> AuditFileSink` path to a temp file and reads
//! the resulting JSONL back, covering the E12 acceptance criteria that the unit
//! tests cannot reach end-to-end:
//!
//! * one valid JSON object per processed event, file created on first event;
//! * append-only across a sink restart (the `reset_state` analog — a new sink
//!   over the same path must never truncate prior lines);
//! * the eight §6 required fields and their types;
//! * `ip` is the TCP peer, and distinct `127.0.0.x` aliases stay distinct;
//! * `request_id` / `mode` are carried verbatim (the same values that drive the
//!   `X-WAF-Request-Id` / `X-WAF-Mode` response headers).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::{Duration, Instant};

use serde_json::Value;
use waf_common::config::AuditFileConfig;
use waf_common::types::InteropMode;
use waf_engine::logging::AuditFileSink;
use waf_engine::logging::audit_sender::{AuditEvent, AuditEventType, AuditSender};

fn event(req_id: &str, peer_ip: &str, action: &'static str, mode: InteropMode) -> AuditEvent {
    AuditEvent {
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Block,
        rule_name: "r".to_string(),
        rule_id: Some("R1".to_string()),
        phase: Some("p".to_string()),
        peer_ip: peer_ip.to_string(),
        client_ip: peer_ip.to_string(),
        host: "example.com".to_string(),
        method: "GET".to_string(),
        path: "/admin".to_string(),
        tier: Some("standard".to_string()),
        detail: None,
        req_id: Some(req_id.to_string()),
        risk_score: 90,
        mode,
        query: "a=1".to_string(),
        contract_action: action,
    }
}

fn unique_path(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("waf_audit_it_{}_{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("waf_audit.log")
}

/// Poll the file until it has at least `want` lines or the deadline elapses.
fn read_lines(path: &std::path::Path, want: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(content) = std::fs::read_to_string(path) {
            let lines: Vec<Value> = content
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
                .collect();
            if lines.len() >= want || Instant::now() >= deadline {
                return lines;
            }
        } else if Instant::now() >= deadline {
            return Vec::new();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn first_event_creates_file_with_one_json_line() {
    let path = unique_path("first");
    assert!(!path.exists(), "file must not exist before the first event");
    let sink = AuditFileSink::spawn(&AuditFileConfig {
        enabled: true,
        log_path: path.to_string_lossy().into_owned(),
    });
    let sender = AuditSender::new(sink);
    sender.send(event("id-1", "127.0.0.1", "block", InteropMode::Enforce));

    let lines = read_lines(&path, 1);
    assert_eq!(lines.len(), 1, "exactly one JSON line for one event");
    assert_eq!(lines[0]["request_id"], "id-1");
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn each_line_has_eight_required_fields_with_correct_types() {
    let path = unique_path("fields");
    let sender = AuditSender::new(AuditFileSink::spawn(&AuditFileConfig {
        enabled: true,
        log_path: path.to_string_lossy().into_owned(),
    }));
    sender.send(event("id-f", "203.0.113.5", "block", InteropMode::Enforce));

    let lines = read_lines(&path, 1);
    let r = &lines[0];
    assert!(r["request_id"].is_string());
    assert!(r["ts_ms"].is_i64());
    assert!(r["ip"].is_string());
    assert!(r["method"].is_string());
    assert!(r["path"].is_string());
    assert!(r["action"].is_string());
    assert!(r["risk_score"].is_u64());
    assert!(r["mode"].is_string());
    // §6: path includes the query string; method is the request method.
    assert_eq!(r["path"], "/admin?a=1");
    assert_eq!(r["method"], "GET");
    // JSONL file must not contain ingest-layer-specific field names.
    assert!(r.get("_time").is_none());
    assert!(r.get("_msg").is_none());
    assert!(r.get("stream").is_none());
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn append_only_across_sink_restart() {
    // A fresh sink over the same path (the `reset_state` analog) must append,
    // never truncate the records written by the previous sink.
    let path = unique_path("append");

    let sender1 = AuditSender::new(AuditFileSink::spawn(&AuditFileConfig {
        enabled: true,
        log_path: path.to_string_lossy().into_owned(),
    }));
    sender1.send(event("id-a", "127.0.0.1", "block", InteropMode::Enforce));
    let _ = read_lines(&path, 1);
    drop(sender1); // close the channel so the consumer flushes and exits

    let sender2 = AuditSender::new(AuditFileSink::spawn(&AuditFileConfig {
        enabled: true,
        log_path: path.to_string_lossy().into_owned(),
    }));
    sender2.send(event("id-b", "127.0.0.2", "block", InteropMode::Enforce));

    let lines = read_lines(&path, 2);
    assert_eq!(lines.len(), 2, "prior line preserved + new line appended");
    assert_eq!(lines[0]["request_id"], "id-a");
    assert_eq!(lines[1]["request_id"], "id-b");
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn ip_field_is_peer_and_distinct_127_aliases_stay_distinct() {
    let path = unique_path("peer");
    let sender = AuditSender::new(AuditFileSink::spawn(&AuditFileConfig {
        enabled: true,
        log_path: path.to_string_lossy().into_owned(),
    }));
    sender.send(event("id-1", "127.0.0.1", "block", InteropMode::Enforce));
    sender.send(event("id-2", "127.0.0.2", "block", InteropMode::Enforce));
    sender.send(event("id-3", "127.0.0.3", "block", InteropMode::Enforce));

    let lines = read_lines(&path, 3);
    let ips: Vec<&Value> = lines.iter().map(|l| &l["ip"]).collect();
    assert_eq!(ips[0], "127.0.0.1");
    assert_eq!(ips[1], "127.0.0.2");
    assert_eq!(ips[2], "127.0.0.3");
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn request_id_and_mode_are_carried_verbatim() {
    // These are the exact values mirrored into the X-WAF-Request-Id / X-WAF-Mode
    // response headers, so a SIEM can join the audit line to the wire response.
    let path = unique_path("corr");
    let sender = AuditSender::new(AuditFileSink::spawn(&AuditFileConfig {
        enabled: true,
        log_path: path.to_string_lossy().into_owned(),
    }));
    sender.send(event("uuid-enf", "10.0.0.9", "block", InteropMode::Enforce));
    sender.send(event("uuid-log", "10.0.0.9", "allow", InteropMode::LogOnly));

    let lines = read_lines(&path, 2);
    assert_eq!(lines[0]["request_id"], "uuid-enf");
    assert_eq!(lines[0]["mode"], "enforce");
    assert_eq!(lines[1]["request_id"], "uuid-log");
    assert_eq!(lines[1]["mode"], "log_only");
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
