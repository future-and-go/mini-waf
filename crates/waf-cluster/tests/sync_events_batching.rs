//! Tests for the event batcher, stats collector, config syncer, and the
//! lz4 snapshot helpers used by the rule sync pipeline.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use tokio::sync::mpsc;

use waf_cluster::protocol::{ConfigSync, SecurityEvent};
use waf_cluster::sync::config::ConfigSyncer;
use waf_cluster::sync::events::{EventBatcher, StatsCollector, run_event_batcher};
use waf_cluster::sync::rules::{compress_snapshot, decompress_snapshot};

fn evt(path: &str) -> SecurityEvent {
    SecurityEvent {
        timestamp_ms: 1,
        client_ip: "127.0.0.1".to_string(),
        method: "GET".to_string(),
        path: path.to_string(),
        host: "example.com".to_string(),
        rule_id: None,
        action: "allow".to_string(),
        geo_country: String::new(),
        node_id: "n1".to_string(),
    }
}

// ─── EventBatcher ─────────────────────────────────────────────────────────────

#[test]
fn event_batcher_flushes_on_capacity() {
    let mut b = EventBatcher::new("n1".to_string(), 2, 1000);
    assert!(b.push(evt("/a")).is_none(), "first push under capacity");
    let batch = b.push(evt("/b")).expect("second push must auto-flush");
    assert_eq!(batch.events.len(), 2);
    assert_eq!(batch.node_id, "n1");
    assert_eq!(b.pending_count(), 0);
}

#[test]
fn event_batcher_flush_empty_returns_none() {
    let mut b = EventBatcher::new("n1".to_string(), 5, 1000);
    assert!(b.flush().is_none());
}

#[test]
fn event_batcher_manual_flush_drains_partial() {
    let mut b = EventBatcher::new("n1".to_string(), 10, 1000);
    b.push(evt("/x"));
    b.push(evt("/y"));
    assert_eq!(b.pending_count(), 2);
    let batch = b.flush().expect("manual flush returns batch");
    assert_eq!(batch.events.len(), 2);
    assert_eq!(b.pending_count(), 0);
}

#[test]
fn event_batcher_flush_interval_accessor() {
    let b = EventBatcher::new("n1".to_string(), 1, 250);
    assert_eq!(b.flush_interval_ms(), 250);
}

// ─── run_event_batcher ────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn run_event_batcher_flushes_on_close() {
    let batcher = EventBatcher::new("n1".to_string(), 100, 5_000);
    let (ev_tx, ev_rx) = mpsc::channel::<SecurityEvent>(8);
    let (batch_tx, mut batch_rx) = mpsc::channel(8);

    let h = tokio::spawn(run_event_batcher(batcher, ev_rx, batch_tx));

    ev_tx.send(evt("/p")).await.expect("send evt");
    drop(ev_tx); // close → triggers final flush + return

    let batch = batch_rx.recv().await.expect("expected final batch on close");
    assert_eq!(batch.events.len(), 1);
    h.await.expect("batcher exits cleanly");
}

#[tokio::test(start_paused = true)]
async fn run_event_batcher_flushes_on_capacity() {
    let batcher = EventBatcher::new("n1".to_string(), 2, 5_000);
    let (ev_tx, ev_rx) = mpsc::channel::<SecurityEvent>(8);
    let (batch_tx, mut batch_rx) = mpsc::channel(8);

    let h = tokio::spawn(run_event_batcher(batcher, ev_rx, batch_tx));

    ev_tx.send(evt("/a")).await.unwrap();
    ev_tx.send(evt("/b")).await.unwrap();

    let batch = batch_rx.recv().await.expect("capacity flush");
    assert_eq!(batch.events.len(), 2);

    drop(ev_tx);
    h.await.expect("ok");
}

// ─── StatsCollector ───────────────────────────────────────────────────────────

#[test]
fn stats_collector_counts_and_flushes() {
    let mut c = StatsCollector::new("n1".to_string());
    c.record_request("1.1.1.1", Some("rule-a"), "US", false);
    c.record_request("1.1.1.1", Some("rule-a"), "US", true);
    c.record_request("2.2.2.2", None, "", false);
    assert_eq!(c.total_requests(), 3);

    let batch = c.flush();
    assert_eq!(batch.total_requests, 3);
    assert_eq!(batch.blocked_requests, 1);
    assert_eq!(batch.allowed_requests, 2);
    assert_eq!(batch.top_ips.get("1.1.1.1"), Some(&2));
    assert_eq!(batch.top_ips.get("2.2.2.2"), Some(&1));
    assert_eq!(batch.top_rules.get("rule-a"), Some(&2));
    assert!(!batch.top_countries.contains_key(""), "empty country must be skipped");
    assert_eq!(batch.top_countries.get("US"), Some(&2));

    // After flush counters reset.
    assert_eq!(c.total_requests(), 0);
    let empty = c.flush();
    assert_eq!(empty.total_requests, 0);
    assert!(empty.top_ips.is_empty());
}

// ─── ConfigSyncer ─────────────────────────────────────────────────────────────

#[test]
fn config_syncer_apply_and_build() {
    let mut s = ConfigSyncer::new("n1".to_string());
    assert_eq!(s.current_version(), 0);

    let built = s.build_sync("toml=1".to_string());
    assert_eq!(built.version, 1, "build_sync increments without applying");
    assert_eq!(built.config_toml, "toml=1");

    let incoming = ConfigSync {
        version: 7,
        config_toml: "x".to_string(),
    };
    s.apply_sync(&incoming).expect("apply");
    assert_eq!(s.current_version(), 7);
}

// ─── lz4 snapshot helpers ─────────────────────────────────────────────────────

#[test]
fn lz4_compress_decompress_roundtrip() {
    let payload: Vec<u8> = (0..1024u32).flat_map(u32::to_be_bytes).collect();
    let compressed = compress_snapshot(&payload);
    let decompressed = decompress_snapshot(&compressed).expect("decompress");
    assert_eq!(decompressed, payload);
}

#[test]
fn lz4_decompress_garbage_errors() {
    let bogus = vec![0u8; 4];
    let res = decompress_snapshot(&bogus);
    assert!(res.is_err(), "garbage must fail to decompress");
}
