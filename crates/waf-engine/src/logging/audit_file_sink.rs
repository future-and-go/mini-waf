//! Append-only JSONL audit file sink (interop contract v2.3 §6/§8/§10).
//!
//! The §6 audit record built in [`super::audit_sender`] is serialized to one
//! JSON object per line and appended to a configurable file (default
//! `./waf_audit.log`). This file is the **sole** audit sink.
//!
//! ## Off the hot path
//!
//! `append` only pushes a pre-serialized line onto a bounded channel and
//! returns immediately — never touching the filesystem on the request path. A
//! dedicated consumer thread owns a [`BufWriter`] over the append-only file and
//! drains the channel, flushing on a short interval and on shutdown. When the
//! channel is full the line is dropped silently, so the request path is never
//! gated on disk availability (mirrors the fire-and-forget audit semantics).
//!
//! ## Lazy creation
//!
//! The file is opened on the **first** received record, not when the sink is
//! constructed. An idle process therefore creates no audit file; the file
//! appears once the first request is processed (US-1201).

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::thread;
use std::time::Duration;

use waf_common::config::AuditFileConfig;

/// Bounded channel capacity. Older lines are dropped when full so a slow disk
/// never back-pressures the request path.
const CHANNEL_CAPACITY: usize = 10_000;

/// Flush cadence for the consumer's `BufWriter`.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);

/// Fire-and-forget append-only JSONL audit sink. Cloning is cheap (the sender
/// is an `Arc` internally).
#[derive(Clone)]
pub struct AuditFileSink {
    /// `None` when auditing is disabled — `append` becomes a no-op.
    sender: Option<SyncSender<String>>,
}

impl AuditFileSink {
    /// Build a sink from config and spawn its consumer thread. When
    /// `config.enabled` is `false` the sink is inert and `append` does nothing.
    #[must_use]
    pub fn spawn(config: &AuditFileConfig) -> Self {
        if !config.enabled {
            return Self { sender: None };
        }
        let (tx, rx) = sync_channel::<String>(CHANNEL_CAPACITY);
        let log_path = config.log_path.clone();
        // Dedicated OS thread keeps file I/O entirely off the async runtime and
        // the request hot path.
        thread::Builder::new()
            .name("waf-audit-sink".to_string())
            .spawn(move || run_consumer(&log_path, &rx))
            .ok();
        Self { sender: Some(tx) }
    }

    /// Queue one serialized audit line for append. Non-blocking: drops silently
    /// when the sink is disabled or the channel is saturated.
    pub fn append(&self, record: &serde_json::Value) {
        let Some(sender) = &self.sender else {
            return;
        };
        let Ok(line) = serde_json::to_string(record) else {
            return;
        };
        match sender.try_send(line) {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Whether the sink will actually persist records.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.sender.is_some()
    }
}

/// Consumer loop. Opens the append-only file on the first received record
/// (lazy creation), then drains the channel, flushing on `FLUSH_INTERVAL` and
/// when the channel closes.
fn run_consumer(log_path: &str, rx: &std::sync::mpsc::Receiver<String>) {
    let mut writer: Option<BufWriter<std::fs::File>> = None;
    loop {
        match rx.recv_timeout(FLUSH_INTERVAL) {
            Ok(line) => {
                if writer.is_none() {
                    match OpenOptions::new().append(true).create(true).open(log_path) {
                        Ok(file) => writer = Some(BufWriter::new(file)),
                        Err(_) => continue, // disk unavailable — drop, never panic
                    }
                }
                if let Some(w) = writer.as_mut() {
                    let _ = w.write_all(line.as_bytes());
                    let _ = w.write_all(b"\n");
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Some(w) = writer.as_mut() {
                    let _ = w.flush();
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(w) = writer.as_mut() {
                    let _ = w.flush();
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Instant;

    /// Wait until `path` has at least `want` non-empty lines or the deadline
    /// elapses; returns the parsed lines.
    fn read_lines_until(path: &std::path::Path, want: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(content) = std::fs::read_to_string(path) {
                let lines: Vec<serde_json::Value> = content
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
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn append_writes_one_valid_json_line_per_record() {
        let dir = std::env::temp_dir().join(format!("waf_audit_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("one_line.log");
        let cfg = AuditFileConfig {
            enabled: true,
            log_path: path.to_string_lossy().into_owned(),
        };
        let sink = AuditFileSink::spawn(&cfg);
        sink.append(&json!({"request_id": "a", "ts_ms": 1}));
        let lines = read_lines_until(&path, 1);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["request_id"], "a");
        // Trailing newline present.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.ends_with('\n'));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_is_append_only_across_records() {
        let dir = std::env::temp_dir().join(format!("waf_audit_test2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("append.log");
        // Pre-seed an existing line; the sink must preserve it, not truncate.
        std::fs::write(&path, "{\"seed\":true}\n").unwrap();
        let cfg = AuditFileConfig {
            enabled: true,
            log_path: path.to_string_lossy().into_owned(),
        };
        let sink = AuditFileSink::spawn(&cfg);
        sink.append(&json!({"n": 1}));
        sink.append(&json!({"n": 2}));
        let lines = read_lines_until(&path, 3);
        assert_eq!(lines.len(), 3, "seed line preserved + 2 appended");
        assert_eq!(lines[0]["seed"], true);
        assert_eq!(lines[1]["n"], 1);
        assert_eq!(lines[2]["n"], 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_sink_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("waf_audit_test3_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("disabled.log");
        let cfg = AuditFileConfig {
            enabled: false,
            log_path: path.to_string_lossy().into_owned(),
        };
        let sink = AuditFileSink::spawn(&cfg);
        assert!(!sink.is_active());
        sink.append(&json!({"n": 1}));
        thread::sleep(Duration::from_millis(100));
        assert!(!path.exists(), "disabled sink must not create the file");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
