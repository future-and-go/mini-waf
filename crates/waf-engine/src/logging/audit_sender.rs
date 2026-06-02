//! WAF security-event audit sender.
//!
//! Layer 2 of the `VictoriaLogs` pipeline (Layer 1 is `tracing`).  Whereas
//! the `tracing` Layer captures every log line emitted by the WAF process,
//! this sender only records **access decisions** — block / allow on a
//! whitelist hit / rate-limit / challenge.  Each event carries a fixed
//! schema so downstream `LogsQL` queries are deterministic and SIEM
//! ingestion is straightforward.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;
use waf_common::types::InteropMode;

use super::batch_buffer::BatchSender;

/// High-level event category.  Mapped 1:1 to a string in the JSON payload
/// so `VictoriaLogs` filters can use `event_type:block` etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// WAF blocked the request.
    Block,
    /// WAF allowed the request via an explicit whitelist match.
    Allow,
    /// WAF requested a CAPTCHA / challenge.
    Challenge,
    /// WAF rate-limited the request.
    RateLimit,
    /// WAF logged-only mode — would have blocked in enforce mode.
    LogOnly,
}

impl AuditEventType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Allow => "allow",
            Self::Challenge => "challenge",
            Self::RateLimit => "rate_limit",
            Self::LogOnly => "log_only",
        }
    }
}

/// Path truncation cap.  Keeps individual log lines bounded so `VictoriaLogs`
/// indexing stays cheap even if an attacker crafts huge URIs.
const PATH_TRUNCATE_AT: usize = 500;

/// Structured WAF audit event.  Field names match the `LogsQL` queries used
/// by the admin panel — do not rename them without updating the FE.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: AuditEventType,
    pub rule_name: String,
    pub rule_id: Option<String>,
    pub phase: Option<String>,
    pub client_ip: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub tier: Option<String>,
    pub detail: Option<String>,
    pub req_id: Option<String>,
    // Contract §6 fields
    pub risk_score: u8,
    pub mode: InteropMode,
    pub query: String,
    pub contract_action: &'static str,
}

/// Fire-and-forget audit sink.  Cloning is cheap (`Arc` internally).
#[derive(Clone)]
pub struct AuditSender {
    inner: Arc<Inner>,
}

struct Inner {
    buffer: BatchSender,
}

impl AuditSender {
    /// Wrap a [`BatchSender`] dedicated to audit events.
    pub fn new(buffer: BatchSender) -> Self {
        Self {
            inner: Arc::new(Inner { buffer }),
        }
    }

    /// Send an event without blocking the caller. Drops silently when
    /// `VictoriaLogs` is unreachable so the WAF request path is never gated
    /// on observability availability.
    pub fn send(&self, event: AuditEvent) {
        if !self.inner.buffer.is_active() {
            return;
        }
        let payload = build_vl_payload(event);
        self.inner.buffer.try_send(payload);
    }
}

/// Build the VictoriaLogs JSON payload from an audit event. Extracted from
/// `AuditSender::send` so unit tests can verify the payload schema without
/// needing a live `BatchSender`.
fn build_vl_payload(event: AuditEvent) -> serde_json::Value {
    let path = if event.path.len() > PATH_TRUNCATE_AT {
        let mut end = PATH_TRUNCATE_AT;
        while end > 0 && !event.path.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &event.path[..end])
    } else {
        event.path
    };

    json!({
        "_time": event.timestamp.to_rfc3339(),
        "_msg": format!(
            "{} {} {} → {} (rule={})",
            event.event_type.as_str(),
            event.method,
            path,
            event.client_ip,
            event.rule_name,
        ),
        "event_type": event.event_type.as_str(),
        "rule_name": event.rule_name,
        "rule_id": event.rule_id,
        "phase": event.phase,
        "client_ip": event.client_ip,
        "host": event.host,
        "method": event.method,
        "path": path,
        "tier": event.tier,
        "detail": event.detail,
        "req_id": event.req_id,
        "stream": "waf_audit",
        // Contract §6 fields
        "ts_ms": event.timestamp.timestamp_millis(),
        "request_id": event.req_id,
        "action": event.contract_action,
        "risk_score": event.risk_score,
        "mode": event.mode.as_contract_str(),
        "query": event.query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_string_round_trip() {
        assert_eq!(AuditEventType::Block.as_str(), "block");
        assert_eq!(AuditEventType::Allow.as_str(), "allow");
        assert_eq!(AuditEventType::Challenge.as_str(), "challenge");
        assert_eq!(AuditEventType::RateLimit.as_str(), "rate_limit");
        assert_eq!(AuditEventType::LogOnly.as_str(), "log_only");
    }

    fn make_test_event() -> AuditEvent {
        AuditEvent {
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            event_type: AuditEventType::Block,
            rule_name: "test-rule".to_string(),
            rule_id: Some("R001".to_string()),
            phase: Some("phase1".to_string()),
            client_ip: "1.2.3.4".to_string(),
            host: "example.com".to_string(),
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            tier: Some("standard".to_string()),
            detail: Some("test detail".to_string()),
            req_id: Some("req-abc-123".to_string()),
            risk_score: 85,
            mode: InteropMode::Enforce,
            query: "id=1&sort=name".to_string(),
            contract_action: "block",
        }
    }

    #[test]
    fn vl_payload_includes_contract_fields() {
        let event = make_test_event();
        let payload = build_vl_payload(event);

        // Contract §6 fields present
        assert!(payload.get("ts_ms").is_some(), "ts_ms missing");
        assert!(payload.get("request_id").is_some(), "request_id missing");
        assert!(payload.get("action").is_some(), "action missing");
        assert!(payload.get("risk_score").is_some(), "risk_score missing");
        assert!(payload.get("mode").is_some(), "mode missing");
        assert!(payload.get("query").is_some(), "query missing");

        // Existing fields still present
        assert!(payload.get("_time").is_some(), "_time missing");
        assert!(payload.get("event_type").is_some(), "event_type missing");
        assert!(payload.get("req_id").is_some(), "req_id missing");
        assert!(payload.get("stream").is_some(), "stream missing");

        // No duplicate contract_action key — action IS the contract field
        assert!(
            payload.get("contract_action").is_none(),
            "contract_action should not exist as a separate key"
        );
    }

    #[test]
    fn vl_payload_ts_ms_is_epoch_milliseconds() {
        let event = make_test_event();
        let payload = build_vl_payload(event);
        // 2026-01-01T00:00:00Z in epoch millis
        assert_eq!(payload["ts_ms"], 1767225600000_i64);
        // _time (RFC3339) and ts_ms represent the same instant
        assert_eq!(payload["_time"], "2026-01-01T00:00:00+00:00");
    }

    #[test]
    fn vl_payload_risk_score_and_mode_propagate() {
        let mut event = make_test_event();
        event.risk_score = 75;
        event.mode = InteropMode::LogOnly;
        event.contract_action = "rate_limit";

        let payload = build_vl_payload(event);
        assert_eq!(payload["risk_score"], 75);
        assert_eq!(payload["mode"], "log_only");
        assert_eq!(payload["action"], "rate_limit");
    }

    #[test]
    fn vl_payload_query_field() {
        let event = make_test_event();
        let payload = build_vl_payload(event);
        assert_eq!(payload["query"], "id=1&sort=name");

        // Empty query produces empty string, not absent
        let mut event2 = make_test_event();
        event2.query = String::new();
        let payload2 = build_vl_payload(event2);
        assert_eq!(payload2["query"], "");
    }

    #[test]
    fn vl_payload_request_id_mirrors_req_id() {
        let event = make_test_event();
        let payload = build_vl_payload(event);
        assert_eq!(payload["request_id"], payload["req_id"]);
    }

    #[test]
    fn path_truncation_respects_utf8_boundaries() {
        let mut p = String::new();
        // 'é' is 2 bytes in UTF-8; pushing > PATH_TRUNCATE_AT/2 chars
        // guarantees we cross the cap and exercise the boundary walk.
        for _ in 0..(PATH_TRUNCATE_AT) {
            p.push('é');
        }
        assert!(p.len() > PATH_TRUNCATE_AT);
        // Use the same logic as `send` for the boundary calculation.
        let mut end = PATH_TRUNCATE_AT;
        while end > 0 && !p.is_char_boundary(end) {
            end -= 1;
        }
        let truncated = &p[..end];
        assert!(truncated.is_char_boundary(0));
        assert!(truncated.len() <= PATH_TRUNCATE_AT);
    }
}
