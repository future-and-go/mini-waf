//! WAF security-event audit sender.
//!
//! Records **access decisions** — block / allow on a whitelist hit /
//! rate-limit / challenge — as one §6 JSON object per processed request,
//! appended to the JSONL audit file (the sole audit sink). Each event carries
//! a fixed schema so SIEM ingestion is straightforward.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;
use waf_common::types::InteropMode;

use super::audit_file_sink::AuditFileSink;

/// High-level event category.  Mapped 1:1 to a string in the JSON record
/// (the `event_type` extra field) so SIEM filters can match on it.
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

/// Path truncation cap.  Keeps individual audit lines bounded even if an
/// attacker crafts huge URIs.
const PATH_TRUNCATE_AT: usize = 500;

/// Structured WAF audit event serialized to the §6 JSONL audit record.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: AuditEventType,
    pub rule_name: String,
    pub rule_id: Option<String>,
    pub phase: Option<String>,
    /// Raw TCP peer address — the contract §6 `ip` field. Peer-pure regardless
    /// of `trust_proxy_headers` (see [`waf_common::types::RequestCtx::peer_ip`]).
    pub peer_ip: String,
    /// Trust-resolved client address (XFF-derived under proxy trust). Retained
    /// as the `client_ip` extra field for the admin panel.
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
    sink: AuditFileSink,
}

impl AuditSender {
    /// Wrap an [`AuditFileSink`] dedicated to audit events.
    pub fn new(sink: AuditFileSink) -> Self {
        Self {
            inner: Arc::new(Inner { sink }),
        }
    }

    /// Send an event without blocking the caller. The file sink queues the
    /// record and drops silently under backpressure, so the WAF request path
    /// is never gated on disk availability.
    pub fn send(&self, event: AuditEvent) {
        if !self.inner.sink.is_active() {
            return;
        }
        let record = build_audit_record(event);
        self.inner.sink.append(&record);
    }
}

/// Build the §6 audit record from an audit event. Extracted from
/// `AuditSender::send` so unit tests can verify the record schema without a
/// live sink.
fn build_audit_record(event: AuditEvent) -> serde_json::Value {
    // Contract §6: the `path` field is the request path *including* the query
    // string. The standalone `query` field is kept as an extra for FE filters.
    let full_path = if event.query.is_empty() {
        event.path
    } else {
        format!("{}?{}", event.path, event.query)
    };
    let path = if full_path.len() > PATH_TRUNCATE_AT {
        let mut end = PATH_TRUNCATE_AT;
        while end > 0 && !full_path.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &full_path[..end])
    } else {
        full_path
    };

    json!({
        // Contract §6 required fields
        "request_id": event.req_id,
        "ts_ms": event.timestamp.timestamp_millis(),
        "ip": event.peer_ip,
        "method": event.method,
        "path": path,
        "action": event.contract_action,
        "risk_score": event.risk_score,
        "mode": event.mode.as_contract_str(),
        // Extra context (§6 allows; no secrets). Consumed by the admin panel.
        "event_type": event.event_type.as_str(),
        "rule_name": event.rule_name,
        "rule_id": event.rule_id,
        "phase": event.phase,
        "client_ip": event.client_ip,
        "host": event.host,
        "tier": event.tier,
        "detail": event.detail,
        "query": event.query,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
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
            peer_ip: "1.2.3.4".to_string(),
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
    fn audit_record_includes_all_eight_contract_fields() {
        let event = make_test_event();
        let payload = build_audit_record(event);

        // Contract §6: the eight required fields, present with correct types.
        assert!(payload["request_id"].is_string(), "request_id missing");
        assert!(payload["ts_ms"].is_i64(), "ts_ms missing/not int");
        assert!(payload["ip"].is_string(), "ip missing");
        assert!(payload["method"].is_string(), "method missing");
        assert!(payload["path"].is_string(), "path missing");
        assert!(payload["action"].is_string(), "action missing");
        assert!(payload["risk_score"].is_u64(), "risk_score missing/not int");
        assert!(payload["mode"].is_string(), "mode missing");

        // VL-isms must be gone (decommission leaves no VL vocabulary behind).
        assert!(payload.get("_time").is_none(), "_time must be dropped");
        assert!(payload.get("_msg").is_none(), "_msg must be dropped");
        assert!(payload.get("stream").is_none(), "stream must be dropped");

        // No duplicate contract_action key — action IS the contract field
        assert!(
            payload.get("contract_action").is_none(),
            "contract_action should not exist as a separate key"
        );
    }

    #[test]
    fn audit_record_ts_ms_is_epoch_milliseconds() {
        let event = make_test_event();
        let payload = build_audit_record(event);
        // 2026-01-01T00:00:00Z in epoch millis
        assert_eq!(payload["ts_ms"], 1_767_225_600_000_i64);
    }

    #[test]
    fn audit_record_risk_score_and_mode_propagate() {
        let mut event = make_test_event();
        event.risk_score = 75;
        event.mode = InteropMode::LogOnly;
        event.contract_action = "rate_limit";

        let payload = build_audit_record(event);
        assert_eq!(payload["risk_score"], 75);
        assert_eq!(payload["mode"], "log_only");
        assert_eq!(payload["action"], "rate_limit");
    }

    #[test]
    fn audit_record_query_field() {
        let event = make_test_event();
        let payload = build_audit_record(event);
        assert_eq!(payload["query"], "id=1&sort=name");

        // Empty query produces empty string, not absent
        let mut event2 = make_test_event();
        event2.query = String::new();
        let payload2 = build_audit_record(event2);
        assert_eq!(payload2["query"], "");
    }

    #[test]
    fn audit_record_has_contract_ip_field() {
        let event = make_test_event();
        let payload = build_audit_record(event);
        // Contract §6 requires a field named `ip` (TCP peer address).
        assert_eq!(payload["ip"], "1.2.3.4");
        // `client_ip` retained as an extra field for the admin-panel FE.
        assert_eq!(payload["client_ip"], "1.2.3.4");
    }

    #[test]
    fn audit_ip_field_is_peer_not_xff_resolved_client() {
        // Under proxy trust, `client_ip` becomes the XFF value while `peer_ip`
        // stays the raw TCP peer. The §6 `ip` field must report the peer.
        let mut event = make_test_event();
        event.peer_ip = "203.0.113.9".to_string(); // real TCP peer
        event.client_ip = "10.0.0.5".to_string(); // XFF-derived under trust
        let payload = build_audit_record(event);
        assert_eq!(payload["ip"], "203.0.113.9", "§6 ip must be the TCP peer");
        assert_eq!(payload["client_ip"], "10.0.0.5", "extra keeps resolved client");
    }

    #[test]
    fn audit_record_path_includes_query_string() {
        // Contract §6: `path` = request path including query string.
        let event = make_test_event();
        let payload = build_audit_record(event);
        assert_eq!(payload["path"], "/api/users?id=1&sort=name");
        // Standalone `query` extra field still present.
        assert_eq!(payload["query"], "id=1&sort=name");
    }

    #[test]
    fn audit_record_path_without_query_has_no_separator() {
        let mut event = make_test_event();
        event.query = String::new();
        let payload = build_audit_record(event);
        assert_eq!(payload["path"], "/api/users");
    }

    #[test]
    fn audit_record_request_id_set_from_req_id() {
        let event = make_test_event();
        let payload = build_audit_record(event);
        assert_eq!(payload["request_id"], "req-abc-123");
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
