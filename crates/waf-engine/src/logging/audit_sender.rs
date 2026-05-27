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
        self.inner.buffer.try_send(build_payload(event));
    }
}

/// Truncate `path` on a UTF-8 char boundary so non-ASCII URIs stay valid.
fn truncate_path(path: String) -> String {
    if path.len() <= PATH_TRUNCATE_AT {
        return path;
    }
    let mut end = PATH_TRUNCATE_AT;
    while end > 0 && !path.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &path[..end])
}

/// Build the NDJSON payload shipped to `VictoriaLogs`. Extracted from `send`
/// so the wire-format contract relied on by the admin panel (`stream`,
/// `rule_name`, `rule_id`, `event_type`, `phase`) is unit-testable without
/// spinning up a `BatchSender`.
fn build_payload(event: AuditEvent) -> serde_json::Value {
    let path = truncate_path(event.path);
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
    })
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn sample_block_event() -> AuditEvent {
        AuditEvent {
            timestamp: chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).unwrap_or_default(),
            event_type: AuditEventType::Block,
            rule_name: "SQLi: classic UNION-based".to_string(),
            rule_id: Some("OWASP-942100".to_string()),
            phase: Some("request_body".to_string()),
            client_ip: "203.0.113.7".to_string(),
            host: "api.example.com".to_string(),
            method: "POST".to_string(),
            path: "/api/login".to_string(),
            tier: Some("critical".to_string()),
            detail: Some("UNION SELECT detected".to_string()),
            req_id: Some("req-abc".to_string()),
        }
    }

    fn field_str<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
        payload.get(key).and_then(Value::as_str)
    }

    fn field_is_null(payload: &Value, key: &str) -> bool {
        payload.get(key).is_some_and(Value::is_null)
    }

    #[test]
    fn event_type_string_round_trip() {
        assert_eq!(AuditEventType::Block.as_str(), "block");
        assert_eq!(AuditEventType::Allow.as_str(), "allow");
        assert_eq!(AuditEventType::Challenge.as_str(), "challenge");
        assert_eq!(AuditEventType::RateLimit.as_str(), "rate_limit");
        assert_eq!(AuditEventType::LogOnly.as_str(), "log_only");
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
        let truncated = truncate_path(p);
        // Ellipsis is appended after the truncation, so the byte length
        // is bounded by PATH_TRUNCATE_AT plus the ellipsis encoding.
        assert!(truncated.ends_with('…'));
        assert!(truncated.len() <= PATH_TRUNCATE_AT + '…'.len_utf8());
    }

    /// Locks the wire-format contract relied on by the admin panel Security
    /// Logs page. The `Rule` column reads `rule_name`, the default LogsQL
    /// filters on `stream:waf_audit`, and operators slice further by
    /// `rule_id` / `event_type` / `phase` — every block event must carry
    /// all of them.
    #[test]
    fn block_payload_contains_all_admin_panel_fields() {
        let payload = build_payload(sample_block_event());

        assert_eq!(field_str(&payload, "stream"), Some("waf_audit"));
        assert_eq!(field_str(&payload, "event_type"), Some("block"));
        assert_eq!(field_str(&payload, "rule_name"), Some("SQLi: classic UNION-based"));
        assert_eq!(field_str(&payload, "rule_id"), Some("OWASP-942100"));
        assert_eq!(field_str(&payload, "phase"), Some("request_body"));
        assert_eq!(field_str(&payload, "client_ip"), Some("203.0.113.7"));
        assert_eq!(field_str(&payload, "host"), Some("api.example.com"));
        assert_eq!(field_str(&payload, "method"), Some("POST"));
        assert_eq!(field_str(&payload, "path"), Some("/api/login"));
        assert_eq!(field_str(&payload, "tier"), Some("critical"));
        assert_eq!(field_str(&payload, "req_id"), Some("req-abc"));
        // `_time` and `_msg` are required by VictoriaLogs' ingest schema.
        assert!(field_str(&payload, "_time").is_some());
        assert!(field_str(&payload, "_msg").is_some());
    }

    /// When a rule fires without a stable identifier (e.g. a runtime
    /// heuristic) `rule_id` serializes as JSON null. LogsQL `rule_id:*`
    /// can still distinguish present-vs-absent so the FE stays consistent.
    #[test]
    fn missing_optional_fields_serialize_as_null() {
        let mut ev = sample_block_event();
        ev.rule_id = None;
        ev.phase = None;
        ev.tier = None;
        ev.detail = None;
        ev.req_id = None;

        let payload = build_payload(ev);

        assert!(field_is_null(&payload, "rule_id"));
        assert!(field_is_null(&payload, "phase"));
        assert!(field_is_null(&payload, "tier"));
        assert!(field_is_null(&payload, "detail"));
        assert!(field_is_null(&payload, "req_id"));
        // Required identifiers stay populated.
        assert_eq!(field_str(&payload, "stream"), Some("waf_audit"));
        assert_eq!(field_str(&payload, "event_type"), Some("block"));
        assert_eq!(field_str(&payload, "rule_name"), Some("SQLi: classic UNION-based"));
    }

    /// Long paths are truncated with an ellipsis, but the payload field
    /// is still a non-empty string so the admin panel's `Path` column
    /// never renders blank.
    #[test]
    fn build_payload_truncates_long_path() {
        let mut ev = sample_block_event();
        ev.path = format!("/api/{}", "a".repeat(PATH_TRUNCATE_AT * 2));

        let payload = build_payload(ev);

        let path = field_str(&payload, "path").unwrap_or_default();
        assert!(path.ends_with('…'));
        assert!(path.len() <= PATH_TRUNCATE_AT + '…'.len_utf8());
    }

    /// Non-block events (`allow`, `challenge`, `rate_limit`, `log_only`)
    /// share the same schema so a single LogsQL preset filters everything
    /// in `stream:waf_audit`.
    #[test]
    fn all_event_types_share_the_audit_stream() {
        for ty in [
            AuditEventType::Allow,
            AuditEventType::Challenge,
            AuditEventType::RateLimit,
            AuditEventType::LogOnly,
        ] {
            let mut ev = sample_block_event();
            ev.event_type = ty;
            let payload = build_payload(ev);
            assert_eq!(field_str(&payload, "stream"), Some("waf_audit"));
            assert_eq!(field_str(&payload, "event_type"), Some(ty.as_str()));
        }
    }
}
