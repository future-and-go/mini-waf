//! Unsupported request-body charset detection.
//!
//! Every body-side detection in this crate (`sql_injection`, `xss`,
//! `body_abuse_walker`, custom regex rules) operates on the raw bytes of
//! the request body and assumes those bytes encode ASCII / UTF-8 text.
//! When a request carries `Content-Type: ...; charset=utf-16le` (legacy
//! .NET / SOAP stacks) the bytes for `<script>` are
//! `3c 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00` — none of the
//! ASCII-oriented pattern matchers see the payload, but an upstream that
//! honours the declared charset decodes it back to `<script>` and runs it.
//! Same primitive lets `' OR 1=1--` slip past libinjection.
//!
//! Defensive policy (chosen over edge transcoding for v1): reject any
//! request whose `Content-Type` declares a charset other than UTF-8 /
//! US-ASCII / ASCII. Operators who legitimately need other encodings must
//! transcode at their own edge before the request reaches the WAF.

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

/// Case-insensitive supported-charset table. Matched against the *value*
/// of the `charset=` parameter after lowercasing.
const SUPPORTED_CHARSETS: &[&str] = &["utf-8", "utf8", "us-ascii", "ascii"];

pub struct CharsetCheck;

impl CharsetCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for CharsetCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for CharsetCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let ct = ctx.headers.get("content-type")?;
        let cs = parse_charset(ct)?;
        if is_supported_charset(&cs) {
            return None;
        }
        Some(DetectionResult {
            rule_id: Some("CHARSET-001".to_string()),
            rule_name: "Unsupported Charset".to_string(),
            phase: Phase::UnsupportedCharset,
            detail: format!("Content-Type declares unsupported charset: {cs}"),
            rule_action: None,
            action_status: None,
        })
    }
}

/// Extract the `charset=` parameter value from a `Content-Type` header.
///
/// Returns the value in lowercase with surrounding whitespace and double
/// quotes stripped. Returns `None` when no `charset=` parameter is present;
/// the caller treats absence as "trust upstream" (no detection emitted).
pub fn parse_charset(content_type: &str) -> Option<String> {
    for raw in content_type.split(';') {
        let part = raw.trim();
        let lower = part.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("charset=") {
            let cleaned = rest.trim().trim_matches('"');
            return Some(cleaned.to_string());
        }
    }
    None
}

/// Whether the given charset name (already lowercased) is one the WAF
/// pattern matchers can reason about directly.
pub fn is_supported_charset(name: &str) -> bool {
    SUPPORTED_CHARSETS.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Arc;
    use waf_common::HostConfig;
    use waf_common::tier::Tier;

    fn make_ctx(content_type: Option<&str>) -> RequestCtx {
        let mut headers = HashMap::new();
        if let Some(ct) = content_type {
            headers.insert("content-type".to_string(), ct.to_string());
        }
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "1.2.3.4".parse().unwrap(),
            client_port: 0,
            method: "POST".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/api".to_string(),
            query: String::new(),
            headers,
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier: Tier::CatchAll,
            tier_policy: RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
        }
    }

    // ── parse_charset ────────────────────────────────────────────────────────

    #[test]
    fn parse_returns_none_when_charset_param_absent() {
        assert_eq!(parse_charset("application/json"), None);
        assert_eq!(parse_charset("text/plain; foo=bar"), None);
    }

    #[test]
    fn parse_extracts_simple_value() {
        assert_eq!(parse_charset("text/html; charset=utf-8"), Some("utf-8".into()));
        assert_eq!(parse_charset("application/json;charset=UTF-8"), Some("utf-8".into()));
    }

    #[test]
    fn parse_strips_quotes_and_whitespace() {
        assert_eq!(parse_charset("text/xml; charset=\"utf-16le\""), Some("utf-16le".into()));
        assert_eq!(parse_charset("text/html;   charset=  utf-8  "), Some("utf-8".into()));
    }

    #[test]
    fn parse_is_case_insensitive_on_parameter_name() {
        assert_eq!(
            parse_charset("text/html; CHARSET=ISO-8859-1"),
            Some("iso-8859-1".into())
        );
        assert_eq!(parse_charset("text/html; ChArSet=utf-8"), Some("utf-8".into()));
    }

    // ── is_supported_charset ─────────────────────────────────────────────────

    #[test]
    fn supported_accepts_utf8_and_ascii_variants() {
        assert!(is_supported_charset("utf-8"));
        assert!(is_supported_charset("utf8"));
        assert!(is_supported_charset("us-ascii"));
        assert!(is_supported_charset("ascii"));
    }

    #[test]
    fn supported_rejects_utf16_and_iso8859() {
        assert!(!is_supported_charset("utf-16le"));
        assert!(!is_supported_charset("utf-16be"));
        assert!(!is_supported_charset("iso-8859-1"));
        assert!(!is_supported_charset("windows-1252"));
        assert!(!is_supported_charset("shift_jis"));
    }

    // ── Check impl integration ───────────────────────────────────────────────

    #[test]
    fn check_passes_when_no_content_type_header() {
        let ctx = make_ctx(None);
        assert!(CharsetCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn check_passes_when_charset_omitted() {
        let ctx = make_ctx(Some("application/json"));
        assert!(CharsetCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn check_passes_for_utf8() {
        let ctx = make_ctx(Some("application/json; charset=utf-8"));
        assert!(CharsetCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn check_blocks_utf16le_xml_soap_envelope() {
        let ctx = make_ctx(Some("application/xml; charset=utf-16le"));
        let det = CharsetCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "CHARSET-001");
        assert_eq!(det.phase, Phase::UnsupportedCharset);
        assert!(det.detail.contains("utf-16le"), "detail={}", det.detail);
    }

    #[test]
    fn check_blocks_iso8859_form_body() {
        let ctx = make_ctx(Some("application/x-www-form-urlencoded; charset=iso-8859-1"));
        let det = CharsetCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "CHARSET-001");
    }

    #[test]
    fn check_blocks_quoted_uppercase_utf16() {
        let ctx = make_ctx(Some("text/xml; charset=\"UTF-16BE\""));
        let det = CharsetCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "CHARSET-001");
        assert!(det.detail.contains("utf-16be"), "detail={}", det.detail);
    }
}
