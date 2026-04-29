//! Header leak prevention (FR-035).
//!
//! Strips or sanitizes response headers that leak server info, debug data,
//! or PII to downstream clients.
//!
//! Detection cases live in the const tables below (server-info, PHP, ASP.NET,
//! framework/CMS, CDN/edge, debug-prefix, error-prefix, PII regexes). Each
//! family is independently gated by a `HeaderFilterConfig` boolean — operators
//! choose which categories run, code never has to recompile to drop a case.
//!
//! Hardening built into every active filter:
//!   * RFC 9110 §7.6.1 hop-by-hop headers are pinned to a never-strip list.
//!   * CRLF (`\r` / `\n`) inside any header value is treated as response-
//!     splitting (CWE-93 / CVE-2017-1000026 class) and the header is dropped.
//!   * PII regex input length is hard-capped (default 8 KiB; tunable via
//!     `PiiConfig::max_scan_bytes`) to bound `ReDoS` `DoS` surface.
//!   * `Set-Cookie` / `ETag` / `Authorization` are protected from PII-match
//!     stripping unless the operator opts in — a regex false-positive on a
//!     session token should not kill a user's session by default.
//!   * Operators may declare a per-deployment allowlist
//!     (`HeaderFilterConfig::preserve_headers` / `preserve_prefixes`) that
//!     beats every strip rule except the unconditional CRLF strip and the
//!     hop-by-hop guard.

use std::collections::HashSet;

use regex::Regex;
use tracing::{debug, warn};
use waf_common::config::{HeaderFilterConfig, PiiConfig};

use super::OutboundConfigError;

/// Compiled header filter rules.
#[derive(Debug)]
pub struct HeaderFilter {
    /// Exact header names to strip (lowercase).
    strip_exact: HashSet<String>,
    /// Header name prefixes to strip (lowercase).
    strip_prefixes: Vec<String>,
    /// Operator allowlist — exact header names preserved even when matched
    /// by a strip rule (lowercase).
    preserve_exact: HashSet<String>,
    /// Operator allowlist — header-name prefixes preserved (lowercase).
    preserve_prefixes: Vec<String>,
    /// Regex patterns to detect PII in header values.  Aligned 1:1 with
    /// `pii_pattern_names`.
    pii_patterns: Vec<Regex>,
    /// Stable names matching `pii_patterns` (built-ins keep their canonical
    /// names; operator extras are named `custom_<index>`).
    pii_pattern_names: Vec<String>,
    /// Whether PII detection in values is enabled.
    detect_pii: bool,
    /// Whether `Set-Cookie` / `ETag` / Authorization should be stripped on PII match.
    strip_session_on_pii_match: bool,
    /// Hard cap on the input length passed to the PII regex set.  Values
    /// longer than this skip the value-scan (still subject to name-based
    /// strip rules).  `0` disables the cap (operator opt-in; logged at
    /// startup).
    max_pii_scan_len: usize,
}

/// Default hard cap on the input length passed to the PII regex set.
/// Sized well above any legitimate header (8 KiB) but well below pathological
/// values an attacker could send to inflate regex backtracking cost.  The
/// runtime cap is operator-tunable via `PiiConfig::max_scan_bytes`; this
/// constant exists as a known reference value for tests asserting the
/// default.  The runtime path reads `self.max_pii_scan_len`.
#[cfg(test)]
const MAX_PII_SCAN_LEN: usize = 8 * 1024;

/// RFC 9110 §7.6.1 hop-by-hop headers.  Pingora handles these at the proxy
/// layer; stripping any of them from `should_strip` would break HTTP semantics
/// for the next hop.  Acts as a defensive allowlist so future const additions
/// cannot silently introduce that bug.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers that legitimately carry session / auth material.  When a PII
/// pattern matches one of these values, the strip is gated on
/// `HeaderFilterConfig::strip_session_headers_on_pii_match` — operator opt-in
/// avoids killing a user session on a false-positive.
const SESSION_PROTECTED_HEADERS: &[&str] = &["set-cookie", "etag", "authorization"];

// ── Server fingerprint headers (CVE-attributed) ─────────────────────────────
// Equifax 2017 / Apache Struts (CVE-2017-5638) — `Server: Apache/2.x.y` enabled
// targeted scans.  CVE-2017-7269 — IIS 6.0 WebDAV identified by
// `Server: Microsoft-IIS/6.0`.  CVE-2017-12617 — Tomcat PUT JSP RCE — the tell
// was `Server: Apache-Coyote/1.1`.  SharePoint / Liferay / PageSpeed leakage
// classes are bundled here for the same reason: they advertise the platform.
const SERVER_INFO_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "x-runtime",
    "x-version",
    "x-generator",
    "x-owa-version",
    "ms-author-via",
    "microsoftsharepointteamservices",
    "x-sharepointhealthscore",
    "liferay-portal",
    "x-mod-pagespeed",
    "x-page-speed",
];

// ── PHP fingerprint (CVE-2024-4577 PHP-CGI argument injection) ──────────────
// `X-Powered-By: PHP/x.y.z` is already covered by SERVER_INFO_HEADERS; this set
// covers PHP-specific extras some hosts add.
const PHP_FINGERPRINT_HEADERS: &[&str] = &["x-php-version", "x-php-response-code"];

// ── ASP.NET fingerprint (CVE-2017-7269 IIS WebDAV; ViewState attacks) ───────
const ASPNET_FINGERPRINT_HEADERS: &[&str] = &["x-aspnet-version", "x-aspnetmvc-version", "x-sourcefiles"];

// ── Framework / CMS fingerprint ─────────────────────────────────────────────
// CVE-2014-3704, CVE-2018-7600 (Drupalgeddon 1/2): X-Drupal-* enabled targeting.
// CVE-2022-22965 (Spring4Shell): X-Application-Context exposed Actuator.
// Magento bug-bounty class: X-Magento-Cache-Debug, X-Magento-Tags.
// WordPress XML-RPC discovery via X-Pingback.  Ruby Rack via X-Rack-Cache.
const FRAMEWORK_FINGERPRINT_HEADERS: &[&str] = &[
    "x-drupal-cache",
    "x-drupal-dynamic-cache",
    "x-magento-cache-debug",
    "x-magento-tags",
    "x-pingback",
    "x-application-context",
    "x-rack-cache",
];

// ── CDN / edge layer (origin / topology disclosure) ─────────────────────────
const CDN_INTERNAL_HEADERS: &[&str] = &[
    "x-served-by",
    "x-varnish",
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "x-fastly-request-id",
];
const CDN_INTERNAL_PREFIXES: &[&str] = &["x-akamai-"];

// ── Debug / internal prefixes ───────────────────────────────────────────────
const DEBUG_PREFIXES: &[&str] = &[
    "x-debug-",
    "x-internal-",
    "x-backend-",
    "x-real-ip",
    "x-forwarded-server",
];

// ── Error / exception (CWE-209) ─────────────────────────────────────────────
const ERROR_PREFIXES: &[&str] = &[
    "x-error-",
    "x-exception-",
    "x-stack-",
    "x-trace-",
    "x-application-trace-",
    "x-dotnet-version-",
];
const ERROR_EXACT_HEADERS: &[&str] = &["x-exception-class"];

impl HeaderFilter {
    /// Build a header filter from operator config.
    ///
    /// Returns an error when the config references unknown built-in PII
    /// pattern names (`disable_builtin`) or contains an invalid regex
    /// (`extra_patterns`).  The gateway logs the error and skips outbound
    /// filtering for the rest of the process lifetime — a misconfigured
    /// filter must never break the proxy.
    pub fn try_new(config: &HeaderFilterConfig) -> Result<Self, OutboundConfigError> {
        let mut strip_exact = HashSet::new();
        let mut strip_prefixes = Vec::new();

        if config.strip_server_info {
            for h in SERVER_INFO_HEADERS {
                strip_exact.insert((*h).to_string());
            }
        }

        if config.strip_php_fingerprint {
            for h in PHP_FINGERPRINT_HEADERS {
                strip_exact.insert((*h).to_string());
            }
        }

        if config.strip_aspnet_fingerprint {
            for h in ASPNET_FINGERPRINT_HEADERS {
                strip_exact.insert((*h).to_string());
            }
        }

        if config.strip_framework_fingerprint {
            for h in FRAMEWORK_FINGERPRINT_HEADERS {
                strip_exact.insert((*h).to_string());
            }
        }

        if config.strip_cdn_internal {
            for h in CDN_INTERNAL_HEADERS {
                strip_exact.insert((*h).to_string());
            }
            for p in CDN_INTERNAL_PREFIXES {
                strip_prefixes.push((*p).to_string());
            }
        }

        if config.strip_debug_headers {
            for p in DEBUG_PREFIXES {
                strip_prefixes.push((*p).to_string());
            }
        }

        if config.strip_error_detail {
            for p in ERROR_PREFIXES {
                strip_prefixes.push((*p).to_string());
            }
            for h in ERROR_EXACT_HEADERS {
                strip_exact.insert((*h).to_string());
            }
        }

        for h in &config.strip_headers {
            strip_exact.insert(h.to_lowercase());
        }
        for p in &config.strip_prefixes {
            strip_prefixes.push(p.to_lowercase());
        }

        let preserve_exact: HashSet<String> = config.preserve_headers.iter().map(|h| h.to_lowercase()).collect();
        let preserve_prefixes: Vec<String> = config.preserve_prefixes.iter().map(|p| p.to_lowercase()).collect();

        let (pii_patterns, pii_pattern_names) = if config.detect_pii_in_values {
            build_pii_patterns_filtered(&config.pii)?
        } else {
            (Vec::new(), Vec::new())
        };

        if config.detect_pii_in_values && config.pii.max_scan_bytes == 0 {
            warn!(
                "FR-035: outbound.headers.pii.max_scan_bytes = 0 — \
                 no per-value length cap; ReDoS DoS surface widened by operator choice"
            );
        }

        Ok(Self {
            strip_exact,
            strip_prefixes,
            preserve_exact,
            preserve_prefixes,
            pii_patterns,
            pii_pattern_names,
            detect_pii: config.detect_pii_in_values,
            strip_session_on_pii_match: config.strip_session_headers_on_pii_match,
            max_pii_scan_len: config.pii.max_scan_bytes,
        })
    }

    /// Check if a header name should be stripped.
    pub fn should_strip(&self, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }

        let lower = name.to_lowercase();

        // RFC 9110 §7.6.1 — hop-by-hop headers are reserved for proxy layer.
        if HOP_BY_HOP_HEADERS.contains(&lower.as_str()) {
            return false;
        }

        // Operator allowlist — beats every strip rule below.  CRLF strip
        // runs in `filter_headers` before this check, so preserve cannot
        // save a malformed header value (header-injection is never legitimate).
        if self.preserve_exact.contains(&lower) {
            return false;
        }
        if self.preserve_prefixes.iter().any(|p| lower.starts_with(p)) {
            return false;
        }

        if self.strip_exact.contains(&lower) {
            return true;
        }

        self.strip_prefixes.iter().any(|p| lower.starts_with(p))
    }

    /// Check if a header value contains PII. Returns the pattern name if found.
    pub fn detect_pii_in_value(&self, value: &str) -> Option<&str> {
        if !self.detect_pii {
            return None;
        }
        // Hard cap on regex input — closes ReDoS DoS surface on huge values.
        // `max_pii_scan_len = 0` disables the cap (operator opt-in).
        if self.max_pii_scan_len > 0 && value.len() > self.max_pii_scan_len {
            return None;
        }

        for (pattern, name) in self.pii_patterns.iter().zip(self.pii_pattern_names.iter()) {
            if pattern.is_match(value) {
                return Some(name.as_str());
            }
        }
        None
    }

    /// Filter response headers in-place. Returns list of stripped header names.
    pub fn filter_headers(&self, headers: &mut Vec<(String, String)>) -> Vec<String> {
        let mut stripped = Vec::new();

        headers.retain(|(name, value)| {
            // CRLF inside a value violates RFC 9110 §5.5 and is the response-
            // splitting / header-injection class (CWE-93, CVE-2017-1000026).
            // Treat as malicious regardless of whether the name is in any list.
            if has_crlf_injection(value) {
                warn!(
                    "Outbound: stripping header {} — CRLF in value (CWE-93 / RFC 9110 §5.5)",
                    name
                );
                stripped.push(format!("{name} (CRLF injection)"));
                return false;
            }

            if self.should_strip(name) {
                debug!("Stripping response header: {}", name);
                stripped.push(name.clone());
                return false;
            }

            if let Some(pii_type) = self.detect_pii_in_value(value) {
                let lower = name.to_lowercase();
                let is_session_protected = SESSION_PROTECTED_HEADERS.contains(&lower.as_str());
                if is_session_protected && !self.strip_session_on_pii_match {
                    // Operator did not opt in — preserve session-bearing
                    // header even on PII match.  Log only.
                    debug!(
                        "Outbound: PII pattern {} matched in {} but session-header strip disabled — preserving",
                        pii_type, name
                    );
                    return true;
                }
                debug!("PII detected in response header {}: {} pattern", name, pii_type);
                stripped.push(format!("{name} (PII: {pii_type})"));
                return false;
            }

            true
        });

        stripped
    }
}

/// CRLF inside any header value is a response-splitting / header-injection
/// signal.  RFC 9110 §5.5 forbids `CR` / `LF` in field-value.
fn has_crlf_injection(value: &str) -> bool {
    value.bytes().any(|b| b == b'\r' || b == b'\n')
}

/// Built-in PII detection patterns: stable name → regex source.
///
/// The name is the operator-facing identifier used in
/// `PiiConfig::disable_builtin`.  Names are stable across releases — adding
/// a new pattern is additive; renaming would be a breaking change.
const BUILTIN_PII_PATTERNS: &[(&str, &str)] = &[
    // Email
    ("email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    // Credit card (basic 13-19 digit)
    ("credit_card", r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b"),
    // US SSN
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
    // Phone number
    ("phone", r"\b\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    // Private IPv4
    (
        "ipv4_private",
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    ),
    // JWT — three base64url segments, header+payload start with `eyJ`
    ("jwt", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
    // AWS access key id (well-known prefix)
    ("aws_key", r"\bAKIA[0-9A-Z]{16}\b"),
    // Google API key (well-known prefix)
    ("google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    // Slack tokens (bot / user / app / refresh / legacy)
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    // GitHub fine-grained / classic PAT (gh{p,o,u,s,r}_…)
    ("github_pat", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
];

/// Stable names of all built-in PII patterns.  Test-only — runtime code
/// derives names directly from `BUILTIN_PII_PATTERNS` to avoid a second
/// source of truth that could drift.
#[cfg(test)]
const PII_PATTERN_NAMES: &[&str] = &[
    "email",
    "credit_card",
    "ssn",
    "phone",
    "ipv4_private",
    "jwt",
    "aws_key",
    "google_api_key",
    "slack_token",
    "github_pat",
];

/// Compile every built-in pattern.  Test-only helper — the runtime path
/// uses `build_pii_patterns_filtered` which respects operator config.
/// Compile failures of built-ins are bugs, not config errors — they are
/// logged and skipped to keep the engine fail-safe.
#[cfg(test)]
fn build_pii_patterns() -> Vec<Regex> {
    BUILTIN_PII_PATTERNS
        .iter()
        .filter_map(|(_, src)| match Regex::new(src) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::error!("Failed to compile PII pattern: {e}");
                None
            }
        })
        .collect()
}

/// Build the PII regex set tailored to operator config.
///
/// * Validates `disable_builtin` names — unknown names are a hard error.
/// * Skips disabled built-ins.
/// * Compiles `extra_patterns` — invalid regex is a hard error.
///
/// Returns `(regexes, names)` aligned 1:1; operator extras are named
/// `custom_<index>` so they surface in detection logs without leaking the
/// regex source.
fn build_pii_patterns_filtered(cfg: &PiiConfig) -> Result<(Vec<Regex>, Vec<String>), OutboundConfigError> {
    let valid_names: HashSet<&str> = BUILTIN_PII_PATTERNS.iter().map(|(n, _)| *n).collect();
    for name in &cfg.disable_builtin {
        if !valid_names.contains(name.as_str()) {
            return Err(OutboundConfigError::UnknownPiiPattern {
                name: name.clone(),
                valid: BUILTIN_PII_PATTERNS.iter().map(|(n, _)| *n).collect(),
            });
        }
    }
    let disabled: HashSet<&str> = cfg.disable_builtin.iter().map(String::as_str).collect();

    let total = BUILTIN_PII_PATTERNS.len() + cfg.extra_patterns.len();
    let mut regexes: Vec<Regex> = Vec::with_capacity(total);
    let mut names: Vec<String> = Vec::with_capacity(total);

    for (name, src) in BUILTIN_PII_PATTERNS {
        if disabled.contains(*name) {
            continue;
        }
        match Regex::new(src) {
            Ok(r) => {
                regexes.push(r);
                names.push((*name).to_string());
            }
            Err(e) => {
                tracing::error!("FR-035 built-in PII pattern '{name}' failed to compile: {e}");
            }
        }
    }

    for (i, src) in cfg.extra_patterns.iter().enumerate() {
        let r = Regex::new(src).map_err(|e| OutboundConfigError::InvalidExtraPattern {
            index: i,
            message: e.to_string(),
        })?;
        regexes.push(r);
        names.push(format!("custom_{i}"));
    }

    Ok((regexes, names))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_filter() -> HeaderFilter {
        HeaderFilter::try_new(&HeaderFilterConfig::default()).expect("default config must build")
    }

    fn pii_filter() -> HeaderFilter {
        HeaderFilter::try_new(&HeaderFilterConfig {
            detect_pii_in_values: true,
            ..Default::default()
        })
        .expect("pii filter must build")
    }

    fn pii_filter_with_session_strip() -> HeaderFilter {
        HeaderFilter::try_new(&HeaderFilterConfig {
            detect_pii_in_values: true,
            strip_session_headers_on_pii_match: true,
            ..Default::default()
        })
        .expect("pii session-strip filter must build")
    }

    #[test]
    fn test_strip_server_info() {
        let f = default_filter();
        assert!(f.should_strip("Server"));
        assert!(f.should_strip("X-Powered-By"));
        // X-AspNet-Version is now under strip_aspnet_fingerprint, on by default.
        assert!(f.should_strip("x-aspnet-version"));
    }

    #[test]
    fn test_strip_debug_headers() {
        let f = default_filter();
        assert!(f.should_strip("X-Debug-Token"));
        assert!(f.should_strip("x-internal-request-id"));
        assert!(f.should_strip("X-Backend-Server"));
    }

    #[test]
    fn test_strip_error_headers() {
        let f = default_filter();
        assert!(f.should_strip("X-Error-Message"));
        assert!(f.should_strip("x-exception-type"));
        assert!(f.should_strip("X-Stack-Trace"));
    }

    #[test]
    fn test_keep_normal_headers() {
        let f = default_filter();
        assert!(!f.should_strip("Content-Type"));
        assert!(!f.should_strip("Cache-Control"));
        assert!(!f.should_strip("X-Request-Id"));
    }

    #[test]
    fn test_pii_detection_email() {
        let f = pii_filter();
        assert!(f.detect_pii_in_value("user@example.com").is_some());
    }

    #[test]
    fn test_pii_detection_private_ip() {
        let f = pii_filter();
        assert!(f.detect_pii_in_value("10.0.1.50").is_some());
        assert!(f.detect_pii_in_value("192.168.1.1").is_some());
        assert!(f.detect_pii_in_value("8.8.8.8").is_none());
    }

    #[test]
    fn test_pii_detection_disabled_by_default() {
        let f = default_filter();
        assert!(f.detect_pii_in_value("user@example.com").is_none());
        assert!(f.detect_pii_in_value("10.0.1.50").is_none());
    }

    #[test]
    fn test_custom_strip_headers() {
        let config = HeaderFilterConfig {
            strip_headers: vec!["X-Custom-Secret".to_string()],
            ..Default::default()
        };
        let f = HeaderFilter::try_new(&config).expect("must build");
        assert!(f.should_strip("x-custom-secret"));
    }

    #[test]
    fn test_filter_headers_in_place() {
        let f = default_filter();
        let mut headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Server".to_string(), "nginx/1.25".to_string()),
            ("X-Debug-Token".to_string(), "abc123".to_string()),
            ("X-Request-Id".to_string(), "req-001".to_string()),
        ];
        let stripped = f.filter_headers(&mut headers);
        assert_eq!(headers.len(), 2);
        let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"Content-Type"));
        assert!(names.contains(&"X-Request-Id"));
        assert!(stripped.contains(&"Server".to_string()));
        assert!(stripped.contains(&"X-Debug-Token".to_string()));
    }

    // RFC 9110 §5.1 — header names are case-insensitive.
    #[test]
    fn test_strip_is_case_insensitive() {
        let f = default_filter();
        assert!(f.should_strip("SERVER"));
        assert!(f.should_strip("server"));
        assert!(f.should_strip("Server"));
        assert!(f.should_strip("X-DEBUG-TOKEN"));
        assert!(f.should_strip("x-debug-token"));
    }

    // Critical: stripping must NOT remove security-relevant response headers.
    #[test]
    fn test_preserve_security_headers() {
        let f = default_filter();
        for h in [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ] {
            assert!(!f.should_strip(h), "must preserve {h}");
        }
    }

    #[test]
    fn test_preserve_content_headers() {
        let f = default_filter();
        for h in ["Content-Type", "Content-Length", "Content-Encoding", "Content-Language"] {
            assert!(!f.should_strip(h), "must preserve {h}");
        }
    }

    #[test]
    fn test_preserve_cache_headers() {
        let f = default_filter();
        for h in ["Cache-Control", "Last-Modified", "Vary", "Expires", "Age"] {
            assert!(!f.should_strip(h), "must preserve {h}");
        }
        // ETag is preserved by default — only stripped on PII match when operator opts in.
        assert!(!f.should_strip("ETag"));
    }

    #[test]
    fn test_custom_prefix_only_when_configured() {
        let default = default_filter();
        assert!(!default.should_strip("X-Foo-Bar"));

        let configured = HeaderFilter::try_new(&HeaderFilterConfig {
            strip_prefixes: vec!["x-foo-".to_string()],
            ..Default::default()
        })
        .expect("must build");
        assert!(configured.should_strip("X-Foo-Bar"));
        assert!(configured.should_strip("x-foo-something"));
    }

    #[test]
    fn test_filter_headers_returns_stripped_names() {
        let f = default_filter();
        let mut headers = vec![
            ("Server".to_string(), "nginx".to_string()),
            ("X-Debug-A".to_string(), "1".to_string()),
            ("X-Debug-B".to_string(), "2".to_string()),
        ];
        let stripped = f.filter_headers(&mut headers);
        assert_eq!(stripped.len(), 3);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_empty_headers_no_panic() {
        let f = default_filter();
        let mut headers: Vec<(String, String)> = Vec::new();
        let stripped = f.filter_headers(&mut headers);
        assert!(stripped.is_empty());
        assert!(headers.is_empty());
    }

    #[test]
    fn test_long_header_value_no_redos() {
        // 10 KiB value — must process under ~5 ms; with the 8 KiB cap it is
        // a constant-time skip, so the timing budget is generous.
        let f = pii_filter();
        let value = "a".repeat(10_000);
        let start = std::time::Instant::now();
        let _ = f.detect_pii_in_value(&value);
        assert!(
            start.elapsed().as_millis() < 100,
            "PII scan on 10 KiB took {} ms",
            start.elapsed().as_millis()
        );
    }

    #[test]
    fn test_jwt_in_header_value_detected() {
        let f = pii_filter();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dummysig";
        assert_eq!(f.detect_pii_in_value(jwt), Some("jwt"));
    }

    #[test]
    fn test_clean_value_no_pii_match() {
        let f = pii_filter();
        assert!(f.detect_pii_in_value("abc-123-XYZ").is_none());
        assert!(f.detect_pii_in_value("nginx/1.25").is_none());
    }

    // ─── New tests (FR-035 detection hardening) ─────────────────────────────

    // CVE-2024-4577 — PHP-CGI argument injection.  Banner exposure
    // (`X-PHP-Version`) enabled targeted exploitation in the wild.
    #[test]
    fn test_php_fingerprint_stripped() {
        let f = default_filter();
        assert!(f.should_strip("X-PHP-Version"));
        assert!(f.should_strip("x-php-response-code"));

        let off = HeaderFilter::try_new(&HeaderFilterConfig {
            strip_php_fingerprint: false,
            strip_server_info: false,
            ..Default::default()
        })
        .expect("must build");
        assert!(!off.should_strip("X-PHP-Version"));
    }

    // CVE-2017-7269 — IIS 6.0 WebDAV.  ViewState attacks rely on .NET version.
    #[test]
    fn test_aspnet_fingerprint_stripped() {
        let f = default_filter();
        assert!(f.should_strip("X-AspNet-Version"));
        assert!(f.should_strip("X-AspNetMvc-Version"));
        assert!(f.should_strip("X-SourceFiles"));

        let off = HeaderFilter::try_new(&HeaderFilterConfig {
            strip_aspnet_fingerprint: false,
            strip_server_info: false,
            ..Default::default()
        })
        .expect("must build");
        assert!(!off.should_strip("X-AspNet-Version"));
    }

    // CVE-2014-3704 / CVE-2018-7600 (Drupalgeddon 1/2).
    #[test]
    fn test_drupal_fingerprint_stripped() {
        let f = default_filter();
        assert!(f.should_strip("X-Drupal-Cache"));
        assert!(f.should_strip("X-Drupal-Dynamic-Cache"));
    }

    // CVE-2022-22965 (Spring4Shell) — Spring Boot Actuator presence.
    #[test]
    fn test_spring_actuator_fingerprint_stripped() {
        let f = default_filter();
        assert!(f.should_strip("X-Application-Context"));
    }

    // WordPress XML-RPC discovery class.
    #[test]
    fn test_wordpress_pingback_stripped() {
        let f = default_filter();
        assert!(f.should_strip("X-Pingback"));
    }

    // CDN / edge headers — stripped by default in this deployment shape
    // (WAF is the public edge; any CDN header in upstream = topology leak).
    #[test]
    fn test_cdn_internal_stripped_by_default() {
        let f = default_filter();
        assert!(f.should_strip("X-Varnish"));
        assert!(f.should_strip("X-Amz-Cf-Id"));
        assert!(f.should_strip("X-Amz-Cf-Pop"));
        assert!(f.should_strip("X-Akamai-Edgescape"));
        assert!(f.should_strip("X-Fastly-Request-Id"));

        let off = HeaderFilter::try_new(&HeaderFilterConfig {
            strip_cdn_internal: false,
            ..Default::default()
        })
        .expect("must build");
        assert!(!off.should_strip("X-Varnish"));
        assert!(!off.should_strip("X-Akamai-Edgescape"));
    }

    // PII pattern additions — token-shape detection.
    #[test]
    fn test_pii_aws_access_key_detected() {
        let f = pii_filter();
        assert_eq!(f.detect_pii_in_value("AKIAIOSFODNN7EXAMPLE"), Some("aws_key"));
    }

    #[test]
    fn test_pii_slack_token_detected() {
        let f = pii_filter();
        assert_eq!(f.detect_pii_in_value("xoxb-1234567890-abcdefghij"), Some("slack_token"));
    }

    #[test]
    fn test_pii_github_pat_detected() {
        let f = pii_filter();
        let pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(f.detect_pii_in_value(pat), Some("github_pat"));
    }

    // Guard against zip-misalignment between names and pattern set.
    #[test]
    fn test_pii_pattern_names_match_pattern_count() {
        assert_eq!(build_pii_patterns().len(), PII_PATTERN_NAMES.len());
    }

    // CVE-2017-1000026 (Tomcat HTTP response splitting via CRLF in value).
    #[test]
    fn test_crlf_in_value_stripped() {
        let f = default_filter();
        let mut headers = vec![
            ("X-Request-Id".to_string(), "ok".to_string()),
            ("X-Foo".to_string(), "bar\r\nX-Injected: evil".to_string()),
        ];
        let stripped = f.filter_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.first().map(|(n, _)| n.as_str()), Some("X-Request-Id"));
        assert!(stripped.iter().any(|s| s.contains("CRLF injection")));
    }

    // 8 KiB hard cap on PII regex input — closes ReDoS DoS surface.
    #[test]
    fn test_pii_scan_skipped_above_cap() {
        let f = pii_filter();
        // At cap: pattern can match.
        let at_cap = format!("{}{}", "x".repeat(MAX_PII_SCAN_LEN - 30), "user@example.com");
        assert!(f.detect_pii_in_value(&at_cap).is_some());

        // Above cap: scan skipped, returns None even when pattern is present.
        let above_cap = format!("{}{}", "x".repeat(MAX_PII_SCAN_LEN + 1), "user@example.com");
        assert!(f.detect_pii_in_value(&above_cap).is_none());
    }

    // RFC 9110 §7.6.1 — hop-by-hop headers must never be stripped.
    #[test]
    fn test_hop_by_hop_never_stripped() {
        let f = default_filter();
        for h in [
            "Connection",
            "Keep-Alive",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
        ] {
            assert!(!f.should_strip(h), "hop-by-hop must be preserved: {h}");
        }
    }

    #[test]
    fn test_empty_name_no_panic() {
        let f = default_filter();
        assert!(!f.should_strip(""));
        let mut headers = vec![(String::new(), "v".to_string())];
        let stripped = f.filter_headers(&mut headers);
        assert!(stripped.is_empty());
        assert_eq!(headers.len(), 1);
    }

    // RFC 9110 §5.2 — multi-instance headers (e.g. a backend that emits
    // X-Forwarded-Server twice) must all be evaluated; current behaviour:
    // X-Forwarded-Server is in DEBUG_PREFIXES so both instances strip.
    #[test]
    fn test_multi_instance_x_forwarded_server_all_stripped() {
        let f = default_filter();
        let mut headers = vec![
            ("X-Forwarded-Server".to_string(), "10.0.0.1".to_string()),
            ("X-Forwarded-Server".to_string(), "10.0.0.2".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let stripped = f.filter_headers(&mut headers);
        assert_eq!(stripped.len(), 2);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.first().map(|(n, _)| n.as_str()), Some("Content-Type"));
    }

    // Default policy: do NOT strip Set-Cookie on PII match — operator did
    // not opt in, so a regex false-positive should not kill the user session.
    #[test]
    fn test_setcookie_preserved_on_pii_match_by_default() {
        let f = pii_filter();
        let mut headers = vec![(
            "Set-Cookie".to_string(),
            "session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig; HttpOnly".to_string(),
        )];
        let stripped = f.filter_headers(&mut headers);
        assert!(stripped.is_empty());
        assert_eq!(headers.len(), 1);
    }

    // Operator opt-in: with both detect_pii AND strip_session_headers_on_pii_match
    // ON, Set-Cookie carrying a JWT-shaped value is stripped.
    #[test]
    fn test_setcookie_stripped_when_operator_opts_in() {
        let f = pii_filter_with_session_strip();
        let mut headers = vec![(
            "Set-Cookie".to_string(),
            "session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig; HttpOnly".to_string(),
        )];
        let stripped = f.filter_headers(&mut headers);
        assert_eq!(stripped.len(), 1);
        assert!(headers.is_empty());
    }

    // Spring Boot ETag = SHA(classpath) leak class — preserved by default.
    #[test]
    fn test_etag_preserved_on_pii_match_by_default() {
        let f = pii_filter();
        let mut headers = vec![("ETag".to_string(), "\"akey=AKIAIOSFODNN7EXAMPLE\"".to_string())];
        let stripped = f.filter_headers(&mut headers);
        assert!(stripped.is_empty());
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn test_etag_stripped_when_operator_opts_in() {
        let f = pii_filter_with_session_strip();
        let mut headers = vec![("ETag".to_string(), "\"akey=AKIAIOSFODNN7EXAMPLE\"".to_string())];
        let stripped = f.filter_headers(&mut headers);
        assert_eq!(stripped.len(), 1);
        assert!(headers.is_empty());
    }

    // Echoed-token class — Authorization in response (rare backend bug).
    #[test]
    fn test_authorization_preserved_on_pii_match_by_default() {
        let f = pii_filter();
        let mut headers = vec![(
            "Authorization".to_string(),
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig".to_string(),
        )];
        let stripped = f.filter_headers(&mut headers);
        assert!(stripped.is_empty());
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn test_user_strip_headers_extends_built_ins() {
        let f = HeaderFilter::try_new(&HeaderFilterConfig {
            strip_headers: vec!["X-Custom-Bug".to_string()],
            ..Default::default()
        })
        .expect("must build");
        // Built-in still active.
        assert!(f.should_strip("Server"));
        // User extension active.
        assert!(f.should_strip("x-custom-bug"));
    }

    // ─── FR-035 granular config: preserve allowlist + PII tuning ────────────

    // Operator wants `Server` exposed (e.g. proxying a public artifact server)
    // but otherwise wants the rest of the server-info family stripped.
    #[test]
    fn test_preserve_headers_overrides_family_strip() {
        let f = HeaderFilter::try_new(&HeaderFilterConfig {
            preserve_headers: vec!["server".to_string()],
            ..Default::default()
        })
        .expect("must build");
        assert!(!f.should_strip("Server"), "preserve must beat strip_server_info");
        assert!(f.should_strip("X-Powered-By"), "other family members still strip");
    }

    // Operator's own extras list collides with their own allowlist — the
    // allowlist must win (most specific intent).
    #[test]
    fn test_preserve_headers_overrides_operator_extras() {
        let f = HeaderFilter::try_new(&HeaderFilterConfig {
            strip_headers: vec!["x-foo".to_string()],
            preserve_headers: vec!["x-foo".to_string()],
            ..Default::default()
        })
        .expect("must build");
        assert!(!f.should_strip("X-Foo"));
    }

    // Prefix-form allowlist must carve out a sub-tree of an active prefix family.
    #[test]
    fn test_preserve_prefixes_overrides_family_prefix_strip() {
        let f = HeaderFilter::try_new(&HeaderFilterConfig {
            preserve_prefixes: vec!["x-debug-trace-".to_string()],
            ..Default::default()
        })
        .expect("must build");
        assert!(
            !f.should_strip("X-Debug-Trace-Id"),
            "preserve_prefixes must beat strip_debug_headers"
        );
        assert!(
            f.should_strip("X-Debug-Token"),
            "non-preserved members of the debug family still strip"
        );
    }

    // RFC 9110 §5.1 — header names case-insensitive; preserve must follow.
    #[test]
    fn test_preserve_is_case_insensitive() {
        let f = HeaderFilter::try_new(&HeaderFilterConfig {
            preserve_headers: vec!["SERVER".to_string()],
            ..Default::default()
        })
        .expect("must build");
        assert!(!f.should_strip("server"));
        assert!(!f.should_strip("Server"));
        assert!(!f.should_strip("SERVER"));
    }

    // Allowlist must NOT save a CRLF-injected header.  Header-injection is
    // never legitimate; CRLF strip runs before name-based rules.
    #[test]
    fn test_preserve_does_not_save_crlf_injection() {
        let f = HeaderFilter::try_new(&HeaderFilterConfig {
            preserve_headers: vec!["server".to_string()],
            ..Default::default()
        })
        .expect("must build");
        let mut headers = vec![
            ("Server".to_string(), "ok\r\nX-Evil: 1".to_string()),
            ("X-Request-Id".to_string(), "req-1".to_string()),
        ];
        let stripped = f.filter_headers(&mut headers);
        assert!(
            stripped.iter().any(|s| s.contains("CRLF injection")),
            "CRLF beats preserve"
        );
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.first().map(|(n, _)| n.as_str()), Some("X-Request-Id"));
    }

    // Hop-by-hop headers stay non-stripped regardless of any preserve config —
    // regression guard so adding preserve logic does not change RFC behaviour.
    #[test]
    fn test_preserve_does_not_alter_hop_by_hop() {
        let f = HeaderFilter::try_new(&HeaderFilterConfig {
            preserve_headers: vec!["connection".to_string()],
            ..Default::default()
        })
        .expect("must build");
        for h in ["Connection", "Transfer-Encoding", "Upgrade", "TE"] {
            assert!(!f.should_strip(h), "hop-by-hop must remain non-stripped: {h}");
        }
    }

    // disable_builtin removes only the named pattern; others still active.
    #[test]
    fn test_pii_disable_builtin_removes_only_named_pattern() {
        let f = HeaderFilter::try_new(&HeaderFilterConfig {
            detect_pii_in_values: true,
            pii: waf_common::config::PiiConfig {
                disable_builtin: vec!["email".to_string()],
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("must build");
        assert!(
            f.detect_pii_in_value("user@example.com").is_none(),
            "disabled pattern must not match"
        );
        assert_eq!(
            f.detect_pii_in_value("AKIAIOSFODNN7EXAMPLE"),
            Some("aws_key"),
            "other patterns remain active"
        );
    }

    // Unknown pattern names in disable_builtin → constructor error so the
    // operator notices the typo at startup instead of silently shipping an
    // unintended detection set.
    #[test]
    fn test_pii_disable_builtin_unknown_name_errors() {
        let err = HeaderFilter::try_new(&HeaderFilterConfig {
            detect_pii_in_values: true,
            pii: waf_common::config::PiiConfig {
                disable_builtin: vec!["bogus".to_string()],
                ..Default::default()
            },
            ..Default::default()
        })
        .expect_err("unknown name must error");
        match err {
            OutboundConfigError::UnknownPiiPattern { name, .. } => assert_eq!(name, "bogus"),
            other @ OutboundConfigError::InvalidExtraPattern { .. } => {
                panic!("expected UnknownPiiPattern, got {other:?}")
            }
        }
    }

    // Operator-supplied regex extends detection without code change.
    #[test]
    fn test_pii_extra_patterns_adds_custom_detection() {
        let f = HeaderFilter::try_new(&HeaderFilterConfig {
            detect_pii_in_values: true,
            pii: waf_common::config::PiiConfig {
                extra_patterns: vec![r"\bSECRET-\w+\b".to_string()],
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("must build");
        assert_eq!(f.detect_pii_in_value("SECRET-ABC123"), Some("custom_0"));
    }

    // Invalid extra regex → constructor error so the proxy fails fast on
    // misconfig instead of silently dropping a pattern the operator wanted.
    #[test]
    fn test_pii_extra_patterns_invalid_regex_errors() {
        let err = HeaderFilter::try_new(&HeaderFilterConfig {
            detect_pii_in_values: true,
            pii: waf_common::config::PiiConfig {
                extra_patterns: vec!["[unterminated".to_string()],
                ..Default::default()
            },
            ..Default::default()
        })
        .expect_err("invalid regex must error");
        match err {
            OutboundConfigError::InvalidExtraPattern { index, .. } => assert_eq!(index, 0),
            other @ OutboundConfigError::UnknownPiiPattern { .. } => {
                panic!("expected InvalidExtraPattern, got {other:?}")
            }
        }
    }

    // Operator opts out of the DoS cap (e.g. for a controlled internal
    // deployment) — values larger than the default 8 KiB are still scanned.
    #[test]
    fn test_pii_max_scan_bytes_zero_disables_cap() {
        let f = HeaderFilter::try_new(&HeaderFilterConfig {
            detect_pii_in_values: true,
            pii: waf_common::config::PiiConfig {
                max_scan_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("must build");
        // 100 KiB header value embedding an email — would skip with default cap.
        let value = format!("{}{}", "x".repeat(100_000), "user@example.com");
        assert!(f.detect_pii_in_value(&value).is_some());
    }

    // Lower cap shrinks the scan window even below the default.
    #[test]
    fn test_pii_max_scan_bytes_low_cap_skips_long_values() {
        let f = HeaderFilter::try_new(&HeaderFilterConfig {
            detect_pii_in_values: true,
            pii: waf_common::config::PiiConfig {
                max_scan_bytes: 100,
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("must build");
        // 200-byte value containing an email — cap 100 → skipped.
        let value = format!("{}{}", "x".repeat(180), "u@e.co");
        assert!(f.detect_pii_in_value(&value).is_none());
    }
}
