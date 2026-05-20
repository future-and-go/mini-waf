// Tests for the `category_of(rule_id TEXT)` SQL function introduced in
// migration 0011_category_function.sql.
//
// Each WHEN branch in the CASE expression is covered by at least one positive
// assertion. Prefix-ordering cases (longer prefix must win over shorter) are
// explicitly tested: CRS-RESP > CRS-, ADV-SSRF/ADV-SSTI > ADV-,
// API-MASS > API-, MODSEC-RESP > MODSEC-. SSRF-* (bare prefix, emitted by
// `crates/waf-engine/src/checks/ssrf.rs::99`) and ADV-SSRF-* both map to
// 'ssrf' — they are distinct branches that must both fire.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods
)]

#[path = "common/mod.rs"]
mod common;

use common::start_postgres;

#[tokio::test(flavor = "multi_thread")]
async fn category_of_covers_all_prefixes() {
    let fx = start_postgres().await;

    // (rule_id, expected_category)
    // NULL is represented as Option<&str> = None.
    let cases: &[(Option<&str>, &str)] = &[
        // ── Basic prefixes ──────────────────────────────────────────────────
        (Some("SQLI-001"), "sqli"),
        (Some("XSS-42"), "xss"),
        (Some("RCE-X"), "rce"),
        (Some("TRAV-1"), "path-traversal"),
        (Some("SCAN-1"), "scanner"),
        (Some("BOT-1"), "bot"),
        (Some("CC-DDOS-1"), "cc-ddos"),
        // ── SSRF: bare prefix from crates/waf-engine/src/checks/ssrf.rs:99
        (Some("SSRF-001"), "ssrf"),
        (Some("SSRF-99"), "ssrf"),
        // ── ADV ordering: longer prefix (SSRF/SSTI) fires before generic ADV-
        (Some("ADV-SSRF-001"), "ssrf"),
        (Some("ADV-SSTI-001"), "ssti"),
        (Some("ADV-OTHER-1"), "advanced"), // generic ADV-* fallback
        // ── CRS ordering: CRS-RESP fires before generic CRS-
        (Some("CRS-RESP-1"), "data-leakage"),
        (Some("CRS-942100"), "owasp-crs"), // generic CRS-* fallback
        // ── API ordering: API-MASS fires before generic API-
        (Some("API-MASS-1"), "mass-assignment"),
        (Some("API-OTHER-1"), "api-security"), // generic API-* fallback
        // ── MODSEC ordering: MODSEC-RESP fires before generic MODSEC-
        (Some("MODSEC-RESP-1"), "web-shell"),
        (Some("MODSEC-OTHER-1"), "modsecurity"), // generic MODSEC-* fallback
        // ── Remaining simple prefixes ────────────────────────────────────────
        (Some("CVE-2024-1234"), "cve"),
        (Some("GEO-VN"), "geo-blocking"),
        (Some("CUSTOM-1"), "custom"),
        (Some("IP-1"), "ip-rule"),
        (Some("URL-1"), "url-rule"),
        (Some("SENS-1"), "sensitive-data"),
        (Some("HOTLINK-1"), "anti-hotlink"),
        // ── OWASP sub-prefix mapping ─────────────────────────────────────────
        (Some("OWASP-942100"), "sqli"),
        (Some("OWASP-941100"), "xss"),
        (Some("OWASP-930100"), "lfi"),
        (Some("OWASP-931100"), "rfi"),
        (Some("OWASP-932100"), "rce"),
        (Some("OWASP-933100"), "php-injection"),
        (Some("OWASP-913100"), "scanner"),
        // ── Fallback to 'other' ───────────────────────────────────────────────
        (Some("OWASP-999999"), "other"), // OWASP with unrecognised number
        (Some("UNKNOWN-X"), "other"),    // completely unknown prefix
        (Some(""), "other"),             // empty string
        (None, "other"),                 // NULL rule_id
    ];

    for (rule_id, want) in cases {
        let row: (String,) = sqlx::query_as("SELECT category_of($1)")
            .bind(*rule_id)
            .fetch_one(fx.db.pool())
            .await
            .expect("category_of query"); // #[cfg(test)] context
        assert_eq!(&row.0, want, "rule_id={rule_id:?}");
    }
}
