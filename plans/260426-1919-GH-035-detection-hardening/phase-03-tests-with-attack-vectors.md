# Phase 03 — Tests Replaying Real-World Attack Vectors

**Priority:** P0
**Status:** pending
**Depends on:** phase-02

## Goal

Lock the new detection cases and hardening behind regression tests that mirror real CVE / bug-bounty / public-incident patterns. Naming convention: each test cites the incident class it guards against. Adds **≥ 14** new tests on top of PR-14's 19; total target ≥ 33.

## File

**Modify:**
- `crates/waf-engine/src/outbound/header_filter.rs` — extend `#[cfg(test)] mod tests`

No new test files. Stays surgical.

## Test Catalogue

### CVE-attributed family tests

| # | Name | Asserts | Vector reference |
|---|------|---------|------------------|
| 20 | `test_php_fingerprint_stripped` | `X-PHP-Version: 8.1.0` and `X-PHP-Response-Code: 200` stripped under `strip_php_fingerprint=true`; preserved when set false | CVE-2024-4577 (banner enabled targeting) |
| 21 | `test_aspnet_fingerprint_stripped` | `X-AspNet-Version: 4.0.30319`, `X-AspNetMvc-Version: 5.2`, `X-SourceFiles: =?UTF-8?B?...` stripped | CVE-2017-7269; ViewState attacks |
| 22 | `test_drupal_fingerprint_stripped` | `X-Drupal-Cache: HIT` and `X-Drupal-Dynamic-Cache: MISS` stripped under default | Drupalgeddon CVE-2014-3704 / CVE-2018-7600 |
| 23 | `test_spring_actuator_fingerprint_stripped` | `X-Application-Context: myapp:prod:8080` stripped under default | CVE-2022-22965 Spring4Shell — Actuator presence |
| 24 | `test_wordpress_pingback_stripped` | `X-Pingback: https://target/xmlrpc.php` stripped under default | WordPress XML-RPC discovery class |
| 25 | `test_cdn_internal_stripped_by_default` | `X-Varnish: 1234`, `X-Amz-Cf-Id: abc`, `X-Akamai-Edgescape: foo` STRIPPED under default (WAF is public edge — CDN headers are upstream leakage); PRESERVED when `strip_cdn_internal=false` | Origin / backend infrastructure topology disclosure |

### PII pattern additions

| # | Name | Asserts | Vector |
|---|------|---------|--------|
| 26 | `test_pii_aws_access_key_detected` | `AKIAIOSFODNN7EXAMPLE` matches `aws_key` pattern | S3-creds-in-headers leakage class |
| 27 | `test_pii_slack_token_detected` | `xoxb-1234-abcd-...` matches `slack_token` | Bug-bounty token leak class |
| 28 | `test_pii_github_pat_detected` | `ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` matches `github_pat` | GitHub token leakage |
| 29 | `test_pii_pattern_names_match_pattern_count` | `build_pii_patterns().len() == PII_PATTERN_NAMES.len()` | Guard against zip-misalignment footgun |

### Hardening / edge-case tests

| # | Name | Asserts | Vector |
|---|------|---------|--------|
| 30 | `test_crlf_in_value_stripped` | A header with value `"foo\r\nX-Injected: bar"` is removed by `filter_headers`; stripped list contains its name | CVE-2017-1000026 Tomcat response splitting |
| 31 | `test_pii_scan_skipped_above_cap` | `detect_pii_in_value` on a 9 KiB string containing a JWT-shaped substring returns `None`; on 8 KiB returns `Some` | ReDoS DoS surface |
| 32 | `test_hop_by_hop_never_stripped` | `should_strip` returns false for `Connection`, `Transfer-Encoding`, `Upgrade`, `TE`, `Trailer`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization` | RFC 9110 §7.6.1 |
| 33 | `test_empty_name_no_panic` | `should_strip("")` returns false; `filter_headers` over `[("", "v")]` returns the pair unchanged | Defensive |
| 34 | `test_multi_instance_x_forwarded_for_all_stripped` | `vec![("X-Forwarded-For","10.0.0.1"), ("X-Forwarded-For","10.0.0.2")]` — both stripped under `strip_debug_headers=true` (existing prefix `x-forwarded-server` does NOT cover `x-forwarded-for`; either extend prefix list or assert preservation — pick the truthful behaviour and document) | RFC §5.2 |
| 35 | `test_setcookie_preserved_on_pii_match_by_default` | `Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig; HttpOnly` PRESERVED with `detect_pii_in_values=true` and `strip_session_headers_on_pii_match=false` (default) | Avoid killing session on regex false-positive |
| 35b | `test_setcookie_stripped_when_operator_opts_in` | Same Set-Cookie value STRIPPED when both `detect_pii_in_values=true` AND `strip_session_headers_on_pii_match=true` | Auth-token leak class — operator opt-in |
| 36 | `test_etag_preserved_on_pii_match_by_default` | `ETag: "akey=AKIAIOSFODNN7EXAMPLE"` PRESERVED under default; STRIPPED only with `strip_session_headers_on_pii_match=true` | Spring Boot ETag = classpath SHA leak class — operator opt-in |
| 36b | `test_authorization_preserved_on_pii_match_by_default` | `Authorization: Bearer eyJ...` PRESERVED under default; STRIPPED with operator opt-in | Echoed-token class |

### Sanity tests

| # | Name | Asserts |
|---|------|---------|
| 37 | `test_disabling_php_toggle_preserves_php_fingerprint` | With `strip_php_fingerprint=false` AND `strip_server_info=false`, `X-PHP-Version` preserved |
| 38 | `test_user_strip_headers_extends_built_ins` | Built-ins still strip + `strip_headers=["X-Custom-Bug"]` adds custom; both stripped |

## Test Skeleton (one example to anchor style)

```rust
// CVE-2024-4577 — PHP-CGI argument injection
// Banner exposure (X-PHP-Version) enabled targeted exploitation.
#[test]
fn test_php_fingerprint_stripped() {
    let f = HeaderFilter::new(&HeaderFilterConfig::default());
    assert!(f.should_strip("X-PHP-Version"));
    assert!(f.should_strip("x-php-response-code"));

    let off = HeaderFilter::new(&HeaderFilterConfig {
        strip_php_fingerprint: false,
        strip_server_info: false,
        ..Default::default()
    });
    assert!(!off.should_strip("X-PHP-Version"));
}
```

## Implementation Steps

1. **Append** the test functions per the catalogue above into the existing `tests` module in `header_filter.rs`.
2. **Decision for test 34** — current `DEBUG_PREFIXES` includes `x-real-ip`, `x-forwarded-server`, but NOT `x-forwarded-for`. `X-Forwarded-For` is request-side header, rarely on responses. Plan: do NOT add `x-forwarded-for` to default prefixes; the test asserts the **truthful** behaviour (preserved by default; stripped if operator adds `x-forwarded-for` to `strip_prefixes`). Document in test comment.
3. **Run** `cargo test -p waf-engine outbound::` — expect 31+ green tests.
4. **Run** `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
5. **Run** `cargo fmt --all`.

## Verification

- `cargo test -p waf-engine outbound::` reports ≥ 31 passing.
- `cargo clippy ... -D warnings` clean.
- `cargo fmt --all -- --check` clean.
- Each test name self-documents the vector it guards against (no test rot).

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Test 34 surprises a reviewer who expects X-Forwarded-For to be in defaults | Test comment cites RFC reasoning + points to operator override |
| Timing-based test 31 (size cap) flaky on slow CI | Test asserts only return-value (`None` vs `Some`), not wall-clock time |
| Slack/GitHub token regex matches a long but innocuous string | Patterns include the well-known prefix tokens (`xoxb-`, `ghp_`, etc.) — false-positive surface is small; document |

## Success Criteria

- [ ] ≥ 14 new tests added (tests 20-38 + the two `b` variants above), all passing
- [ ] Existing 19 tests still passing — total ≥ 33
- [ ] `cargo clippy ... -D warnings` clean
- [ ] `cargo fmt --check` clean
- [ ] No new test names hint at "AI" / "LLM" / planning context — they read like a security engineer wrote them

## Next

→ phase-04-update-pr-14.md
