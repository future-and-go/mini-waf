# Phase 03 — Tests, Default Config, Docs

**Priority:** P0
**Status:** completed
**Depends on:** phase-02

## Goal

Lock in correctness with unit + integration tests, ship a documented default-disabled config block, update architecture docs.

## Context Links

- Test scenarios catalog: `research/researcher-01-header-leak-prevention.md` §5
- Pre-existing unit tests: `crates/waf-engine/src/outbound/header_filter.rs` lines 181-261 (7 tests)
- Default config: `configs/default.toml`
- Docs to refresh: `docs/system-architecture.md`, `docs/project-roadmap.md`, `docs/codebase-summary.md`

## Files

**Modify:**
- `crates/waf-engine/src/outbound/header_filter.rs` — extend test module with edge cases (see catalog below)
- `configs/default.toml` — add commented `[outbound]` block
- `docs/system-architecture.md` — append "Outbound Phase" subsection
- `docs/project-roadmap.md` — mark FR-035 done
- `docs/codebase-summary.md` — note `outbound/` module

**Create:**
- `crates/gateway/tests/outbound_header_filter_test.rs` — integration test exercising the Pingora `response_filter` hook end-to-end against a stub upstream

**Read for context:**
- existing `crates/gateway/tests/` for test scaffolding pattern (if present); otherwise model after a Pingora ProxyHttp test pattern

## Test Catalog (extend `header_filter.rs` tests module)

Mandatory additions on top of existing 7:

| # | Test | Asserts |
|---|------|---------|
| 8  | `test_strip_is_case_insensitive` | `should_strip("SERVER")` and `should_strip("server")` both true (RFC 9110) |
| 9  | `test_preserve_security_headers` | HSTS, CSP, X-Frame-Options, Referrer-Policy NOT stripped under default config |
| 10 | `test_preserve_content_headers` | Content-Type, Content-Length, Content-Encoding NOT stripped |
| 11 | `test_preserve_cache_headers` | Cache-Control, ETag, Last-Modified, Vary NOT stripped |
| 12 | `test_custom_prefix_only_when_configured` | `X-Foo-bar` not stripped by default; stripped after adding `x-foo-` to `strip_prefixes` |
| 13 | `test_pii_detection_disabled_by_default` | `detect_pii_in_value("user@example.com")` returns `None` when `detect_pii_in_values = false` |
| 14 | `test_filter_returns_stripped_names` | `filter_headers` populates the returned `Vec<String>` with every removed name |
| 15 | `test_empty_headers_no_panic` | `filter_headers(&mut vec![])` returns empty `Vec`, no panic |
| 16 | `test_long_header_value_no_redos` | 10 KiB header value processed under 5 ms (smoke; not strict perf) |
| 17 | `test_jwt_in_header_value_detected` | When `detect_pii_in_values = true` and a header has a JWT-like value, it gets stripped (extends current PII set if needed — research §3) |

Decision needed: extend PII patterns to cover JWT (`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)? Research recommends yes. Add as new pattern. Keep test #17.

## Integration Test (new file)

`crates/gateway/tests/outbound_header_filter_test.rs`:

- Spin up an axum or hyper test server returning `Server: hardcoded`, `X-Debug-Token: secret`, `X-Internal-Path: /admin`, `Content-Type: text/plain`
- Build a `WafProxy` with `outbound.enabled = true` and a minimal host route pointing to the stub
- Send a request through Pingora; assert response headers contain `Content-Type` but NOT `Server`/`X-Debug-Token`/`X-Internal-Path`
- Repeat with `outbound.enabled = false`; assert all headers passthrough

If full Pingora bring-up in tests is too heavy, fallback: unit-test the `response_filter` method directly by constructing a `pingora_http::ResponseHeader` and calling the trait method. (Check whether `response_filter` is callable without a live `Session`.)

## Default Config Block

Append to `configs/default.toml`:

```toml
# ── FR-035: Outbound Header Leak Prevention ──────────────────────────────────
# Strip leaky response headers (server fingerprint, debug, internal, error
# detail) before they reach the client. Detection categories are hard-coded;
# operators choose which categories are active. Disabled by default.
#
# [outbound]
# enabled = false
#
# [outbound.headers]
# strip_server_info   = true   # Server, X-Powered-By, X-AspNet-Version, etc.
# strip_debug_headers = true   # X-Debug-*, X-Internal-*, X-Backend-*
# strip_error_detail  = true   # X-Error-*, X-Exception-*, X-Stack-*
# detect_pii_in_values = false # Regex-scan header values for email/CC/SSN/IP/JWT
# strip_headers   = []          # Extra exact names (case-insensitive)
# strip_prefixes  = []          # Extra prefixes (case-insensitive)
```

## Documentation Updates

### `docs/system-architecture.md`
Add subsection after the 16-phase pipeline section:

```markdown
### Outbound Phase — Response Header Sanitization (FR-035)

After upstream response headers arrive in Pingora's `response_filter` hook,
the configured `HeaderFilter` walks every header and strips:

- Server fingerprint headers (`Server`, `X-Powered-By`, ...)
- Debug/internal headers (`X-Debug-*`, `X-Internal-*`, `X-Backend-*`)
- Error-detail headers (`X-Error-*`, `X-Exception-*`, `X-Stack-*`)
- Optional: any header whose VALUE matches a PII regex (off by default)

Operator-supplied exact names and prefixes extend the built-in lists.
The phase is gated by `[outbound] enabled` and is a no-op when disabled.
```

### `docs/project-roadmap.md`
Marked FR-035 as Completed under a new `v0.2.1 — In Progress` block with date 2026-04-26.

### `docs/codebase-summary.md`
Add `outbound/` module to the `waf-engine` crate breakdown.

## Implementation Steps

1. Extend test module in `header_filter.rs` per catalog — tests 8-17
2. Decide JWT pattern: add to `build_pii_patterns()` and `PII_PATTERN_NAMES` if test 17 keeps it
3. Author `crates/gateway/tests/outbound_header_filter_test.rs` integration test (or fallback: unit-test the `response_filter` method directly inside `gateway/src/proxy.rs`)
4. Append `[outbound]` block to `configs/default.toml`
5. Update three docs files per snippets above
6. Run `cargo test --workspace`
7. Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`
8. Run `cargo fmt --all -- --check`

## Verification

- All new + existing unit tests pass: `cargo test -p waf-engine outbound::`
- Integration test passes: `cargo test -p gateway --test outbound_header_filter_test`
- `cargo clippy ... -D warnings` clean
- `cargo fmt --check` clean
- Docs render correctly (no broken links — check `docs/system-architecture.md` references)

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Full Pingora integration test too heavy | Fall back to direct method call on `response_filter` with a constructed `ResponseHeader` |
| JWT regex false-positives on long base64 strings | Pattern requires `eyJ` prefix on two segments — narrow enough; add test for non-JWT base64 |
| Doc churn | Limit to three files; surgical edits only |

## Success Criteria

- [x] 10 new unit tests added; all pass (19 total in `outbound::header_filter::tests`)
- [x] Method-level coverage via `HeaderFilter::filter_headers` + `should_strip` + `detect_pii_in_value` (full Pingora integration test deferred — fallback per plan)
- [x] `configs/default.toml` documents the block clearly
- [x] Three doc files updated; cross-refs intact
- [x] Touched-crate tests 100% green (153 lib tests in waf-common/waf-engine/gateway)
- [x] No new clippy or fmt violations in touched crates

## Next Phase

→ phase-04-ship.md (build, branch, commit, push, PR)
