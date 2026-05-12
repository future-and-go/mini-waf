# Phase 03 — Tests for New Semantics

**Status:** completed
**Owner:** main agent
**Effort:** S (~150 LOC test code)

## Goal

Lock down every new code path with a unit test in `crates/waf-engine/src/outbound/header_filter.rs` (existing `#[cfg(test)] mod tests`). One test per behavioural claim; no over-testing.

## Test Matrix

| # | Behaviour | Setup | Expected |
|---|-----------|-------|----------|
| 1 | `preserve_headers` overrides family strip | `strip_server_info=true`, `preserve_headers=["server"]` | `should_strip("Server") == false`; `should_strip("X-Powered-By") == true` |
| 2 | `preserve_headers` overrides operator extras | `strip_headers=["x-foo"]`, `preserve_headers=["x-foo"]` | `should_strip("X-Foo") == false` |
| 3 | `preserve_prefixes` overrides family-prefix strip | `strip_debug_headers=true`, `preserve_prefixes=["x-debug-trace-"]` | `should_strip("X-Debug-Trace-Id") == false`; `should_strip("X-Debug-Token") == true` |
| 4 | preserve is case-insensitive | `preserve_headers=["SERVER"]` | `should_strip("server") == false` |
| 5 | preserve does NOT save CRLF-injected value | `preserve_headers=["server"]`, header `Server: ok\r\nX-Evil: 1` | `filter_headers` strips it (CRLF beats preserve) |
| 6 | preserve does NOT touch hop-by-hop allowlist | `preserve_headers=["connection"]` | `should_strip("Connection") == false` (was already false; no behaviour change — verify no regression) |
| 7 | `pii.disable_builtin = ["email"]` removes only that pattern | `detect_pii_in_values=true`, disable `email` | `email` value not detected; `aws_key` still detected |
| 8 | `pii.disable_builtin` with unknown name → constructor error | `disable_builtin=["bogus"]` | `try_new` returns `OutboundConfigError::UnknownPiiPattern` |
| 9 | `pii.extra_patterns` adds custom regex | `extra_patterns=[r"\bSECRET-\w+\b"]` | `detect_pii_in_value("SECRET-123")` returns `Some("custom_0")` |
| 10 | `pii.extra_patterns` invalid regex → constructor error | `extra_patterns=["[unterminated"]` | `try_new` returns `OutboundConfigError::InvalidExtraPattern { index: 0, .. }` |
| 11 | `pii.max_scan_bytes = 0` disables cap | `max_scan_bytes=0`, value 100 KiB containing email | detected (no skip) |
| 12 | `pii.max_scan_bytes = 100` enforces lower cap | `max_scan_bytes=100`, value 200-byte email-bearing string | not detected (skipped due to cap) |

## Helper Updates

- Replace `HeaderFilter::new(&cfg)` in test helpers with `HeaderFilter::try_new(&cfg).unwrap()` — `.unwrap()` allowed inside `#[cfg(test)]` only (Iron Rule 1 exception).
- Add a `pii_filter_with(extras: &[&str], disabled: &[&str], cap: usize) -> HeaderFilter` builder helper to keep tests one-liners.

## Implementation Steps

1. Update existing test helpers (`default_filter`, `pii_filter`, `pii_filter_with_session_strip`) to use `try_new`.
2. Add 12 new `#[test]` functions per the matrix above.
3. Run `cargo test -p waf-engine outbound::` — green.
4. Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.

## Todo

- [ ] Update test helpers to fallible constructor
- [ ] Test 1 — preserve overrides server-info
- [ ] Test 2 — preserve overrides operator extras
- [ ] Test 3 — preserve_prefixes overrides debug
- [ ] Test 4 — preserve case-insensitive
- [ ] Test 5 — preserve does not save CRLF
- [ ] Test 6 — hop-by-hop preservation regression check
- [ ] Test 7 — disable_builtin removes only named pattern
- [ ] Test 8 — disable_builtin unknown name → error
- [ ] Test 9 — extra_patterns adds custom detection
- [ ] Test 10 — extra_patterns invalid regex → error
- [ ] Test 11 — max_scan_bytes=0 means no cap
- [ ] Test 12 — max_scan_bytes=N enforces cap
- [ ] `cargo test -p waf-engine` green
- [ ] `cargo clippy ... -D warnings` clean
- [ ] `cargo fmt --all -- --check` clean

## Success Criteria

- All 12 new tests pass.
- All previously-green tests still pass.
- No flakiness — tests are deterministic, no time / random / I/O.

## Risk

- Test 5 (CRLF + preserve) requires building a multi-header `Vec<(String,String)>` and calling `filter_headers` — verify the existing CRLF test pattern works with the new constructor.
- Test 11 with a 100 KiB value is large for a unit test but synthesized in-memory in <1 ms; acceptable.

## Next

→ Phase 04: build, commit, push, update PR 14 description.
