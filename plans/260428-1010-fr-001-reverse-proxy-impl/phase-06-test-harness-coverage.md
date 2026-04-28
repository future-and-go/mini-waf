# Phase 06 — Test Harness + 95% Coverage Gate

## Context Links
- Design doc §5 (17 test groups)
- Phases 01–05 (code under test)
- AC: all 25 (verification phase)

## Overview
- **Priority:** P1 (gate before merge)
- **Status:** pending
- **Description:** Build axum-based synthetic backend + 17 integration test groups. Add unit tests for every Strategy/Filter/Factory. Wire `cargo-llvm-cov` with 95% gate on changed gateway code.

## Key Insights
- Strategies are pure → unit-testable without Pingora. Filter chain → unit-testable with stub trait.
- Synthetic backend reflects request as JSON (headers, body, path) so tests assert what backend saw vs what client sent.
- Coverage gate scopes to changed files only — measuring untouched legacy code is misleading.

## Requirements
**Functional**
- 17 integration test groups (one per design doc §5 item).
- Unit tests: every file in `filters/`, `policies/`, `error-page/`, `pipeline/`, `ctx-builder/`.
- Synthetic backend: axum, binds `127.0.0.1:0`, returns request echo.
- Coverage tool runs in CI; PR fails if `< 95%` on scoped files.

**Non-Functional**
- Tests run in `cargo test -p gateway` < 60s on dev machine.
- Synthetic backend startup < 100ms per test (`#[tokio::test]` shared via `OnceCell` where safe).

## Architecture
**Test layout**
```
crates/gateway/tests/
├── common/
│   ├── mod.rs
│   ├── synthetic-backend.rs       # axum echo server
│   ├── waf-harness.rs             # spawn WafProxy on ephemeral port
│   └── client-helpers.rs          # reqwest/h2/ws helpers
├── fr001_methods.rs               # AC-01
├── fr001_req_body.rs              # AC-02
├── fr001_resp_body.rs             # AC-03
├── fr001_header_fidelity.rs       # AC-04
├── fr001_status_sweep.rs          # AC-05
├── fr001_url_fuzz.rs              # AC-06
├── fr001_keepalive.rs             # AC-07
├── fr001_protocols.rs             # AC-08..11
├── fr001_xff.rs                   # AC-12..14
├── fr001_leak_headers.rs          # AC-15..16
├── fr001_body_leak_scan.rs        # AC-17
├── fr001_location_rewrite.rs      # AC-18
├── fr001_error_page.rs            # AC-19
├── fr001_hop_by_hop.rs            # AC-20
├── fr001_no_bypass.rs             # AC-22
├── fr001_tls_termination.rs       # AC-23
└── fr001_host_policy.rs           # AC-25
```
(AC-21 & AC-24 in phase-07.)

## Related Code Files
**Create** (all tests above + `tests/common/*`)

**Modify**
- `crates/gateway/Cargo.toml` — `[dev-dependencies]`: `axum`, `tokio-tungstenite`, `reqwest` with features `rustls-tls,http2`, `h2`, optionally `h3` behind feature
- `.github/workflows/ci.yml` (or equivalent) — add `cargo-llvm-cov` step

## Implementation Steps
1. Build `synthetic-backend.rs`: axum router with `/echo`, `/redirect-internal`, `/sse`, `/big`, `/leak-body`. Returns JSON describing what it saw.
2. Build `waf-harness.rs`: spins up `WafProxy` against synthetic backend on ephemeral port; returns `(waf_url, backend_url, shutdown_handle)`.
3. Write integration tests one per AC, each using harness; assertions per design doc §5.
4. Write unit tests inline (`#[cfg(test)] mod tests`) in each Strategy/Filter file.
5. Add `cargo-llvm-cov` config in `Cargo.toml` workspace root or `.config/`. CI invocation:
   ```
   cargo llvm-cov --workspace --lcov --output-path lcov.info \
     --ignore-filename-regex '(cache|lb|tunnel|ssl|http3)\.rs$|tests/' \
     --fail-under-lines 95
   ```
6. Document running tests + coverage locally in `crates/gateway/CLAUDE.md`.

## Todo List
- [ ] `tests/common/synthetic-backend.rs`
- [ ] `tests/common/waf-harness.rs`
- [ ] 17 integration test files
- [ ] Unit tests per Strategy/Filter/Factory (added in phases 01–04 as those land; this phase audits coverage)
- [ ] Cargo dev-deps wired
- [ ] `cargo-llvm-cov` installed in CI image
- [ ] CI gate at 95% on scoped files
- [ ] Local-run docs in gateway/CLAUDE.md

## Success Criteria
- All 17 integration tests green.
- `cargo llvm-cov` reports ≥ 95% line coverage on scoped files.
- Total `cargo test -p gateway` runtime ≤ 60s on M-class dev hardware.
- CI fails a synthetic regression PR (e.g. comment out `RequestXffFilter::apply` body) — proves gate works.

## Risk Assessment
| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| `cargo-llvm-cov` not on CI runner | M | M | Pre-install via setup step; fallback to `tarpaulin` |
| Flaky port-binding tests | M | M | Use ephemeral `:0` port; retry helper for connect |
| 95% gate fails on hard-to-test branches | M | M | Refactor those branches to extract pure functions; allow `#[cfg(coverage_nightly)] #[coverage(off)]` only on documented exceptions (logged) |
| Integration tests slow CI | M | L | Group tests; reuse synthetic backend across tests in same file |

## Security Considerations
- Synthetic backend binds loopback only (`127.0.0.1`).
- Test secrets (TLS keys for AC-23) generated per-test, not committed.

## Next Steps
- Phase 07: perf bench + leak sweep + abort resilience.
