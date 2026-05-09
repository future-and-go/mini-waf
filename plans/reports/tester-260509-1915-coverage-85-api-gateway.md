# Tester Report — coverage-85-api-gateway (Task #3)

Date: 2026-05-09 19:15 (verification 20:19)
Branch: main @ 4b9a0ac (pre-tester fixes)
Acceptance: **PARTIAL PASS** (gateway capped ≥85% verified, full waf-api coverage measurement deferred due to Docker outage)

## Verifiable Results

### fmt / check / clippy
- `cargo fmt --all -- --check` → CLEAN.
- `cargo check --tests -p waf-api -p gateway` → CLEAN (no errors, only pingora-vendor patch warning, pre-existing & unrelated).
- `cargo clippy -p waf-api --tests --no-deps -- -D warnings` → CLEAN (after fix, see below).
- `cargo clippy -p gateway --tests --no-deps -- -D warnings` → CLEAN (after fix, see below).
- Full-deps clippy fails on `crates/waf-engine/src/risk/challenge_credit/nonce_store.rs:128` (`unused_async`) — pre-existing on main HEAD, NOT introduced by Task #1/#2/#3, NOT a waf-api/gateway issue. Verified by stashing tester edits and reproducing on plain main.

### Tests
- `cargo test -p gateway` → **318 passed, 0 failed** across all binaries (lib 207, plus unit/integration suites: cache 13/12/10/16/5/11, tier 6/4, error_page 4, response policies 4, plus minor 3/0).
- `cargo test -p waf-api --lib` → **68 passed, 0 failed** (all unit tests).
- `cargo test -p waf-api --test error_mapping` → **5 passed, 0 failed**.
- `cargo test -p waf-api --test notifications_unit` → **12 passed, 0 failed**.
- `cargo test -p waf-api --test notifications_dispatch_unit -- payload_serializes_round_trip` → **1 passed, 0 failed** (other 2 dispatch_* tests filtered, Docker-required).

### Coverage
- `cargo llvm-cov --summary-only -p gateway` → TOTAL **81.19% lines / 78.74% functions / 80.93% regions** (raw, all files).
- `cargo llvm-cov --summary-only -p gateway --ignore-filename-regex 'proxy\.rs|http3\.rs|tunnel\.rs|proxy_waf_response\.rs|response_cache_integration\.rs'` → TOTAL **92.27% lines / 91.88% functions / 92.43% regions** (capped, Pingora I/O excluded). **≥85% gate met.**
  - Slight delta vs dev-gateway 92.40%: due to tester's clippy fix in `request_ctx_builder.rs` recompiling the file.
- `cargo llvm-cov --summary-only -p waf-api --lib` → TOTAL **25.81% lines / 24.22% functions / 19.96% regions** (lib-only; handler logic gated behind integration tests). Full-suite measurement requires Docker (testcontainers-Postgres). **DEFERRED.**

## Tester Fixes Applied

Two clippy errors blocked `--no-deps` runs on the changed files. Fixed surgically in tester scope:

1. `crates/waf-api/tests/common/mod.rs:230` — `field_reassign_with_default` on `ClusterConfig`. Refactored to struct-init form. (Test harness only.)
2. `crates/gateway/src/ctx_builder/request_ctx_builder.rs:200` — `redundant_closure_for_method_calls`. Replaced `|h| h.as_bytes()` with `http::HeaderValue::as_bytes`. (Production file, behavior identical.)

Both verified by re-running `cargo fmt`, `cargo check`, `cargo clippy --no-deps` clean.

## Deferred / Skipped (Docker outage)

Cannot run on this machine (Docker daemon down):
- `cargo llvm-cov --summary-only -p waf-api` (full) — testcontainers boot fails.
- waf-api integration test binaries (need Postgres testcontainer): `cluster_handlers_enabled`, `crowdsec_handlers_enabled`, `logs_handlers_proxy`, `notifications_dispatch_unit::dispatch_*`, plus pre-existing handler integration suites (`handler_*` tests: cluster_status, hosts_crud, ip_url_lists, plugins_tunnels, rules_api, etc.).
- Therefore: **waf-api coverage measurement against the 85% gate is DEFERRED** as approved by team-lead direction.

## CI Floor Status (`.github/workflows/coverage.yml`)

Current matrix entries (lines 41–47):
- `waf-api: 78` — NOT bumped to 85; raw coverage with current testcontainers-blocked run is 25.81%, full-suite measurement deferred.
- `gateway: 82` — NOT bumped. Raw coverage is 81.19%, *below* current 82 floor. Capped 92.27% only achievable with `--ignore-filename-regex` flag; `coverage-check.sh` does NOT pass any regex (it uses `--ignore-filename-regex 'vendor/'` only).

**CI implication:** if `coverage.yml` runs as-is on main, the `gateway, floor: 82` job will FAIL because raw line% is 81.19% < 82%. This is a regression vs whatever the prior baseline was, possibly because new tests changed instrumented-line denominators OR the full file set now compiles differently. Either:
- (a) lower `gateway` floor to 81 (matches current raw) — short-term unblock.
- (b) modify `coverage-check.sh` to accept exclusion regex, then bump gateway floor to 85 against capped — true 85% claim.
- (c) add tests to push raw ≥ 85% across `proxy.rs`, `tunnel.rs`, `ssl.rs`, etc. (requires Pingora harness — out of scope).

I did NOT edit CI or floors; flagged for team-lead.

## Acceptance Verdict

| Criterion | Result |
|---|---|
| gateway capped ≥85% | **PASS** (92.27%) |
| gateway full suite green | **PASS** (318/318) |
| waf-api lib + non-Docker tests green | **PASS** (68 + 5 + 12 + 1 = 86 tests) |
| fmt / clippy / check clean | **PASS** (after 2 tester surgical fixes) |
| waf-api coverage measurement | **DEFERRED** (Docker daemon down) |

Per teammate-message acceptance ("waf-api coverage measurement explicitly listed as deferred (acceptable due to Docker outage)") → **acceptable PARTIAL PASS**, marking Task #3 completed.

## Unresolved Questions

1. CI `coverage.yml` gateway floor (82) vs current raw (81.19%) — needs team-lead decision: lower floor, switch script to capped, or add Pingora-path tests. (See "CI Floor Status" above.)
2. Should `coverage-check.sh` learn `--ignore-filename-regex` (per crate) so gateway can be measured against 85% capped in CI? Out of tester scope.
3. Pre-existing waf-engine clippy `unused_async` on `nonce_store.rs:128` — separate cleanup needed; introduced by `c67a215`. Not blocking this task.
4. waf-api full-suite coverage number remains unknown until Docker is back; dev-api's pre-PR claim of "deferred measurement" stands unchallenged.
