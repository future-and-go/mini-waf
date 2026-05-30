---
phase: 1
title: "TDD Test Scaffold"
status: completed
priority: P1
effort: "3h"
dependencies: []
---

## Completion Note (2026-05-30)

Scaffold landed in two files:

- `crates/gateway/tests/waf_observability_headers.rs` — new unit-test crate with
  21 tests. 10 fail red on the injector contract (6-header coverage, score
  clamp, rule_id `None` + CRLF→`none`, cache enum, mode, idempotency); 2 pass
  (already-implemented `WafAction::as_contract_str` + `CacheStatus::default`);
  9 are `#[ignore]` stubs reserving slots for every remaining inventory path
  (Phase 3 ctx default, Phase 5 allow/passthrough/cache-HIT, Phase 6
  access-gate/fail-closed/HTTP→HTTPS/health/transport-error, Phase 4 challenge).
- `crates/gateway/tests/proxy_waf_response_writer.rs` — added 9 path tests
  asserting all six `X-WAF-*` headers on every enforced arm of
  `write_waf_decision` (block, rate_limit, timeout, circuit_breaker, redirect)
  and `write_waf_body_decision` (block, rate_limit, timeout, redirect). 17
  existing tests still green (no regression). 1 `#[ignore]` for the
  challenge-page render (needs Phase 4 `ChallengeCtx` fixture).

API locked for Phase 2 via a temporary `mod waf_observability_headers` stub
inside the test file — Phase 2 deletes the stub and replaces it with
`use gateway::waf_observability_headers::{...}`; no test bodies change.

Final state: `cargo test -p gateway --test waf_observability_headers
--test proxy_waf_response_writer` → 19 pass, 19 fail (assertion failures,
not panics), 10 ignored. Build is warning-clean and formatted.

# Phase 1: TDD Test Scaffold

## Overview
Write the failing tests FIRST — covering the injector unit behavior AND every egress path in the
plan's Egress Path Inventory, so no contract-mandatory path can silently ship header-less
(red-team F16: false-green prevention).

## Requirements
- Functional: tests assert all 6 headers, exact names/casing/value-format per contract §5, on every egress path.
- Non-functional: tests compile; assertions fail (red) until production code lands.

## Architecture
Two test layers:
1. **Unit** — pure test of `inject_waf_observability_headers()` over a `pingora_http::ResponseHeader`.
2. **Path** — assertions on each egress function's emitted `ResponseHeader`.

## Related Code Files
- Create: `crates/gateway/tests/waf_observability_headers.rs` (injector + `CacheStatus`/`WafHeaderValues` unit tests)
- Modify: `crates/gateway/tests/proxy_waf_response_writer.rs` (header assertions for `write_waf_decision` AND `write_waf_body_decision`, incl. Redirect arm)
- Read for context: `crates/waf-common/src/types.rs` (WafAction:93-138, InteropMode:183-210, WafDecision:213-309); existing fixtures in `proxy_waf_response_writer.rs:34-97`

## Implementation Steps
1. Unit: `inject_waf_observability_headers(resp, vals)` produces:
   - `X-WAF-Request-Id` == given uuid
   - `X-WAF-Risk-Score` == decimal of `u8`, **clamped to 100** (test `risk_score=200` → `"100"`)
   - `X-WAF-Action` == exact lowercase contract string
   - `X-WAF-Rule-Id` == given id; `None` → `none`; **CRLF-bearing id → `none`** (not empty, not raw): test `Some("r\r\nX-Evil: 1")` → `none`
   - `X-WAF-Cache` == `HIT`/`MISS`/`BYPASS`
   - `X-WAF-Mode` == `enforce`/`log_only`
2. Table test: every `WafAction` variant → expected `X-WAF-Action` string (Redirect/Allow/LogOnly → `allow`).
3. Idempotency: calling injector twice does not duplicate headers (`insert`, not `append`).
4. `WafDecisionMeta::default()` (if `Default` derived) must yield `action == "allow"`, NOT `""` (red-team F13).
5. Path tests in `proxy_waf_response_writer.rs`: after each `write_waf_decision(...)` for
   block/rate_limit/timeout/circuit_breaker/**redirect**, parse the `ResponseHeader` and assert all 6 headers.
6. Add `write_waf_body_decision(...)` tests asserting all 6 headers on its block/rate_limit/timeout/redirect arms.
7. Challenge-page test: `X-WAF-Action: challenge` + 6 headers present.
8. Stub failing tests (or `#[ignore]`-with-TODO) for error-page paths exercised in Phase 6
   (access-gate 403, fail-closed 503, redirect 301, transport error) so they exist before impl.

## Success Criteria
- [ ] New test file compiles and is discovered by `cargo test -p gateway`
- [ ] Test API names match Phase 2 signatures verbatim (lock signatures here)
- [ ] Tests fail with assertion failures (red), not compile errors, after Phase 2 stubs land
- [ ] A test exists for EVERY egress path in the inventory (incl. body-block + error paths)

## Risk Assessment
- Risk: test API drifts from Phase 2 → define `WafHeaderValues` field names + injector signature here as the contract.
- Risk: error-page paths need a Session harness — reuse `session_over_duplex()` (proxy_waf_response_writer.rs:79).

## Security Considerations
- Explicit response-splitting test: a `rule_id` containing CR/LF must yield `none`, never inject a second header.
- Score clamp test guards the contract 0–100 bound.
