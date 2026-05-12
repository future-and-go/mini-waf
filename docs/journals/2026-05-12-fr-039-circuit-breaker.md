# FR-039 Circuit Breaker — Implementation Journal

**Date:** 2026-05-12
**Feature:** FR-039 (P0 — Resilience)
**Branch:** `feat/fr-039-circuit-breaker`
**Plan:** `plans/260512-1425-fr-039-circuit-breaker/`

## Summary

Implemented backend-unresponsive circuit-breaker behaviour: WAF now returns
`503 Service Unavailable` with `Retry-After: 5` within the configured deadline
when an upstream cannot be reached. Stateless — leverages Pingora 0.8's
built-in `HttpPeer.options.*_timeout` primitives + `fail_to_connect` /
`fail_to_proxy` hooks. No Open/Half-Open/Closed state machine (YAGNI).

## Key Decisions

1. **Did NOT reuse `degrade::resolve()` (FR-005 phase 6).** Red-team finding:
   matrix `(Medium, Open, BackendOverload) → AllowAndWarn` contradicts the
   FR-039 spec ("WAF returns 503 instead of hanging"). When the transport is
   broken there is no backend to "allow through". Transport-layer fail is
   unconditional 503; detection-layer degrade remains FR-005's concern.
2. **No state machine.** Pingora's per-peer timeout + Pingora-default no-retry
   = fast-fail without per-upstream counters. Plan reviewed by researcher who
   confirmed Envoy/HAProxy precedent is overkill for spec scope.
3. **Per-host TOML override** added to `HostEntry` after discovery that DB
   admin UI is the primary source for production hosts but TOML must work in
   e2e harness with shortened timeouts.
4. **HTTP/3 path handled separately.** `http3.rs` uses `reqwest::Client`, not
   `HttpPeer`. Mirrored FR-039 timeouts on `Client::builder()`; per-host
   tuning on H3 deferred (single shared client; per-host would require larger
   refactor).

## Phases

| # | Name | Status | Commit |
|---|------|--------|--------|
| 1 | Config schema + defaults | ✅ | `70bc134` |
| 2 | Proxy wiring (HttpPeer + error_to_status + fail_to_connect + Retry-After) | ✅ | `1265497` |
| 3 | Unit tests (12 cases) | ✅ | `9bceab1` |
| 4 | Docker e2e harness + H3 + TOML wiring | ✅ | (current) |
| 5 | Coverage gate + docs + PR | ✅ | (current) |

## Coverage

- **waf-common** FR-039 module: 5 unit tests covering defaults, serde
  round-trip, legacy JSON fallback, validator pass/fail. All green.
- **gateway** FR-039 module: 12 unit tests covering `apply_fr039_timeouts`
  default/custom/overwrite + `is_transport_unresponsive` yes/no + 6
  `error_to_status` branches + Retry-After. All green.
- **Existing tests:** 9 pre-existing `error_page_factory` tests still pass —
  no regression.
- **E2E:** Docker compose harness at `tests/e2e/circuit-breaker/` covers
  E1 (hang→503), E2 (refused→503), E3 (healthy→200), E4 (Retry-After: 5).
  Requires `cargo build --release -p prx-waf` before run; not in CI yet.

## Files Changed

| Crate | Type | Path |
|-------|------|------|
| waf-common | M | `src/types.rs` (+6 fields, validator, defaults, 5 tests) |
| waf-common | M | `src/config.rs` (+6 optional fields on HostEntry) |
| gateway | M | `src/proxy.rs` (+apply_fr039_timeouts, +is_transport_unresponsive, +fail_to_connect override, +12 tests) |
| gateway | M | `src/error_page/error_page_factory.rs` (+Retry-After on 503) |
| gateway | M | `src/http3.rs` (+reqwest timeouts) |
| prx-waf | M | `src/main.rs` (thread TOML host timeouts through to HostConfig) |
| tests | + | `tests/e2e/circuit-breaker/` (docker-compose, mocks, run.sh, README) |
| docs | M | `docs/project-roadmap.md` (FR-039 section) |

## Unresolved / Followups

1. **HTTP/3 per-host timeouts.** Single shared reqwest client today; per-host
   tuning would require either a client-per-host map or moving the H3 path to
   Pingora's `HttpPeer` API.
2. **Per-tier timeouts.** Plan deliberately omitted (KISS). Could be added by
   reading `TierPolicy` instead of `HostConfig` inside `apply_fr039_timeouts`.
3. **Prometheus counter `upstream_timeout_total`.** Currently only
   `tracing::warn!`. Defer to observability sprint (v0.3.0 metrics theme).
4. **Docker e2e CI integration.** Not wired into nightly workflow yet —
   would require `cargo build --release` step + ~5 min compose run.
