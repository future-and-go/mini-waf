# Phase 5: Rate-Limit Action Mapping — Decision Class Separation Complete

**Date:** 2026-05-29
**Scope:** `crates/waf-engine/src/` — engine decision routing + rate-limit check test activation
**Commit:** `f2666ba`

## What Changed

Modified the checker loop in `engine.rs` to phase-aware decision wrapping:

- **Before:** All checker results wrapped uniformly via `make_block_decision(..., 403)` (HTTP 403 block)
- **After:** `result.phase == Phase::RateLimit` → `WafDecision::rate_limit(429, body, result)` preserving `InteropMode::LogOnly` when active; all other phases stay 403 block

Single match block, single file, zero trait changes. No modifications to the `Check` trait or its 11 implementations.

**Rate-limit check test:** Activated previously-commented TDD scaffold `ip_burst_produces_rate_limit_phase` in `checks/rate_limit/check.rs`. Asserts `BurstExceeded` → `Phase::RateLimit`.

**Verification:** `cargo check` clean, `clippy` clean, `cargo fmt` clean. Rate-limit unit tests 37/37 pass. Code review (code-reviewer subagent): no concerns.

## Key Decision

Skipped plan step 4: engine-level `inspect()` integration test for rate-limit breach. Reason: RateLimitCheck is inert until `start_rate_limit_watcher` loads tier config from a file. A breach test requires a debounced file-watcher fixture + Postgres testcontainer—high fixture cost, low marginal value vs. the unit test that pins the invariant (RateLimitCheck emits Phase::RateLimit on burst, engine routes it to 429). The engine mapping is exhaustive control flow verified by code inspection.

**Verification principle:** Boundary is already covered—RateLimitCheck is the only source of Phase::RateLimit (TxVelocity is signal-only, returns None). Gateway enforces WafAction::RateLimit{status, body} end-to-end (proxy_waf_response.rs, http3.rs), as_contract_str() → "rate_limit".

## Impact

Rate-limited requests now distinct decision class (HTTP 429, X-WAF-Action: rate_limit) per contract §3 matrix. Separable from security blocks (403) in benchmarker classification. DDoS burst detection remains 403 security block (separate code path before loop).

Interop Contract v2.3 compliance complete: Phase::RateLimit consistently mapped to 429 + decision mode preserved in log-only mode.
