# Phase 6: Decision-Class Response Enforcement — §3 Contract Hardening Complete

**Date:** 2026-05-29
**Scope:** `crates/gateway/src/` — response writer match arms + mode-aware test coverage
**Commit:** `0eafad9`

## What Changed

Gap analysis of live code vs. Phase 6 success criteria revealed prior commits had already wired 80% — write_waf_decision, write_waf_body_decision, and http3 handler enforced RateLimit(429), Timeout(504), CircuitBreaker(503) with is_enforcement_allowed() guards. Three gaps closed:

1. **Structured logging:** Added `action = %decision.action.as_contract_str()` field to write_waf_decision warn! log. Previously logged rule detail but not the action class itself — now audit trails which of 6 decision classes fired.

2. **Exhaustive match arms:** Replaced three `_ => {}` catch-alls with explicit non-enforced branches:
   - write_waf_decision: `Allow | LogOnly` — deprecated LogOnly variant kept for migration safety, marked `#[allow(deprecated)]`
   - write_waf_body_decision and http3: `Allow | Challenge | LogOnly` — same deprecation allowance
   - Benefit: Compiler now flags any future 9th WafAction variant; prevents silent regressions.

3. **Mode-aware test coverage:** Added `write_waf_decision_log_only_block_returns_false` — verifies that a Block action with InteropMode::LogOnly skips enforcement (returns Ok(false), blocked counter stays 0). Prior log-only test used deprecated LogOnly *action* variant, not the mode. Mode-aware path was untested until now.

## Design Note: Challenge Bucketing

Challenge enforced only in H1 write_waf_decision (has challenge_ctx for page generation). Body-inspection and HTTP/3 stages pass Challenge through without serving—body stage has no context; H3 challenge unimplemented (deferred to future work).

## Verification

- `cargo check -p gateway` → zero warnings
- `cargo test -p gateway` → 345 lib + 17 in proxy_waf_response_writer all pass (new test included)
- `cargo fmt --all --check` → clean
- code-reviewer subagent: DONE, no concerns

## Impact

All 6 decision classes (allow, block, challenge, rate_limit, timeout, circuit_breaker) now have exhaustive, non-silenceable enforcement paths. Mode-aware enforcement (log-only vs. enforced) verified by unit test. Interop Contract v2.3 §3 response handlers complete.

## Lesson: Gap Analysis Before Re-implementing

Plan Phase 6 was marked pending but prior work had shipped 80% of the code. Scanning live code for gaps against success criteria identified 3 surgical fixes vs. redundant full re-implementation. Saved ~2 hours of duplicate work and merge conflict risk. Pattern: always diff plan against live before assuming phase is empty.

## Unresolved

- HTTP/3 challenge support: deferred; requires challenge_ctx in HTTP/3 path (architectural change)
- Upstream wiring for Timeout/CircuitBreaker: out of scope — belongs to §8 binary contract work (requires load-balancer/probe integration)
