---
title: "GH-206 risk/geo hot-path perf: O(1) LRU, single-RTT Redis apply, scoring after fast-path exits, clone/alloc removal"
description: "Remove per-request hot-path waste in risk scoring + geo lookup: O(10k) LRU scan under a mutex, 2-RTT Redis apply, scoring before fast-path exits, avoidable clones/allocs"
status: completed
priority: P2
branch: "main-harness"
tags: [perf, risk, geoip, redis]
blockedBy: []
blocks: []
created: "2026-07-03T15:00:21.513Z"
createdBy: "ck:plan"
source: skill
---

# GH-206 risk/geo hot-path perf: O(1) LRU, single-RTT Redis apply, scoring after fast-path exits, clone/alloc removal

## Overview

GitHub issue: https://github.com/future-and-go/mini-waf/issues/206 (5 CONFIRMED findings from multi-agent code review, 2026-07-03). This is a WAF — every finding is per-request cost.

| # | Finding | Where | Phase |
|---|---------|-------|-------|
| 1 | Hand-rolled LRU does `VecDeque::retain` O(capacity=10k) + `key.to_string()` on every get/insert, under one global `Mutex` | `crates/waf-engine/src/risk/store/redis.rs:89-108` | 1 |
| 2 | `apply()`/`force_max()` = 2 sequential Redis RTTs (MINT_OR_GET_OWNER, then APPLY/FORCE_MAX); non-atomic, contradicts `redis_lua.rs:3` doc. **Scope addition (Validation Session 1): also fixes #199 — convergence selects max-score owner** | `redis.rs:414+443, 487+498` | 2 |
| 3 | `scorer.score()` (a store write) runs before `inspect_pipeline`'s guard-disabled / IP-whitelist / blacklist short-circuits | `crates/waf-engine/src/engine.rs:665-674` | 3 |
| 4 | `windows.entry(key.clone())` clones `RiskKey` (incl. session `Vec<u8>`) per request even on hit | `crates/waf-engine/src/risk/velocity/window.rs:126` | 4 |
| 5 | Per-request `ip.to_string()` in geoip lookup; `geo.rs:133` re-uppercases `iso_code` per rule per request | `geoip.rs:107`, `checks/geo.rs:133` | 4 |

Phase 5 is the cross-cutting verification gate (tests, clippy, fmt, benches).

## Intake

- Input type: maintenance request (perf). Lane: **normal** (flags: existing behavior, weak proof — Redis store tests are gated on `REDIS_TEST_URL`).
- `scripts/bin/harness-cli` is absent in the working tree → story registration is a clean skip; GitHub issue #206 is the tracked work item.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [O(1) LRU fallback cache](./phase-01-o-1-lru-fallback-cache.md) | Pending |
| 2 | [Single-RTT atomic Redis apply](./phase-02-single-rtt-atomic-redis-apply.md) | Pending |
| 3 | [Scoring after fast-path exits](./phase-03-scoring-after-fast-path-exits.md) | Pending |
| 4 | [Velocity and geo alloc removal](./phase-04-velocity-and-geo-alloc-removal.md) | Pending |
| 5 | [Verification and benches](./phase-05-verification-and-benches.md) | Pending |

Phases 1–4 are independent of each other and can be implemented in any order; Phase 5 runs last.

## Dependencies

No open plan in `plans/` touches these files. Coordination with open **issues** (not plans):

- **#199** (owner convergence takes first index instead of max-score) — **folded into Phase 2** by Validation Session 1 decision: the merged APPLY/FORCE_MAX scripts select the max-score owner among colliding index hits, per the `store_trait.rs:29-33` contract and memory-store parity (`memory.rs:85`). #199's own acceptance criterion 3 anticipated this (merge must be atomic with apply — the single-script merge provides exactly that).
- **#198** (APPLY_SCRIPT persists unparseable RiskState — cjson `{}` contributors, Decay null kind, `is_new` always false) remains **out of scope**: state-encoding semantics are preserved as-is; #198 lands separately on the merged script.
- **#201** (fail-open on Redis errors) touches the same fallback paths as Phase 1's cache; Phase 1 does not change fallback *policy*, only cache internals.

## Acceptance Criteria (from issue #206, plus #199 per Validation Session 1)

- [x] LRU get/insert O(1), no per-op String alloc.
- [x] Redis apply/force_max are single-script, single-RTT.
- [x] Fast-path-rejected requests do not pay scoring cost.
- [x] Steady-state velocity record is clone-free; geo normalization done once at rule-load time.
- [x] (#199) Convergence selects the max-score owner in the Lua script.
- [x] (#199) Conformance test: divergent-score collision at apply time keeps the max score, both backends.

## Validation

- `cargo test -p waf-engine` (unit + Lua parity tests); Redis integration tests via `REDIS_TEST_URL=redis://127.0.0.1:6379` — a **Valkey** instance serves the standard port (Lua/EVAL compatible; the `redis` crate speaks RESP to it unchanged). These tests are **required**, not optional (confirmed available in Validation Session 1).
- `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`.
- Existing benches in `crates/waf-engine/benches/` as regression guard — closest to touched code: `tx_velocity_bench.rs`, `risk_anomaly.rs`, `rule_eval.rs`, `access_lookup.rs`.

## Validation Log

### Session 1 — 2026-07-03
**Trigger:** `/ck:plan validate` chosen at post-plan handoff (same session as plan creation).
**Questions asked:** 4

#### Verification Results
- **Tier:** Full (5 phases)
- **Claims checked:** ~20
- **Verified:** 20 | **Failed:** 0 | **Unverified:** 0
- Key confirmations: `scorer.score(` has exactly 1 production caller (engine.rs:670); `inspect_pipeline` called only from `inspect()` (engine.rs:674); `MINT_OR_GET_OWNER_SCRIPT`/`resolve_or_mint_owner` used only by code Phase 2 deletes; `ctx.geo` consumed at engine.rs:980/1031/1128; `send_audit_event` reads `decision.risk_score` (engine.rs:1102) after assignment (675→676); ip2region `IpValueExt` impls exist for `Ipv4Addr`/`Ipv6Addr`; `GeoIpInfo` is public in waf-common/src/types.rs:35; `[workspace.dependencies]` exists (Cargo.toml:25); benches `tx_velocity_bench.rs`/`risk_anomaly.rs` exist (plan originally cited only `rule_eval`/`access_lookup` — folded in).

#### Questions & Answers

1. **[Architecture]** Phase 1 LRU replacement: `lru` crate (new dep) vs HashMap + generation counter (no new dep)?
   - Options: lru crate (Recommended) | HashMap + generation counter
   - **Answer:** lru crate
   - **Rationale:** less code, O(1), ubiquitous; issue explicitly offers it.
2. **[Scope]** Phase 3: should blacklist BLOCKS also skip scoring (repeat offenders stop accumulating risk) or only allow-side exits?
   - Options: Skip all 5 exits (Recommended) | Skip only allow-side exits
   - **Answer:** Skip all 5 exits
   - **Rationale:** matches acceptance criterion "fast-path-rejected requests do not pay scoring cost"; blocked traffic is already handled by a cheaper layer.
3. **[Risks]** Phase 2 vs bug #199 (same Lua script) land order?
   - Options: Merge first, #199 later (Recommended) | Fix #199 inside the merge | Block Phase 2 on #199
   - **Answer:** **Fix #199 inside the merge** (deviates from recommendation)
   - **Rationale:** one script edit instead of two; #199's criterion 3 already asks for the merge to be atomic with apply. Scope of Phase 2 grows to include max-score convergence + conformance test.
4. **[Assumptions]** Redis available for `REDIS_TEST_URL` integration tests?
   - Options: Yes, local Redis (Recommended) | No — inspection only
   - **Answer:** Other — "using valkey but connect same port"
   - **Rationale:** Valkey on 6379 is protocol- and Lua-compatible; gated tests run unchanged and are now required proof, not optional.

#### Confirmed Decisions
- LRU: `lru` crate — as planned.
- Scoring skip: all 5 fast-path exits — as planned.
- Phase 2 scope: **now includes #199 max-score convergence fix** — plan updated.
- Test env: Valkey at `redis://127.0.0.1:6379` — Redis-gated tests mandatory.

#### Action Items
- [x] Rewrite Phase 2 semantics: convergence = max-score owner; add divergent-score conformance test; drop "byte-for-byte convergence preservation".
- [x] Phase 5: Redis-gated tests required (Valkey); bench list updated.
- [x] Update GitHub issues #206 and #199 with the fold-in decision.

#### Impact on Phases
- Phase 2: Requirements/Architecture/Steps/Success Criteria rewritten for max-score convergence (#199 in scope; #198 still preserved as-is).
- Phase 5: Valkey note; Redis-gated tests mandatory; bench names corrected.
- Phases 1, 3, 4: confirmed as written, no changes.

### Whole-Plan Consistency Sweep
- Files reread: plan.md, phase-01 … phase-05 (all edited or reviewed this session)
- Decision deltas checked: 4 (lru crate, skip-all-5 exits, #199 fold-in, Valkey-required tests)
- Reconciled stale references: 3 (plan.md Dependencies "preserve convergence byte-for-byte" → max-score; Phase 5 "if Redis reachable" → required Valkey; Phase 5 bench names)
- Unresolved contradictions: 0
- Note: remaining "byte-for-byte" wording applies only to state *encoding* (#198, intentionally preserved); conformance test target `test_triple_index_max` verified to exist at `crates/waf-engine/src/risk/store/conformance.rs:66`.

## Unresolved Questions

- None blocking. Phase 3 documents one intentional semantics change (fast-path-rejected requests no longer feed risk state) — flagged in the issue's acceptance criteria as desired and confirmed in Validation Session 1.
