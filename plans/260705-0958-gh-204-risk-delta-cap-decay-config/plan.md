---
title: "GH-204 risk: enforce per-request delta cap, honor DecayConfig, add RiskConfig::validate"
description: "Wire the defined-but-unused per-request delta cap into the scorer, thread DecayConfig into both store backends so it stops being dead config, and add RiskConfig::validate at the parse boundary"
status: completed
priority: P2
effort: 5h
branch: "main-harness"
tags: [bug, area:engine, risk, gh-204]
blockedBy: []
blocks: []
created: "2026-07-05"
createdBy: "ck:plan"
source: skill
issue: https://github.com/future-and-go/mini-waf/issues/204
---

# GH-204 risk: enforce per-request delta cap, honor DecayConfig, add RiskConfig::validate

## Overview

Issue: https://github.com/future-and-go/mini-waf/issues/204 (P2 bug, CONFIRMED by
multi-agent review 2026-07-03; all claims re-verified on HEAD `9ee484b`, 2026-07-05
after merges #209/#210/#211 shifted line numbers).

Three documented scoring limits that do not bind:

1. **Per-request delta cap never enforced.** `clamp_per_request_deltas` /
   `MAX_PER_REQUEST_DELTA = 100` (`crates/waf-engine/src/risk/score.rs:38,68-103`)
   are defined, tested, and re-exported (`risk/mod.rs:46`) but have **zero call
   sites**. `Scorer::score_with_l2` (`scorer.rs:255`) passes the fully-collected
   `all_deltas` straight to `store.apply`; the memory fold (`store/memory.rs:155`
   → `score::fold`) and the Redis Lua both apply raw deltas uncapped. One request
   can therefore add unbounded positive `raw_score` despite the FR-025 100-point
   per-request cap. `scorer.rs:255` is the single choke point where the seed
   short-circuit path (`scorer.rs:172`) and the normal path both converge, and it
   is the only place both backends are reached.
2. **DecayConfig is dead config.** `DecayConfig` (min_clean_streak, decay_rate,
   max_decay — `risk/config.rs:152-165`) is parsed from `risk.yaml` and editable
   via the admin API, but never read. `decay.rs:12-18` hardcodes
   `MAX_DECAY=50` / `MIN_CLEAN_STREAK=10` / `DECAY_RATE=1`; `apply_decay`
   (`decay.rs:23`) uses the consts; `store/memory.rs:153` calls it; `store/redis.rs:343-345`
   feeds the **consts** (not `cfg.decay`) into Lua `ARGV[6,7,8]`. The Lua script
   (`store/redis_lua.rs:39-41`) already accepts them as ARGVs, so threading config
   through is arithmetic-only — the script body does not change. Failure story:
   operator sets `decay_rate: 0` to disable decay, the UI echoes it back, and decay
   still sheds 1 point per clean request.
3. **No `RiskConfig::validate()`.** `RiskConfig` has only `from_path`
   (`config.rs:375`); zero-window and unknown-backend values pass silently. A
   `gc_interval_secs: 0` panics `tokio::time::interval` in the purge loop
   (`store/memory.rs:47`); `ttl_secs: 0` expires every actor immediately.

Verified non-issue: the canary honeypot path (`scorer.rs:182-206`) calls
`self.force_max` → `store.force_max`, which never runs `fold`/decay/clamp. It is
**unaffected** by the delta cap. Confirmed by tracing both store `force_max` impls
(`store/memory.rs:168`, `store/redis.rs:385`) — neither touches deltas.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Enforce per-request delta cap in the scoring pipeline](./phase-01-enforce-per-request-delta-cap-in-the-scoring-pipeline.md) | Pending |
| 2 | [Honor DecayConfig across memory and redis backends](./phase-02-honor-decayconfig-across-memory-and-redis-backends.md) | Pending |
| 3 | [Add RiskConfig::validate wired into config load](./phase-03-add-riskconfig-validate-wired-into-config-load.md) | Pending |
| 4 | [Acceptance tests and quality gates](./phase-04-acceptance-tests-and-quality-gates.md) | Pending |

## Key Decisions

- **Cap once at the scorer, not in the stores.** Wire `clamp_per_request_deltas`
  at the single `store.apply` choke point in `score_with_l2` (`scorer.rs:255`).
  No double-capping risk: `fold`/Lua only clamp the *total* score to `[0,100]`;
  the per-request cap bounds the *positive delta sum of one request* to 100 — a
  distinct operation. Also cap at `ingest/worker.rs:106` (the async ingest job is
  one-request-equivalent) so the "no single apply exceeds +100 positive" invariant
  holds on both ingestion paths. The pre-clamp `raw_sum` returned by the helper is
  discarded (RiskState has no audit-sum field; adding one is YAGNI).
- **Thread DecayConfig by constructor injection, not by changing the `apply`
  trait signature.** Adding a `&DecayConfig` param to `RiskStore::apply` would
  ripple to ~50 test/conformance call sites (see enumeration in Phase 2). Instead,
  each store holds its `DecayConfig`: `MemoryRiskStore` gains a `decay` field;
  `RedisRiskConfig` gains a `decay` field fed into the Lua ARGVs. `apply_decay` /
  `preview_decay` take `&DecayConfig`. This keeps the hot `apply` signature and
  all its callers untouched.
- **Decay config lifetime = store lifetime (start-time).** Consistent with the
  GH-196 decision that the store backend is chosen once at load and not hot-swapped,
  decay params are read when the store is built. Changing decay at runtime takes
  effect on the same restart/rebuild path as the backend. Hot-reloading decay
  alone (ArcSwap<DecayConfig> + setter) is out of scope (YAGNI). See Open Questions.
- **`decay_rate: 0` disables decay via existing floor arithmetic — no special
  branch.** In `apply_decay`, `available = (raw_score - floor).min(decay_rate)`;
  rate 0 ⇒ available 0 ⇒ the `available <= 0` guard returns 0. In Lua,
  `if available > decay_rate then available = decay_rate` ⇒ 0 ⇒ the `available > 0`
  guard skips decay. Both already handle 0 correctly once the value comes from config.
- **`validate()` is fail-hard at the parse boundary, fail-soft at operational
  boundaries.** `RiskConfig::validate(&self) -> Result<()>` is called inside
  `from_path` after parse. The hot-reload watcher (`reload.rs:40`) already keeps
  the previous snapshot on `Err`; GH-196's admin PUT will reject with 400. validate
  rejects: `ttl_secs == 0`, `gc_interval_secs == 0`, `ingest.channel_capacity == 0`,
  `store.backend ∉ {memory, redis}`, `decay.max_decay > 100`. It does **not** check
  risk thresholds (allow/challenge/block) — those live in `TierPolicy.risk_thresholds`
  (waf-common), not `RiskConfig`; the issue's "thresholds out of order" example is
  out of scope for this validator (documented in Phase 3).

## Cross-Plan Dependencies

- **GH-200** (`plans/260705-0958-gh-200-canary-before-seed-early-return`) also edits
  `scorer.rs`. Soft ordering: land GH-200 first, then rebase Phase 1's one-line
  clamp insertion. No hard `blockedBy`.
- **GH-196** (`plans/260705-0953-gh-196-risk-admin-api-engine-wiring`) reworks
  `engine.rs` store construction (Scorer over `dyn RiskStore`, `build_risk_store`)
  and will consume `RiskConfig::validate()` from its PUT path (Phase 3 here). Shared
  touch-point: the store-construction site in `engine.rs`. Whichever lands first,
  the other carries the `cfg.decay` argument forward. Soft coordination, no hard block.
- **GH-208** cleanup touches `store/memory.rs` `force_max` and decay-adjacent code;
  Phase 2 edits `memory.rs`. Soft note — regions differ (constructor/`apply_decay`
  call vs `force_max`).

## Acceptance Criteria (from issue)

- [ ] `clamp_per_request_deltas` wired into the scoring pipeline (both backends);
      oversized delta batch capped. → Phase 1, Phase 4
- [ ] `cfg.decay` threaded to memory `apply_decay` and Redis ARGVs; consts used as
      defaults only. → Phase 2
- [ ] Decay honors configured rate incl. `decay_rate: 0` disables decay
      (memory + `REDIS_TEST_URL`-gated redis). → Phase 2, Phase 4
- [ ] `RiskConfig::validate()` rejects nonsensical values (zero windows, bad
      backend, decay floor out of range). → Phase 3, Phase 4

## Validation

- `cargo test -p waf-engine risk` green (scorer cap, decay-honors-config, validate).
- `REDIS_TEST_URL`-gated conformance covers the cap and `decay_rate: 0` on redis.
- `cargo clippy --workspace --all-targets` clean.

## Open Questions

- Should decay params hot-reload independently of a store rebuild? This plan freezes
  them at store construction (matching backend lifetime). If operators expect admin
  API decay edits to apply without restart, a follow-up would add
  `ArcSwap<DecayConfig>` + a setter called from `replace_risk_config`. Deferred as YAGNI.
</content>
</invoke>
