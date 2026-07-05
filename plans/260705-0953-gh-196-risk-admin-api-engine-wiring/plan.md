---
title: "GH-196 risk admin API: wire config, store backend, and actor ops to the engine"
description: "Make the risk admin API real: configs/risk.yaml loaded at startup + hot-reload, store built from StoreConfig (memory purge loop / redis), PUT round-trips full RiskConfig via serde, actor clear/credit mutate the store"
status: pending
priority: P1
branch: "main-harness"
tags: [bug, area:api, risk, gh-196]
blockedBy: []
blocks: []
created: "2026-07-05T02:52:48.553Z"
createdBy: "ck:plan"
source: skill
issue: https://github.com/future-and-go/mini-waf/issues/196
---

# GH-196 risk admin API: wire config, store backend, and actor ops to the engine

## Overview

Issue: https://github.com/future-and-go/mini-waf/issues/196 (P1 bug, CONFIRMED by
multi-agent review 2026-07-03; all claims re-verified on HEAD `9ee484b`, 2026-07-05).

The risk admin API is a façade — four independent gaps:

1. **Config PUT is write-only.** `put_risk_config` (`crates/waf-api/src/risk_api.rs:145-148`)
   writes `configs/risk.yaml`; nothing loads it. `RiskReloader::start` has zero
   production callers, `Engine::replace_risk_config` (`engine.rs:315`) is called
   only from tests, and `crates/prx-waf/src/main.rs` never mentions risk. The
   engine's `risk_cfg` stays `RiskConfig::default()` (enabled=false) forever.
2. **Store backend ignored.** `WafEngine::new` (`engine.rs:258`) hardcodes
   `MemoryRiskStore::new()`; `scorer: Arc<Scorer<MemoryRiskStore>>` is concretely
   typed (`engine.rs:161`). `StoreConfig.backend=redis`, `to_runtime_config`
   (`risk/config.rs:122`), and `MemoryRiskStore::start_purge_loop`
   (`store/memory.rs:44`) all have zero production callers → redis silently
   ignored, memory DashMap never purged.
3. **Actor ops are no-ops.** `clear_risk_actor` / `credit_risk_actor`
   (`risk_api.rs:180-195`) return `success:true` without touching any store.
   `RiskStore` trait has no clear op; `Contributor.delta` is `i16` so negative
   credits are already first-class (challenge credit uses -25).
4. **PUT drops config sections.** `fe_to_yaml` (`risk_api.rs:111-132`) hand-maps
   fields through `serde_json::Value` and silently drops `session_cookie`,
   `ingest.signal_weights`, `challenge`, and seed file paths. `RiskConfig`
   already derives `Serialize + Deserialize` with authoritative defaults.

Established repo pattern to follow: engine-owned `start_*_watcher(&self, path)`
(rate-limit, ddos, tx-velocity) called from `main.rs` `setup()` (~lines 1607-1634),
fail-soft on missing/bad file.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Scorer over dyn RiskStore + store from StoreConfig](./phase-01-scorer-over-dyn-riskstore-store-from-storeconfig.md) | Pending |
| 2 | [Risk config load + hot-reload watcher wiring](./phase-02-risk-config-load-hot-reload-watcher-wiring.md) | Pending |
| 3 | [Risk config PUT/GET serde round-trip](./phase-03-risk-config-put-get-serde-round-trip.md) | Pending |
| 4 | [Actor clear/credit wired to the store](./phase-04-actor-clear-credit-wired-to-the-store.md) | Pending |
| 5 | [Acceptance tests + quality gates](./phase-05-acceptance-tests-quality-gates.md) | Pending |

## Key Decisions

- **Store backend is start-time only.** The store (memory vs redis) is chosen once
  when `start_risk_watcher` performs the initial load; hot-reload swaps only the
  `RiskConfig` snapshot (thresholds, canary, deltas). A backend change in
  risk.yaml at runtime logs `warn!("risk store backend change requires restart")`.
  Rationale: swapping a live store loses all actor state and races in-flight
  scoring; no other subsystem hot-swaps its store either.
- **Scorer becomes `Scorer<dyn RiskStore>`** (relax bound to `S: RiskStore + ?Sized`).
  Engine holds `ArcSwap<Scorer<dyn RiskStore>>` so the redis-backed scorer built at
  initial load can replace the construction-time memory default; `inspect()` pays
  one atomic load (same idiom as `risk_cfg`).
- **Hot-reload goes through `replace_risk_config`** (not `RiskReloader`'s raw
  `ArcSwap` store) so the canary layer stays in sync (paths + ban TTL). Reuse
  `RiskReloader`'s watch/debounce machinery by generalizing it to a callback,
  or add an engine-side wrapper — implementer's choice, but raw-swap is a bug.
- **Credit = negative-delta `apply`**; new `ContributorKind::AdminCredit` variant
  (unit variant — must round-trip through the redis Lua path; see GH-198 Decay
  precedent). Clear = new `RiskStore::clear(&self, key)` trait method.
- **`list_risk_actors` stays a documented stub** — enumerating actors is not in
  the GH-196 acceptance criteria and redis can't enumerate cheaply. Out of scope.

## Cross-Plan Dependencies

- **Blocks GH-207 item 2** (risk FE config mapping dedupe): Phase 3 here deletes
  `fe_to_yaml`/`yaml_to_fe`/`default_risk_fe` and replaces them with `RiskConfig`
  serde round-trip — GH-207's plan must treat that item as done here.
- **No conflict with GH-202 plan** (`260705-0739-gh-202-riskbump-actor-keyed-submit`):
  it touches `checks/ddos/action/risk.rs` + aggregator; overlap is limited to
  distinct regions of `engine.rs`.
- **Related to GH-201** (redis fail-open): Phase 1 wires `RedisRiskStore` into
  production; GH-201 changes its error propagation. Textual overlap in
  `store/redis.rs` is minimal, but land this plan first so GH-201 tests run
  against a reachable production path.

## Acceptance Criteria (from issue)

- [ ] Startup (or hot-reload watcher) loads `configs/risk.yaml` into the engine; PUT takes effect without restart.
- [ ] Store constructed from `StoreConfig` (memory vs redis) and purge loop started for memory backend.
- [ ] clear/credit endpoints mutate the store or return 501 — no false success.
- [ ] PUT round-trips all `RiskConfig` fields (test: load → PUT → reload → same config).

## Validation

- `cargo test -p waf-engine risk` and `cargo test -p waf-api risk` green.
- Redis-gated conformance (`REDIS_TEST_URL`) covers `clear` + AdminCredit round-trip.
- `cargo clippy --workspace --all-targets` clean.
