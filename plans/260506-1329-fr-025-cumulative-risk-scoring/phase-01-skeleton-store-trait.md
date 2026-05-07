---
phase: 1
title: "Skeleton & Store Trait"
status: pending
priority: P1
effort: "3d"
dependencies: []
---

# Phase 1: Skeleton & Store Trait

## Overview

Stand up the `risk` module: types, store trait, in-memory backend, scorer orchestrator stub, threshold gate, config schema, hot-reload, and the `X-WAF-Risk-Score` egress header. End state: every response carries the header (BG-01 gate green) and threshold gate routes to `WafDecision`. Score itself is just the seed (zero) plus rule contributors fed via a placeholder hook — richness layered in later phases.

## Why P1 First

Compiles and runs alone. Passes the BG-01 acceptance gate (header on every response). Establishes the seam for P2–P9 to plug into without re-architecting. No external deps beyond what's already in the workspace.

## Requirements

**Functional:**
- `RiskStore` trait with `read / apply / force_max / purge_expired / reset_all` async methods.
- `MemoryRiskStore` backend: three `DashMap` indices (ip, fp_hash, session) sharing `Arc<RwLock<RiskState>>`.
- `Scorer` orchestrator: builds `RiskKey` from request → calls store → applies threshold → emits header → returns `WafAction`.
- `Thresholds` pure-function gate (`<t_allow Allow`, `>=t_block Block`, else Challenge).
- TTL-based eviction (idle 30 min default) — never per-request reset.
- Hot-reload via `ArcSwap<RiskConfig>` + `notify` watcher (mirror FR-005/FR-010 pattern).

**Non-functional:**
- Threshold gate ≤ 10µs p99 (criterion bench).
- `apply` returns post-update state in single round-trip — no follow-up read.
- All public types `Send + Sync`.
- Zero `.unwrap()` / `.expect()` outside `#[cfg(test)]`.

## Architecture

```
risk/
├── mod.rs                  # public surface: Scorer, RiskStore, RiskKey, RiskState, types
├── key.rs                  # RiskKey, SessionId, fp_hash derivation from FpKey
├── state.rs                # RiskState, Contributor, ContributorKind, SmallVec ring
├── score.rs                # pure score-fold function (events → integer)
├── decay.rs                # pure decay (with MAX_DECAY=50 floor)
├── threshold.rs            # pure decide(score, cfg, override) → WafAction
├── tier.rs                 # route → tier classifier (longest-prefix), Tier enum
├── config.rs               # YAML schema + ArcSwap hot-reload
├── reload.rs               # notify file watcher
├── scorer.rs               # Scorer orchestrator (the Check impl)
└── store/
    ├── mod.rs
    ├── store_trait.rs      # RiskStore trait + RiskState (re-export)
    ├── memory.rs           # DashMap-based MemoryRiskStore
    └── conformance.rs      # shared backend conformance suite (#[cfg(test)])
```

### Triple-Index Pattern (CRITICAL — §3.4 of brainstorm)

Three `DashMap` indices keyed independently:
- `by_ip: DashMap<IpAddr, Arc<RwLock<RiskState>>>`
- `by_fp:  DashMap<u64, Arc<RwLock<RiskState>>>`     // truncated hash of FpKey
- `by_session: DashMap<SessionId, Arc<RwLock<RiskState>>>`

On `apply(key, deltas)`:
1. Look up each leg; if missing, create new `Arc<RwLock<RiskState>>` and insert into ALL three indices (or as many legs as `key` has).
2. **CRITICAL:** the three lookups MUST resolve to the SAME `Arc` for a given actor. On read-miss for one leg but hit on another, clone the existing `Arc` into the missing index — do NOT create a fresh state.
3. On state collision (different `Arc` per leg, e.g. legs converged after divergence), merge by taking max-state and unifying the `Arc` across indices. Document this as the "merge on collide" rule.
4. Acquire `RwLock` write, append deltas, return clone of post-update `RiskState`.

On `read(key)`: look up each leg, take `max(score)` across found states.

### RiskState Layout

```rust
// state.rs — under 200 LoC budget
pub struct RiskState {
    pub raw_score: i32,                      // pre-clamp accumulator (audit)
    pub clamped_score: u8,                   // 0..=100, runtime decision uses this
    pub last_updated_ms: i64,
    pub created_ms: i64,
    pub contributors: SmallVec<[Contributor; 8]>,  // most-recent 8 events
    pub clean_streak: u32,                   // consecutive normal requests
    pub pinned_until_ms: Option<i64>,        // FR-028 honeypot floor
}

pub struct Contributor {
    pub kind: ContributorKind,               // Rule(rule_id), Anomaly, Seed, Signal(name)
    pub delta: i16,                          // signed; negative for credits
    pub ts_ms: i64,
}
```

> SmallVec inline cap = 8. Beyond that, oldest evicted; full record lives in audit log (P3+ wires the log).

## Related Code Files

**Create (kebab-case, snake_case for `.rs` per Rust convention):**
- `crates/waf-engine/src/risk/mod.rs`
- `crates/waf-engine/src/risk/key.rs`
- `crates/waf-engine/src/risk/state.rs`
- `crates/waf-engine/src/risk/score.rs`
- `crates/waf-engine/src/risk/decay.rs`
- `crates/waf-engine/src/risk/threshold.rs`
- `crates/waf-engine/src/risk/tier.rs`
- `crates/waf-engine/src/risk/config.rs`
- `crates/waf-engine/src/risk/reload.rs`
- `crates/waf-engine/src/risk/scorer.rs`
- `crates/waf-engine/src/risk/store/mod.rs`
- `crates/waf-engine/src/risk/store/store_trait.rs`
- `crates/waf-engine/src/risk/store/memory.rs`
- `crates/waf-engine/src/risk/store/conformance.rs`
- `crates/waf-engine/src/risk/tests/lifecycle_smoke.rs`
- `crates/waf-engine/src/risk/tests/threshold_boundaries.rs`
- `crates/waf-engine/src/risk/tests/identity_triple.rs`
- `crates/waf-engine/src/risk/tests/reset_state.rs`
- `crates/waf-engine/benches/risk_skeleton.rs` (criterion)
- `configs/risk.yaml` (default risk config snippet, loaded by main config)

**Modify:**
- `crates/waf-engine/src/lib.rs` — `pub mod risk;`
- `crates/waf-engine/src/checker.rs` — register `Scorer` as a `Check`; place AFTER existing detection checks so all sync deltas land before threshold gate.
- `crates/waf-engine/Cargo.toml` — add `smallvec = { version = "1", features = ["serde"] }` if not present.
- `configs/*.toml` (or YAML root) — wire `risk:` section into top-level config crate.
- `docs/system-architecture.md` — section: "Risk Scoring (FR-025)" with the triple-index diagram.

## Implementation Steps

1. **Module skeleton.** Create `risk/mod.rs` with empty re-exports. Add `pub mod risk;` to `lib.rs`. Run `cargo check -p waf-engine` — must pass.
2. **Types (`key.rs`, `state.rs`).** Define `RiskKey`, `SessionId`, `RiskState`, `Contributor`, `ContributorKind`. Derive `Clone, Debug` everywhere; `Serialize, Deserialize` on persistable types. `fp_hash` via `xxhash-rust` (already in workspace) — truncate `FpKey` to `u64`.
3. **Pure functions.** `score.rs` (`fold(state, deltas, now)` → updated state), `decay.rs` (`apply_decay(state, now)` with MAX_DECAY=50 floor), `threshold.rs` (`decide(score, cfg, override_block)` → `WafAction`). Each ≤80 LoC, exhaustive unit tests on boundaries.
4. **Store trait.** `store/store_trait.rs` — exact signatures from brainstorm §3.2. Document the "merge on collide" rule on the `apply` method.
5. **Memory backend.** `store/memory.rs` — three `DashMap`s + shared `Arc<RwLock<RiskState>>`. Implement triple-index on insert, max-on-read, atomic `reset_all` via swap-with-empty (NOT iterate-and-clear). TTL eviction in background `tokio::spawn` task on `MemoryRiskStore::start_purge_loop()`.
6. **Conformance suite.** `store/conformance.rs` — `pub async fn run_all<S: RiskStore>(store: S)` with parameterized test cases (insert/read/triple-merge/reset/ttl). Memory backend tests call this; Redis backend (P7) reuses.
7. **Scorer orchestrator.** `scorer.rs` — implements `Check` trait. Pulls IP/fp/session from `RequestCtx`, builds `RiskKey`, calls `store.apply(key, sync_deltas, now)` (sync_deltas empty in P1), applies threshold gate, sets `X-WAF-Risk-Score` response header, returns `Action::Allow/Challenge/Block`.
8. **Config + hot-reload.** `config.rs` — `RiskConfig` struct, serde from YAML. `reload.rs` — `notify` watcher swaps `ArcSwap<RiskConfig>`. Mirror `device_fp/reload.rs` byte-for-byte.
9. **Wire into pipeline.** `checker.rs` — push `Scorer::new(store, cfg)` onto check chain AFTER all existing detectors. Verify order via integration test (header always present).
10. **Tests.** Lifecycle smoke (req in → score 0 → header set → Allow), threshold boundaries (0/29/30/69/70/100), identity-triple max (insert under fp leg, read under ip leg returns same score), `reset_all` atomicity (concurrent reads during reset see either pre or post — never partial).
11. **Bench.** `benches/risk_skeleton.rs` — `decide` ≤ 10µs, `fold(empty)` ≤ 5µs, `MemoryStore::apply` warm path ≤ 50µs.
12. **Compile gates.** `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test -p waf-engine`. All green.

## Success Criteria

- [ ] `cargo check -p waf-engine` passes after each step.
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` zero warnings.
- [ ] All unit tests in `risk/tests/` green.
- [ ] Conformance suite green for `MemoryRiskStore`.
- [ ] Integration test: HTTP GET / → response has `X-WAF-Risk-Score: 0` header.
- [ ] Threshold-boundary test: scores 0,29 → Allow; 30,69 → Challenge; 70,100 → Block.
- [ ] Identity-triple test: state inserted via fp leg readable via ip leg with same score.
- [ ] `reset_all` test: 100 concurrent readers + 1 reset — no panic, no half-state observed.
- [ ] Bench: `decide` p99 ≤ 10µs, `apply` warm p99 ≤ 50µs.
- [ ] Hot-reload test: edit `configs/risk.yaml` t_block 70→60 → next request reflects.
- [ ] Zero `.unwrap()` / `.expect()` outside `#[cfg(test)]` (grep verified).
- [ ] Each new file ≤ 200 LoC (project rule).

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Triple-index divergence (three independent states for same actor) | High | Merge-on-collide rule + integration test that creates divergence then merges |
| Lock contention on `RwLock<RiskState>` at 5k rps | Medium | `parking_lot::RwLock` (no poison, fast); DashMap shards spread keys; bench gate |
| TTL purge task starves under load | Low | Bounded sweep (≤1k entries per tick), tracing instrumentation |
| `ArcSwap` config read on every request adds latency | Low | Already proven pattern in FR-005/FR-010 — same shape |
| Header injection on cached responses (FR-009) | Medium | Defer integration to P5; document cross-team flag in plan.md open questions |

## Verify

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p waf-engine risk::
cargo bench -p waf-engine --bench risk_skeleton
# Integration smoke
curl -sI http://localhost:16880/ | grep -i x-waf-risk-score
```
