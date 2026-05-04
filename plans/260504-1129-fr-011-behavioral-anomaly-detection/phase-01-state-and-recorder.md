---
phase: 1
title: "State and Recorder"
status: completed
priority: P1
effort: "1d"
dependencies: []
---

# Phase 1: State and Recorder

## Overview

Build the per-actor sliding-window state struct + lock-free `Recorder` (DashMap-keyed by `FpKey`) + TTL janitor. This is the foundation; all four classifiers read from it. No Pingora wiring yet — pure data layer with unit tests.

## Requirements

- **Functional:** `Recorder::record(key, sample)` upserts in O(1); ring-buffer keeps last `WINDOW`(=16) `Sample`s; `distinct_paths` bounded to 8; janitor evicts entries idle > `actor_ttl_secs`.
- **Non-functional:** <1 µs typical write; bounded memory ~448 B per actor; thread-safe under tokio multi-task contention; zero allocs in hot path.

## Architecture

```
crates/waf-engine/src/device_fp/behavior/
├── mod.rs              (re-exports + module wiring)
├── state.rs            (Sample, ActorBehavior, ring buffer)
├── recorder.rs         (Recorder struct, DashMap, janitor task)
└── config.rs           (BehaviorConfig stub — fully fleshed in Phase 5)
```

Reuse:
- `FpKey` from `device_fp::types` (do **not** invent a new key — DRY).
- Janitor pattern from `device_fp::identity::memory::spawn_janitor` (verbatim copy with adjusted closure).
- DashMap usage pattern from `checks::rate_limit/`.

### State shape

```rust
pub(crate) const WINDOW: usize = 16;

#[derive(Clone, Copy)]
pub(crate) struct Sample {
    pub ts_ms: u64,        // monotonic ms since Recorder boot (NOT wall clock)
    pub path_hash: u64,    // xxhash64 of normalized path
    pub had_referer: bool,
    pub tier: Tier,        // CRITICAL/HIGH/MEDIUM/CATCH_ALL — reuse existing rule-tier enum
}

pub(crate) struct ActorBehavior {
    samples: ArrayDeque<Sample, WINDOW>, // arraydeque crate (already in workspace? check)
    distinct_paths: ArrayVec<u64, 8>,
    updated_ms: u64,
}
```

If `arraydeque` not in workspace, hand-roll a fixed-array ring (no `Vec`) — must stay alloc-free.

## Related Code Files

- **Create:**
  - `crates/waf-engine/src/device_fp/behavior/mod.rs`
  - `crates/waf-engine/src/device_fp/behavior/state.rs`
  - `crates/waf-engine/src/device_fp/behavior/recorder.rs`
  - `crates/waf-engine/src/device_fp/behavior/config.rs` (stub: window_size, actor_ttl_secs only)
- **Modify:**
  - `crates/waf-engine/src/device_fp/mod.rs` — add `pub mod behavior;`
  - `crates/waf-engine/Cargo.toml` — add `arraydeque` and `xxhash-rust` if missing (verify first)
- **Reference (read only):**
  - `crates/waf-engine/src/device_fp/identity/memory.rs` (janitor pattern)
  - `crates/waf-engine/src/device_fp/types.rs` (`FpKey`)

## Implementation Steps

1. Verify dependency availability: `cargo tree -p waf-engine | grep -E 'arraydeque|xxhash|arrayvec'`. Add what's missing to `crates/waf-engine/Cargo.toml`.
2. Create `state.rs` (<80 LOC): `Sample`, `Tier` re-export, `ActorBehavior` with `record(sample)`, `intervals_ms()` iterator, `distinct_paths_len()` accessor. Monotonic `u64` ms via `Instant::elapsed().as_millis() as u64` — store anchor `Instant` in `Recorder`, not in `Sample`.
3. Create `recorder.rs`:
   - `pub struct Recorder { actors: DashMap<FpKey, ActorBehavior, ahash::RandomState>, anchor: Instant, cfg: Arc<ArcSwap<BehaviorConfig>> }`
   - `pub fn record(&self, key: &FpKey, path: &str, had_referer: bool, tier: Tier)` — hashes path, computes ts_ms, calls `entry().or_insert_with().record(...)`.
   - `pub fn snapshot(&self, key: &FpKey) -> Option<ActorBehaviorSnapshot>` — clones the small bounded state for classifier reads (avoids holding shard lock across classifier eval).
   - `pub fn spawn_janitor(self: Arc<Self>, period: Duration) -> JoinHandle<()>` — copy from `identity::memory::spawn_janitor`.
4. Create `config.rs` stub: `BehaviorConfig { window_size: u16, actor_ttl_secs: u32 }` with sane defaults. Full schema in Phase 5.
5. Wire `mod.rs` and add `pub mod behavior;` to `device_fp/mod.rs`.
6. Run `cargo check -p waf-engine` and `cargo clippy -p waf-engine -- -D warnings` until clean.
7. Write unit tests in `recorder.rs` and `state.rs`:
   - ring wraps at `WINDOW` (push 20 → len == 16, oldest dropped).
   - `distinct_paths` caps at 8 (push 12 distinct → len == 8).
   - clone semantics for snapshot.
   - `record` upserts (new key creates entry).
   - concurrent inserts: 100 tokio tasks × 100 keys, no panics, all keys present.
   - janitor: insert → advance time → `purge_expired` → entry gone.
8. `cargo test -p waf-engine device_fp::behavior` — all green.

## Success Criteria

- [ ] `cargo check -p waf-engine` clean.
- [ ] `cargo clippy -p waf-engine --all-targets -- -D warnings` clean.
- [ ] `cargo test -p waf-engine device_fp::behavior` — all unit tests pass.
- [ ] Zero `.unwrap()` / `.expect()` outside `#[cfg(test)]` (Iron Rule 1).
- [ ] No `std::sync::Mutex`; only `DashMap` + `parking_lot` if any sync primitive needed.
- [ ] `state.rs` ≤ 80 LOC, `recorder.rs` ≤ 200 LOC.
- [ ] Bounded memory verified: `std::mem::size_of::<ActorBehavior>()` documented in test assertion.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Wall-clock jumps backward → negative intervals | Monotonic `Instant` anchor + `u64` ms deltas only. Saturating arithmetic. |
| Unbounded actor map under churn | Janitor + `max_entries` cap (defer cap to Phase 5; document TODO). |
| `arraydeque` not in workspace | Hand-roll fixed-array ring (~30 LOC). Document choice. |
| Holding DashMap shard across classifier eval (deadlock-prone if classifier ever calls back into Recorder) | Snapshot pattern: clone small state out, drop guard, classifier reads snapshot. |

## Security Considerations

- `FpKey` already binds device + IP-class — behavioral state cannot be poisoned by IP rotation alone.
- Path is hashed (xxhash64), not stored — no PII in memory.
- TTL prevents indefinite retention.
