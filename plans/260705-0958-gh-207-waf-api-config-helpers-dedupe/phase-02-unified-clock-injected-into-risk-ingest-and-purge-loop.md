---
phase: 2
title: "Unified Clock injected into risk ingest and purge loop"
status: completed
effort: "2h"
---

# Phase 2: Unified Clock injected into risk ingest and purge loop

## Overview

Collapse the three clock idioms in the risk pipeline onto the existing `Clock`
trait. Promote `Clock`/`SystemClock`/`MockClock` to a neutral `crate::time`
module (so risk does not depend on ddos detector internals), inject it into
`ScoringAggregator` + the ingest worker + `start_purge_loop`, and delete
`unix_now_ms`. Behavior-preserving: production defaults to `SystemClock` (same
wall-clock as today); the only new capability is mock-clock testability.

## Requirements

- `Clock` trait + `SystemClock` + `test_utils::MockClock` live in one neutral
  module; ddos detector code (`per_tier.rs`, `detector/mod.rs`) compiles unchanged.
- `ScoringAggregator::submit` uses an injected `Clock` instead of `unix_now_ms()`.
- The ingest worker's process/lag timestamp (`worker.rs:75`) uses the **same**
  injected clock, so `lag_ms = now - submitted_ms` is deterministic under one
  `MockClock`.
- `MemoryRiskStore::start_purge_loop` uses an injected `Clock` instead of
  `chrono::Utc::now()` (`memory.rs:50`).
- Production wall-clock behavior identical (default `SystemClock`).

## Files to modify

- Create: `crates/waf-engine/src/time.rs` — move the `Clock` trait, `SystemClock`,
  and `#[cfg(test)] pub mod test_utils { MockClock }` verbatim from
  `checks/ddos/detector/clock.rs:1-30+`.
- Register: `crates/waf-engine/src/lib.rs` — add `pub mod time;` (alphabetical
  slot near `pub mod rules;`). Optionally `pub use time::{Clock, SystemClock};`.
- Shim: `crates/waf-engine/src/checks/ddos/detector/clock.rs` → replace body with
  `pub use crate::time::{Clock, SystemClock};` and (under `#[cfg(test)]`)
  `pub use crate::time::test_utils;`. Keeps `super::clock::Clock`
  (`per_tier.rs:31`), `super::super::clock::test_utils::MockClock`
  (`per_tier.rs:154`), and `detector/mod.rs:17` re-export resolving unchanged.
- `crates/waf-engine/src/risk/ingest/aggregator_impl.rs`:
  - Add field `clock: Arc<dyn crate::time::Clock>` to `ScoringAggregator`.
  - `start` / `start_with_capacity`: default `Arc::new(SystemClock)`; add a
    test-facing `start_with_clock(store, weights, capacity, clock)` (or a
    `clock` param on `start_with_capacity`) that threads the clock into
    `spawn_worker`.
  - `submit`: `let now_ms = self.clock.now_ms();` — delete `fn unix_now_ms`
    (`:99-108`) and the `use std::time::{SystemTime, UNIX_EPOCH}` (`:7`) if orphaned.
- `crates/waf-engine/src/risk/ingest/worker.rs`:
  - `spawn_worker` / `supervised_worker_loop` / `process_job` gain an
    `Arc<dyn Clock>` param; `process_job` replaces `chrono::Utc::now()...` (`:75`)
    with `clock.now_ms()`. Check `worker.rs:146,172,198` — those are in
    `#[cfg(test)]` helpers; leave test-only chrono or pass a `MockClock`
    (implementer's choice, but production `:75` must use the injected clock).
- `crates/waf-engine/src/risk/store/memory.rs`:
  - `start_purge_loop(self: &Arc<Self>, ttl_ms, interval_secs, clock: Arc<dyn Clock>)`;
    replace `chrono::Utc::now().timestamp_millis()` (`:50`) with `clock.now_ms()`.
    Zero production callers today, so the signature change touches tests only.

## Out of scope (leave as-is)

- `risk/store/redis.rs:574`, `risk/tests/conformance_redis.rs:16`,
  `risk/tests/redis_failover.rs:18` — `timestamp_nanos` unique-id seeds, not
  pipeline wall-clock. Do not touch.

## Implementation Steps

1. Read `aggregator_impl.rs`, `worker.rs`, `memory.rs`, `detector/clock.rs`, and
   `per_tier.rs` import lines fully; confirm no other `super::clock` importers via
   `grep -rn "clock::" crates/waf-engine/src`.
2. Create `time.rs` (move contents), register in `lib.rs`, convert
   `detector/clock.rs` to the re-export shim. Build `-p waf-engine` → ddos tests
   still compile.
3. Inject `Clock` into `ScoringAggregator` (field + ctors + submit); thread into
   `spawn_worker` → `process_job`; delete `unix_now_ms`.
4. Add `clock` param to `start_purge_loop`; update its test callers.
5. Add one aggregator test: `MockClock::new(t0)`, submit signals, advance clock,
   assert the worker's `lag_ms` / applied `now_ms` reflects the mocked time
   (proves the aggregator is now mock-clock testable — the issue's core ask).

## Tests / Validation

- Baseline: `cargo test -p waf-engine risk::` and `... checks::ddos::` green on
  HEAD before edits.
- After: same suites green; new aggregator mock-clock test passes.
- `cargo build -p waf-engine`, `cargo clippy -p waf-engine --all-targets` clean.

## Risks & Rollback

- **Risk (Low):** shim re-export path mismatch breaks ddos `MockClock` test
  imports. Mitigation: keep `test_utils` re-exported under `#[cfg(test)]`; build
  ddos tests first (step 2) before touching risk.
- **Risk (Low):** threading `Clock` through `spawn_worker` changes a public-ish
  fn signature. Mitigation: `spawn_worker`/`start*` have no production callers
  (grep-verified); only tests/doc adjust. If a caller appears, default-`SystemClock`
  overloads keep the common path call-site-compatible.
- **Rollback:** revert commit; `crate::time` is additive and the shim is a pure
  re-export, so reverting restores the original `clock.rs` with no data/state.

## Success Criteria

- [ ] `crate::time::{Clock, SystemClock, test_utils::MockClock}` exists; ddos
      detector compiles via the shim with no import edits in `per_tier.rs`.
- [ ] `unix_now_ms` deleted; `ScoringAggregator` + worker + `start_purge_loop`
      take a `Clock`; production defaults to `SystemClock`.
- [ ] Pipeline `chrono` at `memory.rs:50` and `worker.rs:75` replaced; unique-id
      `timestamp_nanos` usages untouched.
- [ ] Mock-clock aggregator test proves deterministic submit→process timing.
- [ ] `cargo test -p waf-engine` risk + ddos suites green before/after; clippy clean.
