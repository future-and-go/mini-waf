---
phase: 1
title: "Actor-Keyed Sync Submit Seam"
status: completed
priority: P2
dependencies: []
---

# Phase 1: Actor-Keyed Sync Submit Seam

## Overview

Add a sync, IP-keyed submit path to the `RiskAggregator` trait and thread the
actor IP through the ingest pipeline (`Job` → worker → `RiskKey`). After this
phase, a caller on the sync request path can credit risk to a real actor
(IP axis) without any async bridge.

## Requirements

- Functional: `submit_ip(ip, signals)` enqueues without blocking; worker
  resolves it to `RiskKey { ip: Some(ip), .. }` so deltas join the
  request-path actor via the store's `by_ip` index.
- Non-functional: no `block_in_place`/`block_on`; no new dependency from
  `device_fp` onto `risk` (use std `IpAddr`, not `RiskKey`).

## Architecture

```
sync request path                    async ingest
RiskBumpAction ──submit_ip(ip)──▶ ScoringAggregator ──try_send(Job{actor_ip})──▶ worker
                                                                                  │
                                              RiskKey{ip: Some(ip), fp_hash} ◀───┘
                                              store.apply → by_ip index = real actor
```

`mpsc::Sender::try_send` is sync — `submit_ip` needs no runtime at all.

## Related Code Files

- Modify: `crates/waf-engine/src/device_fp/aggregator.rs`
- Modify: `crates/waf-engine/src/risk/ingest/worker.rs`
- Modify: `crates/waf-engine/src/risk/ingest/aggregator_impl.rs`

## Implementation Steps

1. **`device_fp/aggregator.rs` — trait method** (sync, required — only 3
   in-crate impls, compiler flags each):

   ```rust
   /// Submit signals credited to an actor identified by client IP.
   /// Sync and non-blocking by contract (queue fan-out, drop-with-warn on
   /// overflow) — callable from the request path without a runtime.
   fn submit_ip(&self, ip: IpAddr, signals: &[Signal]);
   ```

   Update the module-top FR-025 contract docs (skeleton) to mention both
   submit paths. Add `use std::net::IpAddr;`.

2. **`NoopAggregator`**: implement as debug-log drop (mirror `submit`).

3. **`LoggingAggregator`**: extend `AggregatorSubmission` with
   `pub actor_ip: Option<IpAddr>` (test/dev type — in-crate construction
   only). Async `submit` records `actor_ip: None`; `submit_ip` records
   `key: FpKey::default(), actor_ip: Some(ip)`. Fix the two struct-literal
   construction sites in `aggregator.rs`; existing assertions on
   `.key`/`.signals` keep compiling.

4. **`risk/ingest/worker.rs` — `Job` gains the IP axis**:
   - Fields become `fp_key: Option<FpKey>`, `actor_ip: Option<IpAddr>`
     (keep `signals`, `submitted_ms`).
   - Constructors: `Job::for_fp(fp_key, signals, ms)` and
     `Job::for_ip(ip, signals, ms)`; migrate existing `Job::new` call sites
     (worker tests, aggregator_impl).
   - `process_job`: build
     `RiskKey { ip: job.actor_ip, fp_hash: job.fp_key.as_ref().and_then(RiskKey::hash_fp_key), session: None }`;
     drop with `inc_dropped_key_unresolved` only when **both** axes are
     `None`.

5. **`risk/ingest/aggregator_impl.rs` — `ScoringAggregator`**:
   - Extract the existing `try_send` + metrics match into a private sync
     `enqueue(&self, job: Job)` helper.
   - `async fn submit` → `self.enqueue(Job::for_fp(..))` (unchanged
     semantics).
   - `fn submit_ip` → `self.enqueue(Job::for_ip(..))`; early-return on empty
     signals, same as `submit`.

6. Unit tests (this phase):
   - worker: job with `actor_ip` only → state readable at
     `RiskKey::from_ip(ip)`; job with both axes `None` → dropped with
     `dropped_key_unresolved` metric.
   - `ScoringAggregator::submit_ip` enqueues and worker processes (mirror
     `submit_enqueues_job`), **without** wrapping in `block_in_place`.
   - `LoggingAggregator::submit_ip` records `actor_ip`.

## Success Criteria

- [ ] `submit_ip` is sync (no `async`, no `block_on` anywhere in impls).
- [ ] Worker maps `actor_ip` job → `RiskKey { ip: Some(ip) }` and
      `store.read(RiskKey::from_ip(ip))` sees the applied contributors.
- [ ] Existing FpKey path behavior unchanged (all current
      `risk::ingest` + `device_fp::aggregator` tests pass).
- [ ] `cargo test -p waf-engine risk::ingest device_fp::aggregator` green.

## Risk Assessment

- Trait change ripple: `RiskAggregator` has exactly 3 impls, all in
  `waf-engine` (verified by grep). External crates only consume
  `Arc<dyn RiskAggregator>` — adding a method is compile-checked, not silent.
- `AggregatorSubmission` field addition breaks only in-crate struct literals;
  compiler-guided.
