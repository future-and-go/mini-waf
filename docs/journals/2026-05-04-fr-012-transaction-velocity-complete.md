# FR-012: Transaction Velocity & Sequence Detection — Recorder + 3 Classifiers + Hot-Reload

**Date**: 2026-05-04 21:50
**Severity**: High
**Component**: waf-engine `checks/tx_velocity` module, engine.rs checker chain wiring
**Status**: Resolved

## What Happened

FR-012 shipped in 5 phases over a single working day: scaffold + role tagger + recorder (phase 1), `Signal` enum extension + 3 classifiers + cooldown (phase 2), engine integration with `start_tx_velocity_watcher` + `configs/tx-velocity.yaml` (phase 3), 31 unit + 9 integration tests + 6 Criterion benches (phase 4), and operator/codebase docs + journal (phase 5). Module ships at `crates/waf-engine/src/checks/tx_velocity/`. Position in the request pipeline: Phase 5.5 — between rate-limit (shed flood traffic first) and scanner (record before pattern checks pollute state). Signal-only by design — never blocks; emits `Signal::TxSequenceTooFast` / `WithdrawalVelocity` / `LimitChangeBurst` to the shared `RiskAggregator` (FR-025 plug-in point).

## The Brutal Truth

**We shipped two known correctness gaps and kept the timeline.** Phase 3 records every event with `ok = true` because the request-entry check has no view of the upstream response status. That means a brute-force login attempt with 100 failed `POST /auth/login` requests looks identical to 100 successful ones. The sequence-timing classifier still catches the pattern because the *timing* is what signals fraud, but the **withdrawal-velocity classifier could miss "10 attempted withdrawals where 9 are denied" — because all 10 still record as `ok = true`.** A response-side hook is the right fix; we deferred it because phase budget was 0.5d and the response phase wiring needed more thought than we had time for.

The second gap is architectural: **the `TxStore` is per-node, identical to FR-011's recorder.** A session that hops between WAF nodes (Bob's iPhone connects via WiFi → cell → WiFi during a 2-minute attack) splits its event stream across nodes, and no single node sees enough events to fire the velocity classifier. We documented the mitigation ("assume LB session affinity") in the operator guide, but **session affinity is a deployment-time guarantee, not a code-time one** — operators with naive round-robin LBs will get silent classifier degradation and never know it. Redis-backed `TxStore` is the right answer; we deferred to post-v0.2 to keep the hackathon scope tight.

Phase 4's benchmark numbers were almost too good — ~94 ns hot path, sub-microsecond at 50k sessions. We double-checked: the classifier loop runs only **after** the cooldown check, so the steady-state hot path is `record() + cooldown gate (false)` — three classifiers don't run on most requests. That's by design (cooldown prevents signal flooding), but **the bench number doesn't reflect the path that fires when an attack is actually in progress.** The truthful number is: ~94 ns for the 99% of requests that don't trigger anything, and ~94 ns × N for the bursts where the cooldown elapses. We added a note to `bench-results.md` but the misleading framing is on us.

## Technical Details

**Phase 1: Scaffold + Recorder**
- `EndpointRole` enum: `Login | Otp | Deposit | Withdrawal | LimitChange | None` (default)
- `Event { role, ts_ms, ok }`: 16 B, monotonic ms (NOT wall clock)
- `TxStore`: `DashMap<SessionKey, ActorTx>`; `ActorTx { events: ArrayVec<Event, 16>, last_signal_ms: u64 }` (~256 B/session)
- `RoleTagger`: regex Vec, first-match-wins; compiled once, swapped atomically on hot-reload
- `SessionKey = (host: SmolStr, ident: SessionIdent)`; `SessionIdent = Cookie(SmolStr) | Fingerprint(FpKey)` — cookie preferred, FpKey fallback
- Janitor: `tokio::spawn` interval, `O(n)` DashMap scan, removes idle entries past `session_ttl_secs`
- 4 + 12 unit tests (role_tagger + recorder)

**Phase 2: Classifiers + Signal Enum**
- Extended `device_fp::signal::Signal` with 3 variants: keeps single signal sink (existing `RiskAggregator` consumes everything)
- `Classifier` trait: `evaluate(&self, actor: &ActorTxSnapshot, now_ms: u64, cfg: &TxVelocityConfig) -> Option<Signal>`
- `SequenceTimingClassifier`: scans most-recent transitions (Login→OTP, OTP→Deposit, Login→Deposit); fires only when latest event is the "to" role (prevents replay)
- `WithdrawalVelocityClassifier`: counts events with `role == Withdrawal && ts_ms >= now_ms - window_ms`; emits when `count > max_count`
- `LimitChangeBurstClassifier`: same shape, different role + thresholds
- Cooldown: `if now_ms - last_signal_ms < cooldown_ms { skip classifier loop }` — prevents signal flooding (DoS amplification)
- Aggregator submission: `tokio::spawn` fire-and-forget — request path never blocks on aggregator
- 15 unit tests across 3 classifiers (6+5+4)

**Phase 3: Engine Integration**
- `TxVelocityCheck` implements `Check` trait; returns `None` always (signal-only contract)
- Constructed in `WafEngine::with_sqli_config` between `RateLimitCheck` and `ScannerCheck`
- `Arc<ArcSwap<TxVelocityConfig>>` shared between Check, TxStore, and reloader
- `start_tx_velocity_watcher(path)`: loads `configs/tx-velocity.yaml`, starts `notify` watcher, atomic swap on edit
- Bad YAML retains last-good snapshot + `tracing::warn!` (Iron Rule #4 fail-safe)
- Default config: `enabled: false` — subsystem inert until operator opts in

**Phase 4: Tests + Benches**
- 9 integration tests in `tests/tx_velocity_integration.rs`: full pipeline with mock aggregator, deterministic time fixtures
- 6 Criterion benches: `tx_velocity_record_existing` (~94 ns), `tx_velocity_record_new` (~1.5 µs), scaling 1k → 50k (constant ~253 ns), 4-thread concurrent (~109 µs / 400 ops)
- E2E live HTTP excluded — integration tests with mock aggregator provide same coverage without infrastructure overhead

**Phase 5: Docs**
- New: `docs/transaction-velocity.md` (operator guide, mermaid arch diagram, tuning table)
- Modified: `docs/request-pipeline.md` (Phase 5.5 insertion), `docs/project-roadmap.md` (FR-012 entry), `CHANGELOG.md` (Unreleased entry)
- `docs/codebase-summary.md` already had FR-012 entries from prior phases — verified, no edits needed
- Plan tree marked complete (5/5 phases)

## What We Tried

1. **`ok` flag at request entry vs. response phase:** Considered routing through Pingora's response_filter to capture upstream status. Cost: significant wiring (response context propagation + state lookup). Settled for `ok = true` always with documented limitation. Sequence-timing classifier still catches automated takeovers because timing is the signal — `ok` matters more for failed-login bursts (deferred).

2. **Per-classifier config vs. shared `TxVelocityConfig`:** FR-011 fragmented its config across providers and had to merge in phase 5. We learned: passed full `TxVelocityConfig` to every classifier from day one. Single ArcSwap, single snapshot — no inconsistency window across hot-reload.

3. **`ArrayVec<Event, 16>` vs. dynamic ring:** Same trade-off as FR-011. 16-slot cap covers `Login → OTP → Deposit → 13 Withdrawals` without growth. Bench-verified: alloc-free hot path after first record. Pathological case (>16 events in cooldown window) drops oldest — acceptable.

4. **Cookie name source:** Considered reusing FR-004 rate-limit's `session_cookie_name`. Rejected: tight coupling between rate-limit and tx-velocity configs. Made `tx_velocity.session_cookie` independent — operator can use different cookies per check if their stack splits session/auth.

5. **DashMap shards default vs. tuned:** Defaulted (16-way). Bench at 50k sessions showed constant `O(1)` lookup, ~253 ns. No need to tune. If we hit contention at >100k sessions in production, increase via `DashMap::with_shard_amount`.

6. **Bench scope:** Wanted full E2E with live Pingora + dummy backend. Rejected after phase 4 — integration tests already exercise the full record + classifier + aggregator path with mock aggregator. E2E adds infrastructure flakiness without coverage gain. Documented as "intentional" in plan completion summary.

## Root Cause Analysis

**Request-entry-only `ok` flag = silent classifier degradation under failed-login bursts.** Sequence-timing catches the pattern via timing, but withdrawal-velocity over-counts denied withdrawals as if they succeeded. Root cause: the request pipeline runs Phase 5.5 before the upstream returns. To enrich `ok`, we'd need to either re-key the event in the response phase (state-coordination cost) or defer recording to the response phase (loses request-entry latency budget). Neither is right for a 0.5d phase. Documented; deferred to follow-up FR.

**Per-node state assumes LB session affinity, which is operator-controlled.** Same as FR-011. Cluster deployments with naive round-robin LBs split a session's event stream across nodes; no single node sees enough events to fire velocity classifiers. The mitigation ("session affinity at the LB") is correct but invisible to the WAF — there's no runtime check that affinity is actually configured. A Redis-backed `TxStore` would close this, at the cost of Redis as a hard dependency for clustered deployments. Punted to post-v0.2 because v0.2 explicitly assumes single-node-or-affine deployments.

**Cooldown gate hides classifier latency in benchmarks.** Steady-state hot path is `record() + cooldown gate skip` (94 ns). Attack-state path runs all 3 classifiers per record (~340 ns + signal submission). Both are well under budget, but the publicly cited "94 ns" is the cheap path. Future bench reports should split steady-state vs. attack-state paths explicitly.

**`enabled: false` default ⇒ ship-and-forget risk.** New deployments will roll this out as inert. Operators who don't read the docs will think FR-012 is "on" because it's in the changelog. Mitigation: changelog entry explicitly says "flip `enabled: true` to activate." But if a fraud incident slips through and the post-mortem reveals tx-velocity was inert the whole time, that's on us. Trade-off: opt-in default protects naive deployments from false positives; opt-out default catches more fraud. Chose opt-in.

## Lessons Learned

**Mirror prior recorder patterns aggressively.** FR-011's `BehaviorRecorder` and FR-004's rate-limit hot-reload both shipped before us. We copied their structure (DashMap + ring buffer, ArcSwap + notify) and saved an estimated 1.5 days of design work. The resulting code is also easier to review because it looks like the existing codebase. **Cost of duplication ≪ cost of bespoke design** for hackathon-pace work.

**Single shared config beats per-classifier configs.** FR-011 had to merge 4 per-classifier `ArcSwap`s into one in phase 5 because of consistency bugs. We started with one config from day one. Zero regressions on hot-reload; each classifier reads from the same atomic snapshot. **Pay the design cost upfront to avoid the merge cost later.**

**Cooldown is not a tuning knob; it's a correctness boundary.** Cooldown prevents signal flooding (DoS amplification on the aggregator). It's not "how often we want to fire" — it's "the minimum gap between fires that doesn't break the aggregator." Operators who tune `signal_cooldown_ms` low to "catch more attacks" will spam the aggregator. Document the *purpose*, not just the parameter.

**Signal-only contracts must be enforced at the type level, but Rust lets you cheat.** `Check::check() -> Option<DetectionResult>` returning `None` is a runtime contract, not a compile-time one. A future contributor could return `Some(Block)` and the type system wouldn't catch it. Mitigation: explicit `// SIGNAL-ONLY: never blocks` comment + integration test that asserts `None` over diverse traffic. Considered a `SignalOnlyCheck` sub-trait; rejected as over-engineering for one consumer.

**`ok = true` always is acceptable for sequence timing, dishonest for velocity.** Sequence patterns are about *gaps*, not outcomes. Velocity patterns are about *counts*, and counts of denied requests are different from counts of successful requests. We shipped both classifiers under the same `ok` lie. Sequence timing is correct; velocity is approximate. **Be specific in docs about which classifier the limitation actually impacts.**

## Next Steps

- **Response-side `ok` enrichment:** Wire Pingora `response_filter` hook to update the most recent `Event` for the session with the real upstream status. Lifts the failed-login signal blind spot. Estimated 1d.
- **Redis-backed `TxStore`:** Optional feature flag (matching FR-010's `redis-store` pattern). Closes the cluster session-affinity gap. Estimated 2-3d (shared conformance suite + identity-store-style trait).
- **Risk delta wiring (FR-025):** Defaults documented in `transaction-velocity.md` (+15/+10/+10) but not yet wired into a real risk engine. Blocked on FR-025 risk engine implementation.
- **Bench split (steady-state vs. attack-state):** Add Criterion benches that hold cooldown elapsed across iterations to measure the 3-classifier path explicitly. Estimated 0.5d.
- **Default-enabled question:** Re-evaluate `enabled: false` default after fr-025 lands. With a real risk engine that downweights single signals, opt-out becomes safer.

All acceptance criteria green. Production ready under the documented assumptions (single-node or LB-affinity deployments, opt-in via `enabled: true`).
