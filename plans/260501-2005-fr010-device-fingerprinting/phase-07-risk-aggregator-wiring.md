# Phase 07 — RiskAggregator Trait + Noop Default + Signal Wiring

**Status:** completed (2026-05-02) | **Priority:** P0 | **Effort:** S | **Blocked by:** phase-06

## Context

FR-025 (cumulative risk scorer) not shipped yet. Define stable `RiskAggregator` trait now with `NoopAggregator` default so FR-010 emits signals to a clean interface. FR-025 plugs in later w/ zero churn in `device_fp/`.

## Requirements

### Functional
- `RiskAggregator::submit(fp_key, signals)` async, fire-and-forget semantics from caller's POV (no result needed)
- `NoopAggregator` logs at debug level + returns
- `LoggingAggregator` (test/dev) records to in-memory ring buffer for assertions
- `DeviceFpDetector::process(req)` runs capture → fingerprint → store observe → providers → aggregator submit, returns `DeviceIdentity` for downstream consumers

### Non-functional
- Aggregator submit bounded — caller never blocks on slow consumer
- Channel-based design (tokio mpsc) so aggregator can be a separate task

## Files

**Created:**
- `crates/waf-engine/src/device_fp/aggregator/mod.rs`
- `crates/waf-engine/src/device_fp/aggregator/noop.rs`
- `crates/waf-engine/src/device_fp/aggregator/logging.rs` (test util)
- `crates/waf-engine/src/device_fp/detector.rs` — `DeviceFpDetector::process` end-to-end

**Modified:**
- `crates/gateway/src/proxy.rs` — call `DeviceFpDetector::process` in early request filter
- `crates/waf-engine/src/device_fp/mod.rs` — re-export aggregator types

## Steps

1. Define `RiskAggregator` trait in `aggregator/mod.rs` w/ rustdoc covering FR-025 contract
2. Implement `NoopAggregator` (debug log only)
3. Implement `LoggingAggregator` for tests (records last N submissions in `Mutex<VecDeque>`)
4. Implement `DeviceFpDetector::process(req_ctx) -> DeviceIdentity`:
   - Pull `RawCapture` from ConnCtx
   - Run all `FingerprintProvider`s → `FingerprintValue`s → composite `FpKey`
   - `IdentityStore::observe()` → `Observation`
   - Build `DeviceCtx { fp_key, observation, request_ua, request_ip, ... }`
   - Run all `SignalProvider`s → `Vec<Signal>`
   - `aggregator.submit(fp_key, signals)`
   - Return `DeviceIdentity` (attach to request ctx)
5. Wire into `gateway/src/proxy.rs` request filter pipeline (before rule engine)
6. Integration test: end-to-end request → expected signals captured in `LoggingAggregator`
7. Document FR-025 plug-in contract in `docs/system-architecture.md`

## Todos

- [x] `RiskAggregator` trait + rustdoc (FR-025 contract documented in module + system-architecture.md)
- [x] `NoopAggregator` (debug log added)
- [x] `LoggingAggregator` (bounded ring buffer)
- [x] `DeviceFpDetector::process` end-to-end (capture → fp → store observe → providers → aggregator)
- [x] Gateway proxy wiring (`request_filter`, after relay detector)
- [x] Integration test: synthetic h2 anomaly + UA blocklist captured in `LoggingAggregator`
  - Deferred: real curl-impersonate handshake harness (needs L4 capture wiring from phase-03-sub)
- [x] Document FR-025 plug-in contract (`docs/system-architecture.md`)
- [ ] Deferred: <5µs noop overhead bench (phase-09 perf gate)

## Success Criteria

- End-to-end integration test: TLS handshake from curl-impersonate → `LoggingAggregator` records expected `H2Anomaly` + `UaBlocklisted` signals
- Default Noop path adds <5µs over no-fingerprinting baseline (bench)
- FR-025 contract documented w/ trait location + example impl skeleton

## Risks

- Proxy filter ordering: must run before rule engine but after IP normalization → confirm w/ existing pipeline
- `submit` blocking aggregator → use `try_send` w/ channel; drop + warn on full

## Next

Phase 08 — Redis store. Phase 09 — coverage gate + perf bench + docs.
