---
title: "FR-012 close TODOs: device_fp plumbing + response-side ok enrichment"
description: "Close two deferred gaps in tx_velocity/check.rs — pass FpKey from device-fp pipeline into session-key extraction, and enrich Event.ok with real upstream status before classifiers evaluate."
status: complete
priority: P2
branch: "main"
tags: [fr-012, fr-010, tx-velocity, device-fp, behavioral]
blockedBy: []
blocks: []
created: "2026-05-30T16:31:56.567Z"
createdBy: "ck:plan"
source: skill
---

# FR-012 close TODOs: device_fp plumbing + response-side ok enrichment

## Overview

`crates/waf-engine/src/checks/tx_velocity/check.rs` ships with two deferred items left over from FR-012 phase-03:

1. **Line 55 (`TODO: FR-010 integration`)** — `extract_session_key(ctx, &snapshot.session_cookie, None)` passes `None` for the fingerprint fallback. Sessions without a `SESSIONID` cookie are silently dropped from velocity tracking even when device-fp has resolved a JA3/JA4/H2 key for them.
2. **Line 60 (`response-side enrichment of ok deferred`)** — `store.record(&key, role, true)` hard-codes `ok = true`. Classifiers (in particular `WithdrawalVelocityClassifier`) cannot tell a successful 2xx withdrawal apart from a 4xx/5xx rejection.

Both items also distort the FR-025 risk score: cookie-less mobile clients are invisible to the velocity scorer, and failed-withdrawal bursts look identical to honest activity.

## Decisions (locked via /ck:plan validation + red-team adjudication)

1. **Velocity classifier semantics** → emit a richer signal carrying BOTH `count` (attempts) AND `ok_count` (successful 2xx). Keeps current burst detection AND exposes success-rate to FR-025 weighting. Same change applies to `LimitChangeBurst`. (window+ring scoped — see Phase-04 doc note.)
2. **Classifier eval timing** → move all classifier evaluation out of `TxStore::record()` and into `TxStore::set_outcome()`. Request-entry appends an `Event { outcome: Outcome::Pending, … }`; gateway `logging()` hook calls `set_outcome` which flips the slot to `Ok` or `Failed` and runs the pipeline once. Classifiers ignore `Pending` events.
   - **(Red-team C7 + C9 fix)** Tristate `Outcome::{Pending, Ok, Failed}` instead of `bool` — solves WAF-blocked ring-poisoning (Pending stays Pending forever, never counted) AND mobile-retry inflation (a Pending event within `dedupe_window_ms` re-uses its slot instead of appending a new one).
3. **FpKey plumbing** → add `device_fp: Option<Arc<FpKey>>` to `waf_common::RequestCtx`. Requires moving `FpKey` + `FingerprintValue` from `waf-engine::device_fp::types` into `waf-common::types` (re-exported from the old path to keep all current imports working).
4. **Event token in RequestCtx** → `RequestCtx` also carries `tx_velocity_token: Option<TxEventToken>`. `record()` returns the token; `set_outcome(token, outcome)` flips that exact slot — kills the H2-mux race, hot-reload orphan, and replay-flip in one move. (Red-team C1.)
5. **Fingerprint bucket includes `peer_ip`** → `SessionIdent::Fingerprint { fp: FpKey, ip: IpAddr }`. Shared CDN JA3 cannot bucket thousands of victims under one identity. (Red-team C7.)
6. **`set_outcome` dispatch moved to `logging()` hook** → not `response_filter`. Fires at request completion (post-body), works correctly for streaming responses, and decouples from FR-018's `upstream_contacted` gate. (Red-team C2 + C8.)
7. **`impl Default for RequestCtx`** → added in Phase-02 to amortize the 164-fixture maintenance cost — every future field-add lands as one line in a `..Default::default()` spread. (Red-team C5.)

## Architecture

```
Pingora request_filter
  └─ device_fp pipeline resolves FpKey  ─────────────┐
  └─ RequestCtxBuilder.with_device_fp(fp)            │
  └─ WafEngine.evaluate(ctx)                         │
      └─ TxVelocityCheck.check(&mut ctx)  ─ consumes ┘
          └─ extract_session_key(ctx, cookie, ctx.device_fp.as_deref(), ctx.client_ip)
          └─ token = TxStore.record(&key, role)        ← returns TxEventToken
              └─ NO classifier eval here
          └─ ctx.tx_velocity_token = Some(token)

Pingora logging() hook   (NOT response_filter — fires at request completion)
  └─ WafEngine.on_request_complete(ctx, status, upstream_reached)
      └─ TxVelocityCheck.on_request_complete(ctx, status, upstream_reached)
          └─ if !upstream_reached → skip (Pingora-synthesized error / WAF block)
          └─ if let Some(tok) = ctx.tx_velocity_token { ... }
          └─ outcome = if (200..300).contains(&status) { Ok } else { Failed }
          └─ TxStore.set_outcome(tok, outcome)
              └─ flip exact slot (no role-walk race)
              └─ if generation mismatch (slot evicted) → no-op
              └─ run classifiers ONCE on the corrected snapshot
              └─ emit Signal::WithdrawalVelocity { count, ok_count, window_sec }

WAF blocks at gate
  └─ on_response never fires for this ctx
  └─ Event stays Outcome::Pending forever
  └─ Classifiers IGNORE Pending events → no ring poisoning
  └─ janitor purges actor after session_ttl_secs
```

`Event { outcome }` tristate: `Pending` (request recorded, no response yet), `Ok` (2xx), `Failed` (4xx/5xx). Classifiers count only `Ok | Failed`. WAF-blocked / streaming-abandoned / dropped-connection events stay `Pending` and never feed the classifier — matches operator intuition that only completed requests count.

**Token shape:**
```rust
pub struct TxEventToken {
    pub key: SessionKey,
    pub slot: u8,         // 0..WINDOW (=16)
    pub generation: u32,  // incremented on ring wrap; mismatched gen = no-op
}
```
`generation` defeats the slot-was-evicted race: if the actor's ring wrapped between `record()` and `set_outcome()`, the token's generation no longer matches and the flip is dropped cleanly.

## Mode

`--deep --tdd`. Each phase opens with the failing test(s) that capture the gap, then makes them pass. No code lands before its test does.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Hoist FpKey to waf-common](./phase-01-hoist-fpkey-to-waf-common.md) | Complete |
| 2 | [Plumb device_fp into RequestCtx](./phase-02-plumb-device-fp-into-requestctx.md) | Complete |
| 3 | [Defer classifier eval to on_response](./phase-03-defer-classifier-eval-to-on-response.md) | Complete |
| 4 | [Two-signal payload (count + ok_count)](./phase-04-two-signal-payload-count-ok-count.md) | Complete |
| 5 | [Gateway wiring + tests + docs](./phase-05-gateway-wiring-tests-docs.md) | Complete |

## Key Files (anchors)

- `crates/waf-engine/src/checks/tx_velocity/check.rs:55-60` — the two TODOs being closed
- `crates/waf-engine/src/checks/tx_velocity/session_key.rs:36` — `extract_session_key` already accepts `Option<&FpKey>`
- `crates/waf-engine/src/checks/tx_velocity/recorder.rs:165-216` — `TxStore::record` (classifier eval moves out)
- `crates/waf-engine/src/checks/tx_velocity/recorder.rs` — `TxStore::set_outcome` (new)
- `crates/waf-engine/src/device_fp/types.rs:21-56` — `FingerprintValue` + `FpKey` (move to `waf-common`)
- `crates/waf-common/src/types.rs:21` — `RequestCtx` (new `device_fp` field)
- `crates/gateway/src/proxy.rs:526-566` — device-fp resolved here, must flow into the builder
- `crates/gateway/src/proxy.rs:867` — `engine.on_response` call site (already exists)
- `crates/waf-engine/src/device_fp/signal.rs:50-53` — `WithdrawalVelocity` + `LimitChangeBurst` variants gain `ok_count`
- `crates/waf-engine/src/checks/tx_velocity/classifiers/withdrawal_velocity.rs` — classifier updated
- `crates/waf-engine/src/checks/tx_velocity/classifiers/limit_change.rs` — classifier updated

## Dependencies

- **FR-010** complete — `DeviceFpDetector::process` already runs in `proxy.rs:543` and populates `ctx.device_identity`. No FR-010 work required, only plumbing.
- **FR-018** brute-force `on_response` shape (`crates/waf-engine/src/checks/brute_force.rs:125-152`) is the reference pattern.
- **FR-025** risk scorer — consumes the richer `Signal::WithdrawalVelocity { count, ok_count, … }` payload. No breaking change for consumers that match only on the variant name.

## Cross-Plan Scan

Reviewed unfinished plans in `./plans/`:
- `plans/260504-1632-fr-012-transaction-velocity/` — parent plan, status=`complete`. This plan closes the two TODOs explicitly deferred by phase-03 of that work.
- `plans/260501-2005-fr010-device-fingerprinting/` — FR-010 status=complete. No conflict; this plan only consumes FR-010's existing output (`ctx.device_identity.key`).
- `plans/260530-2218-s8-binary-startup-contract/` and `plans/260530-2254-configs-yaml-to-toml-migration/` — current in-flight plans; neither touches `tx_velocity`, `device_fp`, or `RequestCtx`. No blocking relationship.

No `blockedBy` / `blocks` updates required.

## Success Criteria (plan-level)

- [ ] `crates/waf-engine/src/checks/tx_velocity/check.rs:55` TODO removed; cookie-less request with a non-empty `FpKey` records in `TxStore`.
- [ ] `crates/waf-engine/src/checks/tx_velocity/check.rs:60` deferred comment removed; `Event.outcome` reflects upstream 2xx outcome (or stays `Pending` when origin not reached).
- [ ] New tests fail on `main` and pass after this plan lands (TDD gate per phase).
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo test --workspace` passes; existing `tx_velocity` recorder tests adapted to new eval timing.
- [ ] Iron Rule #1 honored — no new `.unwrap()` / `.expect()` outside `#[cfg(test)]`.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| `FpKey` move breaks downstream re-exports | Keep `pub use waf_common::FpKey;` shim in `waf-engine::device_fp::types` so every existing `use crate::device_fp::types::FpKey` keeps compiling. |
| Classifier eval moved to response phase makes test timing brittle | Same `flush().await` pattern used by existing pipeline tests in `recorder.rs:415`. No new timing primitives. |
| `on_request_complete` not called when WAF blocks request at gate | `logging()` fires with `upstream_reached=false` → FR-012 skips; event stays `Outcome::Pending`. Classifiers ignore Pending events → no ring poisoning. Documented in phase-03 + phase-05. |
| Two-signal payload breaks FR-025 risk score consumers | Signal variant adds a field — exhaustive matches break. Mitigated by grep-sweep in phase-04; all current matchers use `Signal::WithdrawalVelocity { count, .. }` which keeps compiling. |
| Concurrent requests for same session race `last_recorded_idx` | Single in-flight HTTP request per session is the dominant case. Documented as known limitation; if telemetry shows collisions we add per-`req_id` token in a follow-up. |

## Red Team Review

### Session — 2026-05-30
**Findings:** 30 raw, 15 accepted after dedup + evidence filter, 2 rejected (out-of-scope / unsupported).
**Severity breakdown:** 5 Critical · 5 High · 5 Medium.

| # | Finding | Severity | Disposition | Applied To |
|---|---------|----------|-------------|------------|
| 1 | Token-based `set_outcome` (kills H2-mux race + hot-reload orphan + replay-flip in one fix) | Critical | Accept | Phase 2 (token field) + Phase 3 (record returns token; set_outcome takes token) |
| 2 | `upstream_contacted` gate fires on origin-down 502 (`ctx.upstream_addr` set before TCP connect, `proxy.rs:478`) | Critical | Accept | Phase 5 (move dispatch to `logging()` hook) |
| 3 | 27 `record()` callers, plan listed 5 — recorder tests, integration tests, benches | Critical | Accept | Phase 3 (enumerated) |
| 4 | `risk/ingest/signal_to_contributor.rs:193-200` constructs `Signal::WithdrawalVelocity { count, window_sec }` exhaustively | Critical | Accept | Phase 4 (promoted to Modify) |
| 5 | 164 `RequestCtx {}` struct literals workspace-wide (plan said ~30-50) — also: add `impl Default for RequestCtx` to absorb future churn | Critical | Accept | Phase 2 (Default impl + corrected count) |
| 6 | WAF-blocked → ring poisoning: attacker pre-burns victim's ring with 16 blocked withdrawals; first 2xx looks like velocity breach | High | Accept | Phase 3 (tristate `Outcome::Pending`; classifiers ignore Pending) |
| 7 | Shared JA3 behind CDN buckets thousands under one `SessionIdent::Fingerprint` — cohort poisoning primitive | High | Accept (modified) | Phase 2 + 3 (bucket key gains `peer_ip`) |
| 8 | Streaming responses (`SSE`/long-poll) fire `response_filter` at headers, not completion | High | Accept | Phase 5 (move dispatch to `logging()` hook — same fix as C2) |
| 9 | Mobile retry storms inflate `count` because each retry appends a new Pending event | High | Accept (modified) | Phase 3 (`record()` collapses into existing Pending slot within `dedupe_window_ms`) |
| 10 | `set_outcome` requires tokio runtime — sync `#[test]` calling `on_response` will panic | High | Accept | Phase 3 (note added; tests use `#[tokio::test]`) |
| 11 | `ok_count` is window+ring scoped, not lifetime success rate — clarify in doc-comment | Medium | Accept | Phase 4 (doc note on Signal variant) |
| 12 | Phase-01 must enumerate derives verbatim — `Hash` is load-bearing for `DashMap` key | Medium | Accept | Phase 1 (derive list explicit) |
| 13 | `debug_assert!(ok_count <= count)` in `evaluate_velocity` to encode the invariant | Medium | Accept | Phase 4 |
| 14 | Cooldown semantics shift (T_request → T_response) is NOT functionally equivalent — document | Medium | Accept | Phase 3 (risk row honest) |
| 15 | Add ring-wraparound test (18+ events) exercising `set_outcome` under head-wrap | Medium | Accept | Phase 3 |

**Rejected:**
- *FpKey `Serialize` exposure via admin endpoints* — speculative, no current consumer path identified by reviewer.
- *`tokio::spawn` JoinHandle drop / silent panic* — pre-existing pattern at `recorder.rs:212-215`, not introduced by this plan. Surgical-changes rule applies; file as follow-up if needed.

### Whole-Plan Consistency Sweep

After applying findings, plan re-read end-to-end. Reconciled across all 6 files:
- `Event.ok: bool` → `Event.outcome: Outcome` — every fixture, every example, every prose mention updated. Surviving `ok: bool` occurrences are in intentional **BEFORE→AFTER** migration blocks (clearly marked).
- `record(&key, role)` returns `TxEventToken` (Phase 3) and is consumed in `RequestCtx.tx_velocity_token` (Phase 2).
- `set_outcome` signature is `(token: TxEventToken, outcome: Outcome)` everywhere.
- `SessionIdent::Fingerprint { fp, ip }` shape consistent in Phase 2 (definition) + Phase 3 (consumer) + Phase 5 (e2e tests).
- Dispatch hook is the gateway `logging()` at `proxy.rs:1179`, not `response_filter` at `:851`. Phase 3 architecture, Phase 5 wiring, and the e2e regression tests all use `on_request_complete(ctx, status, upstream_reached)`.
- `Check::on_response` (FR-018 reference) stays as default no-op for `TxVelocityCheck` — confirmed in Phase 3 final impl + Phase 5 trait extension.
- `Check::on_request_complete` is the new method (Phase 5 step 5.0); Phase 3 implementation block uses it.
- No stale `store.record(..., true)` calls outside the BEFORE example block at phase-03:465.
- `impl Default for RequestCtx` mentioned in Phase 2 only (single source of truth); referenced by `..Default::default()` patterns in Phase 5 test helpers.

Zero unresolved contradictions. Plan is ready for `/ck:cook`.

## Open Questions

- Default `dedupe_window_ms` value — Phase 3 proposes `5_000` (5s). FR-025 risk scorer team should confirm this matches their retry-storm assumptions.
- `Outcome::Pending` event TTL — currently bounded by `session_ttl_secs` via the existing janitor. Re-verify that orphaned Pending events don't accumulate under sustained block-burst attack within the TTL window.
