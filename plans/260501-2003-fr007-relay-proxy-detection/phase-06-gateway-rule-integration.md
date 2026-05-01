# Phase 06 — Gateway + Rule Engine + Risk Scorer Integration

## Context Links
- Design: brainstorm §4.10
- Touch points: `crates/gateway/src/proxy.rs`, `crates/gateway/src/context.rs`, `crates/waf-engine/src/rules/engine.rs`, FR-008 `RequestCtx.client_ip`

## Overview
**Priority:** P0 · **Status:** complete (core wiring) / pending (rule engine predicates split to 06b) · **Effort:** 0.5 d (core) + TBD (06b)

Wire `RelayDetector` into request pipeline. Attach `ClientIdentity` to `RequestCtx`. Expose signals to rule engine. Feed `risk_score_delta` into FR-025 risk scorer. Update FR-008 to consume validated `real_ip`. **Core detector integration DONE. Rule engine predicate refactor (signal:/asn_class:/chain_depth:) deferred to phase-06b per scope/dependency reality.**

## Key Insights
- Detector runs EARLY — before rules, after headers parsed. `request_filter` phase in Pingora is correct insertion point.
- `ClientIdentity` lives on `RequestCtx`; FR-008 currently reads `peer_ip` → flip to read `client_identity.real_ip` once attached. Single-line change but **requires explicit FR-008 regression coverage**.
- Rule engine: add new predicate types `signal:<name>`, `asn_class:<value>`, `chain_depth:<op><n>` matched via `ClientIdentity`.
- Risk scorer: detector emits signals → scorer iterates `cfg.signals.risk_score_delta[signal_name]` → accumulates. Detector itself NEVER blocks.
- Audit log: add fields `signals[]`, `asn_class`, `asn`, `real_ip` per FR-032.

## Requirements

### Functional
- `proxy.rs::request_filter` invokes `RelayDetector::evaluate(peer_ip, &headers)` after header parse, stashes `ClientIdentity` on session ctx.
- `RequestCtx` exposes `client_identity: Option<ClientIdentity>`.
- FR-008 `client_ip` resolved from `client_identity.real_ip` when present, else `peer_ip` (backward compat).
- Rule engine matches new predicates against `ClientIdentity`.
- Risk scorer reads signals + cfg deltas → accumulates into existing FR-025 score.
- Audit log emits new fields.

### Non-functional
- Insertion adds <50µs p99 to request path (verified phase-07 bench).
- Backward compat: if `RelayDetector` not configured (config absent), pipeline behaves exactly as pre-FR-007.
- File touch surgical; no drive-by edits (Iron Rule #3).

## Architecture

```
Pingora request_filter:
  let id = relay_detector.evaluate(peer_ip, &session.req_header());
  ctx.client_identity = Some(id);

  // FR-008 reads client_identity.real_ip if present
  access_phase.evaluate(&ctx, &access_lists);

  // Rules + risk
  rule_engine.match(&ctx, &id);
  risk_scorer.accumulate(&id.signals, &cfg.risk_score_delta);
```

## Related Code Files

### Modify
- `crates/gateway/src/proxy.rs` — invoke detector in `request_filter`
- `crates/gateway/src/context.rs` (or wherever `RequestCtx` lives) — add `client_identity: Option<ClientIdentity>`
- `crates/gateway/src/pipeline/access_phase.rs` — consume `client_identity.real_ip`
- `crates/waf-engine/src/rules/engine.rs` — new predicate kinds
- `crates/waf-engine/src/rules/predicate.rs` (or equivalent) — parser for `signal:`, `asn_class:`, `chain_depth:`
- Risk scorer module (FR-025) — accept `&[Signal]` + delta map

### Create
- `crates/waf-engine/src/rules/relay_predicates.rs` — predicate impls (split if `engine.rs` >200 LOC)
- `crates/gateway/src/relay_phase.rs` — thin invocation wrapper if `proxy.rs` grows

## Implementation Steps

1. **Locate `RequestCtx`** — `grep -rn "struct RequestCtx" crates/gateway/src`. Add `client_identity: Option<ClientIdentity>` field. Re-export `ClientIdentity` from `waf-engine`.
2. **`proxy.rs`** — in `request_filter`:
   - Read `peer_addr` (existing).
   - Call `self.relay_detector.evaluate(peer_ip, &session.req_header())`.
   - Stash on ctx.
3. **FR-008 handover** — in `access_phase.rs`, replace `let client_ip = peer_ip;` with `let client_ip = ctx.client_identity.as_ref().map(|i| i.real_ip).unwrap_or(peer_ip);`. Add regression test: FR-008 AC-01..08 still pass.
4. **Rule predicates** — define:
   - `signal:xff_spoof_private` matches if `id.signals` contains variant
   - `asn_class:datacenter|residential|tor|unknown`
   - `chain_depth:>3` (operators `>`, `>=`, `==`, `<`, `<=`)
   - YAML rules consume these the same way existing predicates do.
5. **Risk scorer hookup** — extend FR-025 `RiskScorer::accumulate(&[Signal], &HashMap<String, i32>) -> i32`. Add unit test for delta sum.
6. **Audit fields** — locate audit-log emitter (FR-032), add `signals`, `asn_class`, `asn`, `real_ip`.
7. **No-op when disabled** — if `RelayDetector` not constructed (no config), wrap with `Option<Arc<RelayDetector>>` on gateway state; skip evaluate.
8. **Compile check** — `cargo check --workspace` clean.

## Todo List
- [x] Add `client_identity` field to `GatewayCtx` (placed on gateway-only ctx; `RequestCtx` stays a `waf-common` leaf — see Deferred)
- [x] Wire `RelayDetector::evaluate` into `request_filter`
- [x] Update FR-008 access gate to consume `real_ip` (preferred over peer when detector is present)
- [x] No-op when detector absent (back-compat) — `Option<Arc<RelayDetector>>` on `WafProxy`
- [x] `RequestCtx.client_ip` overridden with detector `real_ip` post-build
- [x] `cargo check --workspace` clean + `cargo clippy -p gateway -- -D warnings` clean
- [x] Smoke test: detector evaluation → identity flows onto `GatewayCtx`
- [ ] **Deferred to phase-06b:** Rule predicates (`signal:`, `asn_class:`, `chain_depth:`) — non-trivial refactor of `CustomRule`/`Condition` deserializer + compiler + evaluator across `crates/waf-engine/src/rules/engine.rs` (1500+ LOC). Scoped separately to keep this phase surgical.
- [ ] **Deferred to phase-06b:** Risk scorer accumulate — FR-025 `RiskScorer` does not exist yet; only `risk_score_delta` config landed. Will hook up when FR-025 lands.
- [ ] **Deferred to phase-06b:** Audit log fields — request-path audit emitter is not yet present (DB `audit_log` table covers admin actions only). Re-evaluate against FR-032 emitter once it ships.
- [ ] **Deferred to phase-07:** Pingora-driven integration tests — gateway crate's existing convention defers Pingora-session tests to a dedicated harness phase (see `gateway/CLAUDE.md`).

## Success Criteria
- Integration test: peer_ip=`1.2.3.4`, header `X-Forwarded-For: 5.6.7.8`, trusted=`1.2.3.4/32` → `client_identity.real_ip == 5.6.7.8`; FR-008 blacklist matches `5.6.7.8`.
- Integration test: rule `signal:tor_exit` blocks when set match.
- Integration test: rule `asn_class:datacenter` w/ DC IP → matches.
- Integration test: rule `chain_depth:>3` → triggers on 4-hop chain.
- Integration test: detector absent → request flows identically to pre-FR-007 (regression suite passes).
- Audit log entries contain new fields.
- p99 latency overhead <50µs vs FR-008-only baseline.

## Common Pitfalls
- Predicate parser collisions w/ existing syntax — use prefix `signal:`/`asn_class:`/`chain_depth:` to namespace clearly.
- Forgetting to feature-gate detector when no config → `Option` everywhere or single `NoOpRelayDetector` impl. Prefer the latter (KISS).
- `ClientIdentity` Arc: cloning `Vec<Signal>` per-request is wasteful — store `Arc<ClientIdentity>` if Vec >4 items typical.
- Audit-log schema change → update FR-032 docs (phase-08).

## Risk Assessment
**High** — touching the hot path. Mitigated by no-op-when-absent path + criterion regression bench.

## Security Considerations
- Real IP is sensitive: scrub from non-debug logs.
- Rule predicate parsing on untrusted YAML — validate predicate strings, no eval.

## Next Steps
Phase 07 — comprehensive test suite (unit, proptest, wiremock, integration, criterion, llvm-cov ≥90% gate).
