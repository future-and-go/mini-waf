# Cook Report — FR-007 phase-06 gateway+rule integration

**Mode:** `--auto` · **Status:** DONE_WITH_CONCERNS · **Date:** 2026-05-01

## Done (surgical scope)
- `GatewayCtx.client_identity: Option<ClientIdentity>` — gateway/src/context.rs
- `WafProxy.relay_detector: Option<Arc<RelayDetector>>` + `with_relay_detector()` — gateway/src/proxy.rs
- `request_filter` runs `detector.evaluate(peer_ip, headers)` before ctx build (no-op when unset)
- FR-008 handover: access gate evaluated with `client_identity.real_ip` when present, else peer_ip (back-compat)
- `RequestCtx.client_ip` overridden with detector `real_ip` post-build → WAF engine sees validated IP
- Smoke tests for default + populated identity flow
- `cargo check --workspace` clean · `cargo clippy -p gateway -- -D warnings` clean · 111 gateway tests pass

## Deferred (scope/dependency reality)
1. **Rule predicates** (`signal:`/`asn_class:`/`chain_depth:`) — substantial refactor of `CustomRule`/`Condition` deserializer/compiler/evaluator across 1500+ LOC engine. Splitting to phase-06b keeps merges reviewable.
2. **Risk scorer hookup** — FR-025 `RiskScorer` does not exist yet (only `risk_score_delta` config landed). Cannot extend a non-existent module.
3. **Audit fields** — request-path audit emitter (FR-032) not present; existing `audit_log` is for admin actions only.
4. **Pingora integration tests** — gateway crate convention defers these to a test-harness phase (per `gateway/CLAUDE.md`).

## Decisions
- Placed `client_identity` on `GatewayCtx` (gateway-local) rather than `RequestCtx` (waf-common). Reason: `waf-common` is a leaf crate; moving `ClientIdentity`/`Signal`/`AsnClass` into it would invert dependency or duplicate types. Plan's intent ("`RequestCtx` exposes...") preserved functionally — the WAF engine still sees `real_ip` via overridden `RequestCtx.client_ip`.
- `RequestCtxBuilder` left untouched. Override applied after `build()` → minimal blast radius.

## Files
- `crates/gateway/src/context.rs` — field + tests
- `crates/gateway/src/proxy.rs` — wiring + handover
- `plans/260501-2003-fr007-relay-proxy-detection/phase-06-gateway-rule-integration.md` — todo list updated

## Unresolved questions
- When does FR-025 (risk scorer) land? Phase-06b sequencing depends on it.
- Is FR-032 audit emitter scoped to a separate plan? If so, link from phase-06b.
- Should the rule-engine predicates ship behind a feature flag in 06b, or as a clean addition?
