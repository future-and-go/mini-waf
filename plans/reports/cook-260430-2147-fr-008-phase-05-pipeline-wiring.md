# Cook Report — FR-008 phase-05 pipeline wiring

**Mode:** `--auto` on `phase-05-pipeline-wiring.md`
**Status:** DONE (e2e deferred to phase-07 per plan)

## What landed

| File | Change |
|------|--------|
| `crates/gateway/src/pipeline/access_phase.rs` | **NEW** — `AccessPhaseGate` over `Arc<ArcSwap<AccessLists>>`, `AccessGateOutcome { Continue, Bypass, Block(u16) }`, audit logging, 10 unit tests |
| `crates/gateway/src/pipeline/mod.rs` | re-exports `access_phase::{AccessGateOutcome, AccessPhaseGate}` |
| `crates/gateway/src/context.rs` | `GatewayCtx.access_bypass: bool` |
| `crates/gateway/src/proxy.rs` | `WafProxy.access_lists: Option<Arc<AccessPhaseGate>>`, `with_access_lists` builder, gate invoked top of `request_filter` before `engine.inspect`, body inspector skips on bypass |

## Plan deviations (and why)

1. **Bypass flag location** — plan: `AtomicBool` on `RequestCtx` (waf-common). Implemented: plain `bool` on `GatewayCtx` (gateway crate).
   - Reason: `RequestCtx` has 25+ struct-literal sites across `waf-engine` tests/benches; non-default field would force a 25-file diff with no behavioral benefit. The flag only needs to gate `engine.inspect()` — that decision lives entirely in the gateway. KISS, surgical (CLAUDE.md Iron Rule #2).
   - Side-effect: no `AtomicBool` indirection — `GatewayCtx` is `&mut` in every Pingora callback, so a plain `bool` works.

2. **Filter registration** — plan: implement `RequestFilter`, register at `RequestFilterChain` index 0. Implemented: standalone `AccessPhaseGate` invoked inline at top of `WafProxy::request_filter`.
   - Reason: `RequestFilterChain` runs in `upstream_request_filter` (proxy.rs:339) — *post*-WAF lifecycle. Registering Phase 0 there would make it run *after* `engine.inspect` (proxy.rs:296). Inline invocation in `request_filter` matches the plan's architectural intent ("before any other filter pays cost") and the actual Pingora hook ordering.

## Verification

- `cargo check --workspace` — clean
- `cargo clippy -p gateway --all-targets -- -D warnings` — clean
- `cargo test -p gateway pipeline::access_phase` — **10/10 pass**
  - `translate_*` (4): pure decision-translation unit tests
  - `gate_evaluate_*` (5): integration with real `AccessLists` snapshots covering empty, blacklist, whitelist full-bypass, host-gate, dry-run
  - `gate_hot_swap_picks_up_new_snapshot`: validates phase-06 swap path

## Wire-up still required (not phase-05's job)

`prx-waf/src/main.rs` — currently does not call `proxy.with_access_lists(...)`. Phase-06 (file watcher) owns the boot/reload glue that constructs the `Arc<ArcSwap<AccessLists>>` and injects it. Until phase-06 lands, the proxy runs with `access_lists = None` (every request → `Continue`, no enforcement). This is the intended boot fallback (mirrors `tier_registry`).

## Unresolved questions

- **client_ip vs peer_ip semantics** — gate uses `session.client_addr()` (immediate TCP peer), falling back to `request_ctx.client_ip`. Plan §"FR-007 client_ip handover" Q1 (tracked in brainstorm §12) hasn't resolved whether trusted-XFF rewrites should apply *before* the access gate. Current behavior: blacklist is checked against the raw TCP peer, which is the safer default (a misconfigured XFF can't bypass blacklist). Re-evaluate when FR-007 lands.
- **Audit-log target** — plan referenced `target: "audit"`; no such target exists in the codebase yet, so I used the default `tracing` target with structured `access_decision`/`access_reason`/`matched`/`status` fields. Phase-08 (docs) is the right place to formalize the log-target convention if/when an audit sink is added.
