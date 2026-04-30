# Phase 05 — Phase-0 Pipeline Wiring

## Context Links
- Design: brainstorm §4 (architecture diagram), D6, D10
- Existing pipeline: `crates/gateway/src/pipeline/{mod.rs,request_filter_chain.rs}`
- Tier wiring reference: `crates/gateway/src/proxy.rs:24, 61, 87, 209, 241`

## Overview
**Priority:** P0 · **Status:** pending · **Effort:** 0.75 d

Wire `AccessLists::evaluate` into the gateway as **Phase 0** — runs before any other request filter. On `Block` → return 403 via the existing block-page path. On `BypassAll` → set a flag on `RequestCtx` so downstream filters short-circuit. On `Continue` → no-op.

## Key Insights
- Use the existing `RequestFilter` trait. Register the `AccessPhaseFilter` **first** in `RequestFilterChain` so it short-circuits before any other filter pays cost.
- 403 response uses the existing `proxy_waf_response` / block-page factory (D10) — no new error-page surface.
- `BypassAll` is communicated to downstream filters via a new `RequestCtx.access_bypass: bool` field — single boolean, no new enum across crates.
- Optional injection (`Option<Arc<ArcSwap<AccessLists>>>` on `Proxy`): when unset, every request defaults to `Continue`. Mirrors how FR-002 wired `tier_registry`.

## Requirements

### Functional
- New `AccessPhaseFilter` impl `RequestFilter`:
  - Reads `fctx.request_ctx.tier` and `fctx.peer_ip`.
  - Reads `Host` header from `req.headers`.
  - Calls `AccessLists::evaluate`.
  - On `Block { dry_run: false, .. }` → emit 403 via the existing block-pipeline error type and short-circuit the chain (return `Err`).
  - On `Block { dry_run: true, .. }` → log structured WARN `access_dry_run_block` and return `Ok(())`.
  - On `BypassAll` → set `fctx.request_ctx.access_bypass = true` (requires field on `RequestCtx`).
  - On `Continue` → `Ok(())`.
- `Proxy::with_access_lists(Arc<ArcSwap<Arc<AccessLists>>>)` builder method.
- Audit log row appended for every Block (and BypassAll, per brainstorm §9 "skipping audit log on bypass" pitfall).

### Non-functional
- Filter `apply()` allocation-free for `Continue` happy path.
- Added p99 ≤ 0.2 ms (NFR §8 item 7).

## Architecture

```
Pingora::request_filter
   │
   ▼
ctx_builder ──► RequestCtx { tier, peer_ip, host, ... access_bypass=false }
   │
   ▼
RequestFilterChain.apply_all
   │
   ├── [0] AccessPhaseFilter   ◄── NEW
   │       evaluate(view) ──► Continue | BypassAll | Block
   │       Block → return Err (proxy yields 403 page)
   │       BypassAll → mutate ctx.access_bypass = true
   │
   ├── [1] HostHeaderPolicy   (existing)
   ├── [2] ...
   └── ...
```

Downstream filters that respect bypass (rule engine, risk scorer) early-return when `ctx.access_bypass == true`. **In this phase**, only the rule engine (FR-003) check is plumbed; everything else lands in its own plan.

## Related Code Files

### Create
- `crates/gateway/src/pipeline/access_phase.rs` — `AccessPhaseFilter` impl (≤ 150 LoC)

### Modify
- `crates/waf-common/src/lib.rs` (or wherever `RequestCtx` lives) — add `pub access_bypass: bool` (default `false`). Verify with grep: `grep -nR "pub struct RequestCtx" crates/waf-common/`
- `crates/gateway/src/pipeline/mod.rs` — `pub mod access_phase; pub use access_phase::AccessPhaseFilter;`
- `crates/gateway/src/proxy.rs`:
  - new field `access_lists: Option<Arc<ArcSwap<Arc<AccessLists>>>>`
  - `with_access_lists` builder
  - register filter at index 0 of the chain when injected
- `crates/gateway/Cargo.toml` — add `waf-engine` dep if not present (it already is in workspace; confirm), `arc-swap` (already there).

## Implementation Steps

1. **Verify** `RequestCtx` location: `grep -nR "pub struct RequestCtx" crates/waf-common/`. Add `access_bypass: bool` with `#[serde(default)]` so existing serialised contexts deserialise unchanged.
2. **Create** `pipeline/access_phase.rs`:
   ```rust
   use std::sync::Arc;
   use arc_swap::ArcSwap;
   use pingora_core::{Error, ErrorType};
   use pingora_http::RequestHeader;
   use waf_engine::access::{AccessDecision, AccessLists, AccessRequestView, BlockReason};

   use super::{FilterCtx, RequestFilter};

   pub struct AccessPhaseFilter {
       lists: Arc<ArcSwap<Arc<AccessLists>>>,
   }
   impl AccessPhaseFilter {
       pub fn new(lists: Arc<ArcSwap<Arc<AccessLists>>>) -> Self { Self { lists } }
   }
   impl RequestFilter for AccessPhaseFilter {
       fn name(&self) -> &'static str { "access_phase" }

       fn apply(&self, req: &mut RequestHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
           let lists = self.lists.load_full();   // Arc<Arc<AccessLists>> cheap
           let host = req.headers
               .get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
           let view = AccessRequestView {
               client_ip: fctx.peer_ip,
               host,
               tier: fctx.request_ctx.tier,
           };
           match lists.evaluate(&view) {
               AccessDecision::Continue => Ok(()),
               AccessDecision::BypassAll { matched_cidr } => {
                   tracing::info!(target: "audit", access_decision="bypass", access_match=%matched_cidr, "bypass");
                   // SAFETY note: RequestCtx is shared; we need interior mutability OR the
                   //   ctx_builder must run AFTER this filter — it does NOT today.
                   //   Solution: store bypass on a per-request slot via FilterCtx extension.
                   //   See "Pitfalls" — this is the one tricky bit of this phase.
                   fctx.request_ctx.access_bypass.store(true, /*Ordering::Relaxed*/);
                   Ok(())
               }
               AccessDecision::Block { reason, matched, dry_run, status } => {
                   let reason_str = match reason { BlockReason::HostGate => "host_gate", BlockReason::IpBlacklist => "ip_blacklist" };
                   if dry_run {
                       tracing::warn!(target: "audit", access_decision="dry_run_block", access_reason=reason_str, access_match=%matched, "would-block");
                       Ok(())
                   } else {
                       tracing::warn!(target: "audit", access_decision="block", access_reason=reason_str, access_match=%matched, status=status, "block");
                       // Use the gateway's existing 403 path. The chain stops on Err;
                       // proxy.rs translates this into proxy_waf_response.
                       Err(Error::explain(ErrorType::HTTPStatus(status), reason_str))
                   }
               }
           }
       }
   }
   ```
3. **`access_bypass` field on `RequestCtx`**: choose `AtomicBool` so it's settable through `&RequestCtx` (which `FilterCtx` exposes by `&`). Reading is `load(Relaxed)` downstream. This avoids reshaping `FilterCtx` to `&mut`. Document this in the field's doc comment.
4. **Wire into `Proxy`** (mirror FR-002 pattern at `proxy.rs:60-90`):
   ```rust
   // proxy.rs
   pub access_lists: Option<Arc<ArcSwap<Arc<AccessLists>>>>,
   pub fn with_access_lists(&mut self, l: Arc<ArcSwap<Arc<AccessLists>>>) {
       self.access_lists = Some(l);
   }
   ```
   In the request-handling path where `RequestFilterChain` is built, register `AccessPhaseFilter` at the front when `Some`.
5. **Map `Err(HTTPStatus(403))` to existing block page**: identify how current filters (e.g. host policy) yield 403; reuse that exact mechanism. Check `proxy_waf_response` in `crates/gateway/src/proxy.rs` and `proxy_filters/error_page_factory*`.
6. **Tests** (mostly integration, full e2e in phase-07):
   - Unit (`pipeline::access_phase::tests`): build a mock `FilterCtx` with synthetic tier + ip; assert each branch sets the right state / returns expected `Result`.
   - Integration (`crates/gateway/tests/access_e2e_block.rs`): full Pingora session, blacklisted IP → 403 + audit log line.

## Todo List
- [ ] Add `access_bypass: AtomicBool` to `RequestCtx` (defaults `false`)
- [ ] Create `pipeline/access_phase.rs` (`AccessPhaseFilter`)
- [ ] Add `Proxy::with_access_lists` + storage field
- [ ] Register filter at chain index 0 when injected
- [ ] Confirm `Err(HTTPStatus(403))` flows through to `proxy_waf_response` 403 page
- [ ] Unit test each match arm (≥4 tests)
- [ ] Stub e2e — full integration in phase-07
- [ ] `cargo check --workspace` clean

## Success Criteria
- `cargo test -p gateway pipeline::access_phase` ≥ 4 tests pass.
- `cargo clippy --workspace -- -D warnings` clean.
- Manual smoke: `curl --resolve attacker.local:80:127.0.0.1 http://attacker.local/` from a blacklisted source IP returns 403.

## Common Pitfalls
- **Mutating `RequestCtx` through `&`**: the chain only hands filters `&FilterCtx`. The cleanest workaround is `AtomicBool` on the ctx — small, lock-free. Avoid `Mutex<bool>` (overkill).
- **Panic on missing `Host` header**: HTTP/1.0 requests can omit `Host`. Default to empty string and let host-gate's `is_disabled_for(tier)` short-circuit, OR if list non-empty → block (deny-by-default — correct). Do **not** unwrap.
- **403 page double-emission**: ensure only one of {filter Err, downstream proxy} writes the response. Existing host_policy filter is a good template; copy its error type and propagation exactly.
- **Forgetting to register at index 0**: registering at the end means rules run before access — defeats the point of "Phase 0".

## Risk Assessment
- Medium. Touches the live request path and shared `RequestCtx`. Mitigated by:
  - Optional injection — disabled by default.
  - `AtomicBool` chosen to avoid signature ripple.
  - Integration test asserts ordering before merge.

## Security Considerations
- D6 short-circuit means a blacklist hit costs ≤ 1 trie lookup before the connection is closed → reduces DDoS amplification of detection cost.
- Audit-log emission on **every** block is a hard requirement (FR-032); covered by phase-07 e2e test asserting log fields.

## Next Steps
- Phase 06: hot-reload watcher swaps the `ArcSwap` content on file change.
