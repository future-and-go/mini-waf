# Phase 2 — Module Refactor + Decision Pipeline

**Effort:** 2d · **Priority:** P0 · **Status:** complete · **Depends on:** Phase 1

## Context

- Brainstorm: [`../reports/brainstorm-260502-2140-fr-009-smart-caching.md`](../reports/brainstorm-260502-2140-fr-009-smart-caching.md) §3, §4, §6

## Goal

Extract `cache.rs` into `cache/` module. Introduce `CachePolicyResolver` (Chain of Responsibility) over `CacheGate` strategies. **No behavior change** vs Phase 1 — pure refactor + structural foundation for Phase 3.

## Why

Phase 1 inlined the tier check. Phase 3 needs to add Auth, RouteRule, UpstreamCC gates without bloating `put()`. CoR keeps each gate <50 lines and individually testable.

## Related Code

**Read:**
- `crates/gateway/src/cache.rs` (post-Phase 1)
- `crates/gateway/src/tiered/tier_classifier.rs` — gate-style precedent
- `crates/gateway/src/lib.rs` — module declarations

**Modify:**
- `crates/gateway/src/lib.rs` — replace `pub mod cache;` with `pub mod cache;` (still works, dir-based)
- `crates/gateway/src/proxy.rs` — call sites (signature unchanged from Phase 1)

**Delete:** `crates/gateway/src/cache.rs` (moves to `cache/store.rs`)

**Create:**
- `crates/gateway/src/cache/mod.rs` — facade re-exports
- `crates/gateway/src/cache/store.rs` — moka wrapper (existing logic)
- `crates/gateway/src/cache/policy.rs` — `CachePolicyResolver` + `Verdict` + `CacheGate` trait
- `crates/gateway/src/cache/gates/mod.rs`
- `crates/gateway/src/cache/gates/tier_gate.rs`
- `crates/gateway/src/cache/gates/method_gate.rs`
- `crates/gateway/src/cache/gates/upstream_cc_gate.rs`
- `crates/gateway/src/cache/gates/tier_default_gate.rs`
- `crates/gateway/src/cache/stats.rs`

(AuthGate, RouteRule gates land in Phase 3.)

## Implementation Steps

1. Create `cache/` directory; move existing `cache.rs` body into `cache/store.rs`.
2. Extract `CacheStats` into `cache/stats.rs`.
3. Define core types in `cache/policy.rs`:
   ```rust
   pub enum Verdict {
       Bypass(BypassReason),
       Cache { ttl: Duration, tags: Vec<Arc<str>> },
       Continue,
   }
   pub trait CacheGate: Send + Sync {
       fn name(&self) -> &'static str;
       fn evaluate(&self, ctx: &CacheCtx<'_>) -> Verdict;
   }
   pub struct CachePolicyResolver { gates: Vec<Box<dyn CacheGate>> }
   impl CachePolicyResolver {
       pub fn resolve(&self, ctx: &CacheCtx<'_>) -> Verdict { /* first non-Continue wins, else Bypass(NoMatch) */ }
   }
   ```
4. `CacheCtx` is a borrowed view: tier, method, request headers (auth/cookie probe), response headers (Cache-Control, Set-Cookie), policy ref.
5. Implement gates one-per-file:
   - `TierGate`: `Tier::Critical` → `Bypass(CriticalTier)`; else `Continue`
   - `MethodGate`: only GET/HEAD; else `Bypass(NonIdempotentMethod)`
   - `UpstreamCcGate`: parse `Cache-Control`; `no-store|private|no-cache` → `Bypass`; `Set-Cookie` present → `Bypass`; `max-age=N` → `Cache{ttl: min(N, policy_ceiling)}`
   - `TierDefaultGate`: maps `CachePolicy` → `Verdict`
6. `ResponseCache::put` becomes:
   ```rust
   match self.resolver.resolve(&ctx) {
       Verdict::Bypass(r) => { stats.record_bypass(r); false }
       Verdict::Cache { ttl, tags } => { /* moka insert; tags Vec ignored until Phase 4 */ true }
       Verdict::Continue => false, // resolver always terminates with Bypass(NoMatch)
   }
   ```
7. Wire facade re-exports in `cache/mod.rs`: `pub use store::{ResponseCache, CachedResponse};` etc. Existing call sites unchanged.
8. Move/update inline unit tests with the modules.
9. Run full check:
   ```
   cargo check --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test -p gateway
   ```

## File Size Discipline

Each gate file should be <80 lines. `policy.rs` <150. `store.rs` <200. Aligns with project rule (split files >200 LoC).

## Todo

- [x] Create `cache/` dir, move `store.rs`
- [x] Extract `stats.rs`
- [x] Define `Verdict`, `CacheGate`, `CachePolicyResolver`, `CacheCtx`
- [x] Implement TierGate, MethodGate, UpstreamCcGate, TierDefaultGate
- [x] Rewrite `put()` to delegate to resolver
- [x] Per-gate inline unit tests (table-driven)
- [x] Resolver test: gates run in order, first definitive wins
- [x] All existing gateway tests pass
- [x] Clippy clean, no `.unwrap()` in non-test code

## Success Criteria

- Behavior identical to Phase 1 (regression suite passes)
- Each gate file <80 LoC
- Resolver test asserts gate ordering: TierGate fires before any other
- `cargo doc -p gateway` clean (gates documented)

## Risks

| Risk | Mitigation |
|---|---|
| Subtle behavior drift during refactor | Phase 1 tests must pass byte-for-byte; add resolver-level integration test before merge |
| Over-engineering the trait abstraction | Keep `CacheGate` minimal — name + evaluate, nothing more |
| Vec\<Box\<dyn>> dispatch overhead | Negligible: 4-6 gates, all hot in cache; benchmark in Phase 5 |

## Security Considerations

- TierGate MUST be index 0 in resolver gate list. Add a `debug_assert!` and a unit test asserting first gate's `name() == "tier"`.
- No new attack surface — pure refactor.

## Next Steps

→ Phase 3: add YAML config, RouteRule + AuthGate, hot-reload watcher.
