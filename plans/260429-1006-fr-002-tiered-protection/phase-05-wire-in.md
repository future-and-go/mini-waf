# Phase 5 — Wire into ctx_builder

## Context
- Design doc §4 (architecture), §12 risk #4 (tier must be set before consumers read).
- Depends on: Phase 3 registry, FR-001 `ctx_builder/` finalization.

## Why
Tier classification must happen *before* any downstream check that consumes it. The earliest spot is `ctx_builder` — it's the first stage that sees the parsed request. Junior trap: classifying inside a check (e.g., DDoS check) — too late, already past whitelist/blacklist short-circuits.

## Goals
- `RequestCtx` carries `tier: Tier` and `tier_policy: Arc<TierPolicy>`.
- Populated in `ctx_builder` from `Arc<TierPolicyRegistry>` injected via gateway init.
- Default = `CatchAll` if registry not configured (boot-time safety).

## Files
- **Modify:** `crates/waf-common/src/types.rs` (add tier fields to `RequestCtx`)
- **Modify:** `crates/gateway/src/ctx_builder/*.rs` (locate stage, add classify call)
- **Modify:** `crates/gateway/src/lib.rs` or wherever gateway is constructed — accept `Arc<TierPolicyRegistry>`
- **Modify:** `crates/prx-waf/src/main.rs` (or bin entry) — build registry from config, pass into gateway

## Implementation Notes

### `RequestCtx` additions
```rust
pub struct RequestCtx {
    // ... existing fields ...
    pub tier: Tier,
    pub tier_policy: Arc<TierPolicy>,
}
```
WHY non-Option: callers should never have to handle "no tier"; defaulting at construction makes consuming code branchless.

### Default at construction
Provide `RequestCtx::with_default_tier()` for tests / boot fallback. Real prod path always classifies.

### ctx_builder integration
1. Read existing `ctx_builder/` to find the stage that owns `RequestCtx` construction.
2. Inject `Arc<TierPolicyRegistry>` into builder (constructor arg).
3. Build `RequestParts` from Pingora request (path, host header, method, headers).
4. Call `registry.classify(&parts)` → `(tier, policy)`.
5. Set `ctx.tier = tier; ctx.tier_policy = policy;`.

### Bin wiring
`prx-waf/src/main.rs`:
```rust
let tier_cfg = TierConfig::load_from_toml(&config_path)?;
let registry = Arc::new(TierPolicyRegistry::new(TierSnapshot::try_from_config(tier_cfg)?));
let _watcher = TierConfigWatcher::spawn(config_path.clone(), Arc::clone(&registry), shutdown.clone())?;
gateway.with_tier_registry(Arc::clone(&registry));
```

### Tracing
Add `tier=?ctx.tier` field to existing per-request span. Operators need this to debug "why was my request blocked". Cheap, high value.

## Tests
- Unit: `ctx_builder` populates tier correctly for stub requests.
- Integration: full request through gateway sets `RequestCtx.tier` for each route in fixture.

## Acceptance
- `cargo test -p gateway` green.
- `cargo build --release` produces single binary.
- Manual smoke: `curl localhost:16880/login` → log shows `tier=critical`.

## Common Pitfalls
- Classifying *after* whitelist/blacklist → tier is wrong for short-circuited requests. Classify before, even if response is short-circuited. Cheap (microseconds).
- Forgetting to update `RequestCtx::Default` test fixture → unrelated tests fail to compile.
- Lifetime issues: `RequestParts` borrows from request — don't store, classify-and-drop.

## Status
Complete. Just delivered.
- `RequestCtx` extended with `tier: Tier` + `tier_policy: Arc<TierPolicy>` ✅
- `RequestCtx::default_tier_policy()` via OnceLock for fixtures ✅
- `request_ctx_builder.rs`: added `with_tier_registry()`, classify in build() ✅
- `proxy.rs`: wired `tier_registry` at request_filter + upstream_peer ✅
- `prx-waf/src/main.rs`: try_init_tier_registry() + watcher spawn ✅
- 30+ fixture sites updated ✅
- All tests green, clippy clean, release build green ✅

## Next
Phase 6 — verify everything via tests, bench, and write the consumer doc.
