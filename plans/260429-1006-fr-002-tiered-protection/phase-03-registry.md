# Phase 3 — Policy Registry + ArcSwap

## Context
- Design doc §4 (architecture), §8 (hot-reload), §9 (patterns).
- Depends on: Phase 1 types, Phase 2 classifier.

## Why
The registry is the *Single Source of Truth* downstream FRs query. Wrapping it in `ArcSwap` from day one is the difference between a 1-day feature and a 1-week retrofit later. ArcSwap = atomic pointer swap; readers never block, writers replace whole snapshot. Junior trap: using `RwLock<HashMap>` — every request takes a read lock, contending under load.

## Goals
- `TierPolicyRegistry` holds (classifier + per-tier policies) as one immutable snapshot.
- `swap(new_config)` atomically replaces the snapshot.
- `lookup(tier) -> &TierPolicy` is O(1).
- `classify_and_lookup(&req) -> (Tier, Arc<TierPolicy>)` convenience for consumers.

## Files
- **Create:** `crates/gateway/src/tiered/tier_policy_registry.rs`
- **Modify:** `crates/gateway/src/tiered/mod.rs` (re-export)
- **Modify:** `crates/gateway/Cargo.toml` (add `arc-swap = "1"` if not present)

## Implementation Notes

### Snapshot type
```rust
pub struct TierSnapshot {
    pub classifier: TierClassifier,
    pub policies:   HashMap<Tier, Arc<TierPolicy>>,
}
```
WHY `Arc<TierPolicy>` inside: consumers may hold a policy across an `.await`; cloning an Arc is one atomic increment vs cloning the whole struct.

### Registry
```rust
pub struct TierPolicyRegistry {
    inner: ArcSwap<TierSnapshot>,
}

impl TierPolicyRegistry {
    pub fn new(snap: TierSnapshot) -> Self { /* ... */ }

    pub fn snapshot(&self) -> Arc<TierSnapshot> { self.inner.load_full() }

    pub fn swap(&self, new_snap: TierSnapshot) {
        self.inner.store(Arc::new(new_snap));
    }

    pub fn classify(&self, req: &RequestParts) -> (Tier, Arc<TierPolicy>) {
        let snap = self.inner.load();           // cheap Guard
        let tier = snap.classifier.classify(req);
        let policy = snap.policies.get(&tier).cloned()
            .expect("BUG: validate() guaranteed all tiers have a policy");
        (tier, policy)
    }
}
```
**`.expect()` justification (per CLAUDE.md):** "BUG:" prefix + invariant established by `validate()` at load time. This is a compile-time-style invariant. No runtime panic possible if config-load path is the only way to construct a snapshot.

### Constructor from `TierConfig`
```rust
impl TierSnapshot {
    pub fn try_from_config(cfg: TierConfig) -> Result<Self, TierConfigError> {
        cfg.validate()?;
        let classifier = TierClassifier::compile(&cfg.classifier_rules, cfg.default_tier)?;
        let policies = cfg.policies.into_iter()
            .map(|(t, p)| (t, Arc::new(p)))
            .collect();
        Ok(Self { classifier, policies })
    }
}
```
WHY `try_from_config` instead of `From`: building can fail (regex compile). `From` is for infallible conversions; using `TryFrom` would also work — pick consistent one across crate.

## Tests
- `lookup_returns_correct_policy_per_tier`
- `swap_replaces_atomically` — spawn N reader threads + 1 writer, no torn reads.
- `classify_uses_current_snapshot_after_swap`
- `try_from_config_rejects_invalid`

## Acceptance
- `cargo test -p gateway tier_policy_registry` green.
- File < 200 LoC.

## Common Pitfalls
- Storing `Arc<RwLock<HashMap>>` — kills read concurrency. Use `ArcSwap`.
- Calling `.load_full()` per field access — call once, hold the `Arc`, then index.
- Mutating snapshot in place — defeats atomicity. Always replace.

## Status
Complete. Merged in commit ae70bee.
- `tier_policy_registry.rs` ✅ with `TierSnapshot` + `TierPolicyRegistry`
- `try_from_config` constructor ✅
- 4+ unit tests incl. concurrent swap ✅
- `arc-swap` dep added ✅

## Next
Phase 4 — file watcher that calls `swap()` on TOML edits.
