---
phase: 1
title: "O(1) LRU fallback cache"
status: completed
priority: P2
dependencies: []
---

# Phase 1: O(1) LRU fallback cache

<!-- Updated: Validation Session 1 - lru-crate choice confirmed over HashMap+generation counter -->

## Overview

Replace the hand-rolled `LruCache` in `crates/waf-engine/src/risk/store/redis.rs:73-109` with the `lru` crate. The current implementation does `VecDeque::retain` — O(capacity), default 10,000 — plus a `key.to_string()` allocation on **every** `get` and `insert`, all under one global `parking_lot::Mutex`. `cache_update` runs on every successful `apply` (redis.rs:450), `read` (394), and `force_max` (512), so this scan is paid per request when the risk store is active.

## Requirements

- Functional: identical fallback-cache behavior — bounded capacity, least-recently-used eviction, `cache_lookup` returns the cached `RiskState` clone, `reset_all` clears the cache.
- Non-functional: `get`/`insert`/`clear` are O(1); no per-operation `String` allocation beyond the existing `cache_key()` composition (which builds the key once per call and is kept).

## Architecture

Use `lru::LruCache<String, CacheEntry>` (crate `lru`, latest 0.x — a small, widely used, no-unsafe-heavy dependency) behind the existing `Mutex`. The issue offers "lru crate or HashMap + generation counter"; the crate is chosen because it is less code and its `get`/`push` are O(1) via an internal hash map + intrusive list. No behavior change to fail-open policy (issue #201 owns that).

## Related Code Files

- Modify: `crates/waf-engine/src/risk/store/redis.rs` — delete `struct LruCache` + impl (lines 73-109); adapt `cache: Mutex<lru::LruCache<String, CacheEntry>>` construction (line 149), `cache_lookup` (232), `cache_update` (238), and the `reset_all` clear block (569-573 → `cache.lock().clear()`).
- Modify: `crates/waf-engine/Cargo.toml` — add `lru` dependency (workspace-level if other crates may use it; otherwise crate-local, matching how `dashmap` is declared).

## Implementation Steps

1. Add `lru` to `crates/waf-engine/Cargo.toml` (check root `Cargo.toml` for a `[workspace.dependencies]` section and follow the existing dependency-declaration pattern).
2. Replace the hand-rolled struct: `Mutex<lru::LruCache<String, CacheEntry>>`, constructed with `LruCache::new(NonZeroUsize::new(cfg.cache_capacity.max(1)).unwrap())` (guard against a zero capacity in config).
3. `cache_lookup`: `self.cache.lock().get(&cache_key).map(|e| e.state.clone())` — `lru::get` promotes recency with no alloc.
4. `cache_update`: `self.cache.lock().push(cache_key, CacheEntry { ... })` (push = insert-or-update + evict LRU when full).
5. `reset_all`: replace the two-field clear with `self.cache.lock().clear()`.
6. Keep `CacheEntry` as-is (including the `#[allow(dead_code)] owner_id` field — out of scope; #208 tracks dead-code cleanup).
7. Add a unit test (no Redis needed) exercising capacity eviction order and update-promotes-recency, since the old struct had none.

## Success Criteria

- [x] `struct LruCache` hand-rolled implementation deleted; `lru` crate in use.
- [x] No `order.retain` / O(capacity) scans; no `key.to_string()` inside get/insert.
- [x] New unit test covers: eviction at capacity, `get` promotes recency, `push` replaces existing entry.
- [x] `cargo test -p waf-engine risk::store` passes; existing `basic_apply_and_read` / `breaker_tracks_failures` untouched.

## Risk Assessment

- New dependency: `lru` is tiny and ubiquitous; supply-chain delta is minimal. Mitigation: pin a specific version.
- `NonZeroUsize` requirement is the only API mismatch vs the old code — handle `cache_capacity == 0` explicitly rather than panicking.
