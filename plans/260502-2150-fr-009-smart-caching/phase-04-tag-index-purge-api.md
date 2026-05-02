# Phase 4 — Tag Index + Admin Purge API

**Effort:** 2d · **Priority:** P1 · **Status:** complete · **Depends on:** Phase 3

## Context

- Brainstorm: [`../reports/brainstorm-260502-2140-fr-009-smart-caching.md`](../reports/brainstorm-260502-2140-fr-009-smart-caching.md) §8
- Existing admin API: `crates/waf-api/src/cache_api.rs`, `crates/waf-api/src/server.rs`

## Goal

Tag-based purge — operators invalidate logical groups of cached entries (e.g. `purge tag=catalog`) without restarting or flushing the whole cache.

## Related Code

**Read:**
- `crates/waf-api/src/cache_api.rs` — current cache endpoints (flush, stats)
- `crates/waf-api/src/server.rs` — route registration
- `crates/gateway/src/cache/store.rs` — moka wrapper

**Modify:**
- `crates/gateway/src/cache/store.rs` — add tag index, hook into `put`/eviction
- `crates/gateway/src/cache/mod.rs` — expose `purge_by_tag`, `purge_by_route_id`
- `crates/waf-api/src/cache_api.rs` — new endpoints
- `crates/waf-api/src/server.rs` — register routes

**Create:**
- `crates/gateway/src/cache/tag_index.rs` — DashMap-based reverse index

## Tag Index Design

```rust
pub struct TagIndex {
    // tag → set of cache keys
    tag_to_keys: DashMap<Arc<str>, DashSet<Arc<str>>>,
    // key → tags it was registered under (for eviction cleanup)
    key_to_tags: DashMap<Arc<str>, SmallVec<[Arc<str>; 4]>>,
}

impl TagIndex {
    pub fn register(&self, key: &Arc<str>, tags: &[Arc<str>]);
    pub fn unregister(&self, key: &Arc<str>);                  // called by moka eviction listener
    pub fn keys_for_tag(&self, tag: &str) -> Vec<Arc<str>>;    // snapshot — releases locks before purge
}
```

`Arc<str>` deduplication: tags are interned at YAML compile time (Phase 3 already produces `Vec<Arc<str>>`); same Arc instances flow into the index.

## Eviction Listener

Moka supports `eviction_listener`. Hook it into `Cache::builder()`:

```rust
.eviction_listener(move |k: Arc<String>, _v, _cause| {
    tag_index.unregister(&Arc::from(k.as_str()));
})
```

Prevents tag-index leak when entries TTL out or get LRU-evicted.

## Admin API Endpoints (new)

All routes already gated by existing admin auth middleware in `waf-api`.

| Method | Path | Body | Action |
|---|---|---|---|
| POST | `/api/cache/purge/tag` | `{ "tag": "catalog" }` | Purge all keys with this tag |
| POST | `/api/cache/purge/route` | `{ "route_id": "static-assets" }` | Purge all keys cached by this rule |
| POST | `/api/cache/purge/host` | `{ "host": "api.example.com" }` | Existing, retained |
| POST | `/api/cache/purge/key` | `{ "key": "GET:host:/path" }` | Existing, retained |
| POST | `/api/cache/flush` | `{}` | Existing, retained |
| GET | `/api/cache/stats` | — | Existing, includes new `bypassed_*` counters + `tag_index_size` |

Response shape (consistent with existing endpoints):
```json
{ "ok": true, "purged": 142, "duration_ms": 7 }
```

## Implementation Steps

1. Create `cache/tag_index.rs` (`DashMap<Arc<str>, DashSet<Arc<str>>>` + reverse map).
2. Wire `register()` into `ResponseCache::put` happy path (after `Cache::insert`).
3. Wire `unregister()` into moka `eviction_listener` and explicit removal paths.
4. Add `ResponseCache::purge_by_tag(&self, tag: &str) -> usize` — snapshots keys, calls `inner.remove` for each, increments `stats.purges_tag`.
5. Add `ResponseCache::purge_by_route_id(&self, route_id: &str)` — implemented as `purge_by_tag(route_id)` (route_id auto-added as a tag during Phase 3 compile, so every entry is purgeable by its source rule).
   - Update Phase 3 RouteRuleGate output: prepend `Arc::from(rule.id.clone())` to tag list.
6. Extend `CacheStats`: `purges_tag`, `purges_route`, `tag_index_entries`.
7. Add API handlers in `cache_api.rs` — input validation (tag length cap 64, ASCII alnum + `_-:`).
8. Register routes in `server.rs`.
9. Reject malformed bodies with 400; never panic.
10. Tests:
    - Unit: register N keys with tag T, purge T → all gone
    - Unit: TTL expiry triggers eviction listener → tag index shrinks
    - Integration: hit endpoint, verify cache state via stats
    - Concurrent purge + put — no deadlock (DashMap handles it; assert with `tokio::join!`)

## Todo

- [x] `tag_index.rs` with register/unregister/keys_for_tag
- [x] Moka `eviction_listener` wired (with `RemovalCause::Replaced` filter to prevent race)
- [x] `purge_by_tag` and `purge_by_route_id` on `ResponseCache`
- [x] route_id auto-prepended as tag (Phase 3 RouteRuleGate updated)
- [x] `CacheStats` extended (added `purges_tag`, `purges_route`, `tag_index_size`)
- [x] 2 new API endpoints + handlers (`/api/cache/purge/tag`, `/api/cache/purge/route`)
- [x] Input validation on tag strings (≤64 chars, alnum + `_-:`, rejects log-injection)
- [x] Concurrent put/purge stress test (+6 new tests in store.rs, all passing)
- [x] Clippy clean, no `.unwrap()` in non-test code
- [x] OpenAPI/admin docs — N/A, `waf-api` has no spec file (noted, not marked done)

## Success Criteria

- `purge_by_tag("catalog")` removes only catalog-tagged entries; other tags untouched
- 10k key purge < 50ms (bench in Phase 5)
- Tag index size returns to zero after `flush`
- Eviction-driven cleanup confirmed via stats delta over 1k TTL-expired entries
- API rejects tags >64 chars or with shell-special chars (defense-in-depth)

## Risks

| Risk | Mitigation |
|---|---|
| Tag index unbounded growth | Eviction listener cleanup + per-entry size cap (Phase 3 defaults.max_body_bytes) |
| Race: `put` registers tag, concurrent `purge` runs before insert visible | DashMap atomicity; even if ordering flips, next purge will catch it |
| Operator purges wrong tag, mass cache miss | Stats endpoint shows recent purges; document purge audit trail; consider dry-run flag (defer) |
| API auth bypass exposes purge to attackers (cache stampede tool) | Reuse existing admin auth; add rate-limit on purge endpoints |

## Security Considerations

- **Purge auth must be admin-only.** A public purge endpoint = trivial DDoS amplifier (force every request to hit origin).
- Rate-limit purge endpoints (e.g. 10/min per admin token) — leverage existing FR-004 rate limiter if landed.
- Audit-log every purge: timestamp, admin identity, tag/route_id, count purged. Append-only JSON (FR-032 format).
- Tag string validation: prevent log injection (`\n`, `\r` rejected) — common forgotten edge case.
- Never echo unsanitized tag in error responses (XSS via admin panel).

## Deferred to Phase 5

The following items were not implemented in Phase 4 — carry forward to Phase 5 scope:

1. **Bench: 10k key purge < 50ms** — Performance gate for tag purge scalability
2. **TTL-expiry → eviction-listener cleanup integration test** — Verify tag index shrinks when entries expire
3. **Long-running `tag_index_size` monotonicity test under sustained load** — Stress-test eviction correctness
4. **Audit logging of purge events** — Append-only audit trail with timestamp, admin identity, tag/route_id, count purged (waiting on FR-032 audit logging framework)

## Next Steps

→ Phase 5: tests, benches, coverage gate. Incorporate deferred items into test matrix + benches.
