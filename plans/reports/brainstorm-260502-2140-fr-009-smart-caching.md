# FR-009 Smart Caching — Design Brainstorm

**Date:** 2026-05-02
**Source req:** `analysis/requirements.md` §3.1 FR-009
**Scope:** Production-ready, security-domain. Not MVP.

---

## 1. Problem

FR-009 acceptance:
- No cache for CRITICAL tier
- Aggressive cache for MEDIUM tier
- Configurable TTL per route

Current state (`crates/gateway/src/cache.rs` + `crates/waf-common/src/tier.rs`):
- moka LRU + global default/max TTL + Cache-Control parsing
- Per-tier `CachePolicy` enum exists in TOML schema but **not wired** to `ResponseCache::put()`
- No per-route TTL, no YAML rule format, no tag/purge API
- Critical-tier bypass is not enforced — a CRITICAL route would be cached today if upstream sends `Cache-Control: max-age=N`

**Production gaps:** tier-gate enforcement, auth-aware bypass, per-route YAML config + hot-reload, tag-based purge.

---

## 2. Locked Decisions (user-confirmed)

| Concern | Decision |
|---|---|
| Per-route config | Dedicated `rules/cache.yaml`, hot-reloadable |
| Hardening | Tier-gated CRITICAL bypass + auth-aware key |
| Invalidation | TTL + tag-based purge API |
| Persistence | Ephemeral in-memory (moka only) |

**Out of scope (deliberate):** single-flight stampede protection, conditional GET / ETag, Vary header, disk persistence, cluster-shared cache. Re-evaluate post-FR-009.

---

## 3. Design Patterns Applied

| Pattern | Where | Why |
|---|---|---|
| **Chain of Responsibility** | `CachePolicyResolver` — ordered gates: TierGate → MethodGate → AuthGate → RouteRule → UpstreamCC → TierDefault | First definitive verdict wins. Defense-in-depth: tier-gate fires before any rule-level logic can override it. |
| **Strategy** | Each gate impls `trait CacheGate { fn evaluate(ctx) -> Verdict }` returning `Bypass / Cache(ttl,tags) / Continue` | Gates composable, individually testable, swappable. |
| **Specification** | `RouteMatcher` = host AND path AND method, composed | Mirrors existing tier_match style. Cheap, regex precompiled. |
| **Observer + ArcSwap** | `CacheRuleStore` holds `ArcSwap<Arc<CompiledRuleSet>>`; `notify` watcher swaps on file change | Lock-free reads on hot path. Same pattern as `tiered::tier_config_watcher`. Validate-then-swap → bad YAML never reaches traffic. |
| **Facade** | `ResponseCache` exposes `decide / get / put / purge_*` — callers don't see internal gates | Surgical change vs current callers. |
| **Builder** | `CacheRuleSet::compile(YamlDoc) -> Result<CompiledRuleSet>` precompiles regex at load | Pay regex compile once, not per request. |
| **Repository** | Tag index `DashMap<Tag, HashSet<CacheKey>>` | O(1) purge-by-tag amortized. |

Rejected: full Visitor (overkill), Decorator stack (CoR is cleaner here), Repository for cache itself (moka already that).

---

## 4. Architecture

```
                ┌──────────────────────┐
   request ───▶ │  CachePolicyResolver │
                │  (CoR pipeline)      │
                └──┬───────────────────┘
                   │ reads (lock-free)
   ┌───────────────┼─────────────────────────────────┐
   ▼               ▼                                 ▼
┌─────────┐   ┌──────────────┐                ┌──────────────┐
│ Tier    │   │ ArcSwap<     │                │ ResponseCache│
│ Policy  │   │  CompiledRule│                │ (moka + tag  │
│ (waf-   │   │  Set>        │                │  index)      │
│  common)│   └──────▲───────┘                └──────────────┘
└─────────┘          │ swap                          ▲
                ┌────┴────────┐                      │
                │ HotReload   │           purge_by_tag│
                │ Watcher     │           via admin API
                │ (notify)    │                      │
                └─────────────┘                ┌─────┴─────┐
                                               │ waf-api   │
                                               └───────────┘
```

### Module layout

```
crates/gateway/src/cache/
├── mod.rs            # facade re-exports (back-compat with existing call sites)
├── store.rs          # moka wrapper + tag index + stats (extends current cache.rs)
├── policy.rs         # CachePolicyResolver + Verdict + gate trait
├── gates.rs          # TierGate, MethodGate, AuthGate, RouteRule, UpstreamCC, TierDefault
├── rule.rs           # CacheRule + RouteMatcher (compiled)
├── config.rs         # YAML schema (serde) + validation
└── watcher.rs        # notify-based hot reload (ArcSwap swap)
```

Existing `crates/gateway/src/cache.rs` becomes `cache/store.rs` + `cache/mod.rs` re-exports — back-compat preserved.

---

## 5. YAML Schema (`rules/cache.yaml`)

```yaml
version: 1

defaults:
  max_body_bytes: 1048576           # 1 MiB cap per entry
  respect_upstream_cache_control: true
  cacheable_status_codes: [200, 203, 301, 404, 410]

rules:
  - id: static-assets
    match:
      host: "*"                     # wildcard or exact
      path: { regex: '^/(static|assets|images|js|css)/' }
      methods: [GET, HEAD]
    ttl_seconds: 86400
    tags: [static, public]
    allow_authenticated: false      # default — skip if Authorization/Cookie present

  - id: api-public-catalog
    match:
      host: "api.example.com"
      path: { prefix: "/v1/catalog" }
      methods: [GET]
    ttl_seconds: 60
    tags: [api, catalog]

  - id: deny-admin
    match:
      path: { prefix: "/admin" }
    ttl_seconds: 0                  # explicit bypass (defensive)
    tags: [admin]
```

Validation rules (fail-closed at load):
- `version` must equal 1 (forward-compat)
- `ttl_seconds` >= 0; 0 means explicit bypass
- `path.regex` must compile; invalid → reject entire ruleset, keep prior `ArcSwap` snapshot
- `tags` non-empty if rule caches (else purge-by-tag impossible)
- Duplicate `id` → reject
- Total compiled regex bytes capped (DoS guard: 1 MiB)

---

## 6. Decision Pipeline (security-critical ordering)

```
TierGate         : tier == CRITICAL  → Bypass        [terminal, non-overridable]
MethodGate       : !GET && !HEAD     → Bypass        [terminal]
AuthGate         : has Authorization|Cookie           [terminal unless rule allow_authenticated]
                   AND no rule with allow_authenticated=true matches → Bypass
RouteRule        : first matching rule → Cache(ttl=rule.ttl, tags=rule.tags)
UpstreamCC       : response Cache-Control              [refines, never raises CRITICAL]
                   no-store|private|Set-Cookie present → Bypass
                   max-age=N → ttl = min(ttl, N)
TierDefault      : fall back to TierPolicy.cache_policy (Aggressive/ShortTtl/Default/NoCache)
```

**Invariant:** TierGate runs first AND the verdict it returns cannot be elevated by any later gate. CRITICAL-tier traffic is uncacheable even if `cache.yaml` and upstream both say cache. This is the audit-defensible property for the security domain.

---

## 7. Cache Key Construction

```
key = {method}:{lower(host)}:{normalized_path}?{sorted_query}
```

Hardening:
- Host lowercased; port stripped if default (80/443) — prevents `example.com` vs `Example.com:80` poisoning
- Path normalized through existing `waf-common::url_validator` (prevents `/a` vs `/a/.` divergence)
- Query params sorted alphabetically — prevents key explosion via param reorder
- **No header dimensions** in v1 (we deferred Vary). Auth-bearing requests bypass entirely → no auth-mixing risk.

---

## 8. Tag Index (purge-by-tag)

```rust
struct TagIndex {
    tag_to_keys: DashMap<Arc<str>, HashSet<Arc<str>>>,
}
```

- `put(key, tags)` registers key under each tag (Arc<str> dedupe)
- `purge_by_tag(tag)` drains entry, then calls `moka.remove` for each key
- Moka eviction listener removes key from tag index → no stale tag entries
- Memory cap: tag index size monitored via `CacheStats`; bounded by moka capacity

Admin API additions (`waf-api`):
- `POST /api/cache/purge` `{ "tag": "catalog" }`
- `POST /api/cache/purge` `{ "host": "api.example.com" }`
- `POST /api/cache/purge` `{ "key": "GET:host:/path" }`
- `POST /api/cache/flush` (existing)
- All gated by existing admin auth.

---

## 9. Hot Reload Flow

```
notify::watch(rules/cache.yaml)
  └─▶ debounce 500ms
      └─▶ load + parse + validate + compile regex
          ├─ ok    → ArcSwap.store(new) ; emit metric reload_ok
          └─ fail  → keep prior ; log error ; emit reload_fail ; do NOT crash
```

In-flight requests on the hot path read via `ArcSwap::load()` → see either old or new ruleset, never partial. Existing tier_config_watcher.rs is the reference implementation.

---

## 10. Failure Modes & Resilience

| Failure | Behavior | Why |
|---|---|---|
| `cache.yaml` missing on boot | Empty ruleset; only TierGate + TierDefault active | Caching is a perf feature, not safety-critical. Boot must succeed. |
| `cache.yaml` parse error on boot | Boot fails (loud) | Operator misconfig at boot ≠ runtime drift. Fail-fast. |
| `cache.yaml` parse error on reload | Keep prior snapshot | Don't kill production on a typo. |
| Route regex DoS (catastrophic backtrack) | Mitigated by regex crate (no backtracking) + total compiled-bytes cap | rust-regex is linear-time. |
| Cache memory exhaustion | moka `max_capacity` + per-entry `max_body_bytes` | Hard caps. |
| Tag-index leak | moka eviction listener cleans tag refs | Prevents unbounded growth. |
| Cache poisoning via Host header | Host normalized + tier classifier already validates | Defense-in-depth. |
| TOCTOU on rule reload | ArcSwap atomic | Lock-free reads. |

---

## 11. Test Plan (production gate)

Unit:
- Each gate independently — table-driven (request × tier × rule → verdict)
- YAML parse: valid, invalid version, bad regex, dup id, ttl<0
- Tag index: put / purge / eviction-listener cleanup
- Key normalization: host case, query reorder, port stripping

Integration (`crates/gateway/tests/`):
- CRITICAL tier + upstream `Cache-Control: max-age=3600` → MUST NOT cache (regression guard for the core security invariant)
- MEDIUM tier + Aggressive policy + matching route → cached, served from cache
- Authorization header → bypass; same path without → cached
- Hot reload: write bad yaml → prior ruleset still serves; write good yaml → new TTL applied

Bench (`benches/`):
- Decision pipeline p99 < 50µs (target — must not eat into FR p99 ≤ 5ms budget)
- Tag purge of 10k keys < 50ms

CI gate: 95% line coverage on `cache/` (matches existing gateway gate per gateway/CLAUDE.md).

---

## 12. Implementation Phases (suggested)

1. **Phase 1 — Tier wiring (urgent fix).** Add TierGate to existing `cache.rs::put()`. CRITICAL traffic stops being cacheable. ~1 day. Ships the security invariant first.
2. **Phase 2 — Refactor to `cache/` module + decision pipeline.** Extract gates, keep YAML inert. No behavior change. ~2 days.
3. **Phase 3 — YAML config + RouteRule gate + hot reload.** ~3 days.
4. **Phase 4 — Tag index + admin purge API.** ~2 days.
5. **Phase 5 — Tests, benches, coverage gate.** ~2 days.

Total ~10 dev-days. Phase 1 ships the invariant immediately even if 2-5 slip.

---

## 13. Success Criteria

- [ ] CRITICAL-tier route never cached, regardless of upstream/YAML config (integration test asserts)
- [ ] MEDIUM-tier matching `static/*` → 24h TTL hit (integration test asserts)
- [ ] `cache.yaml` reloaded without restart; bad YAML rejected, prior config served
- [ ] `POST /api/cache/purge {tag:"catalog"}` invalidates only tagged entries
- [ ] Authorization-bearing request bypasses cache unless route opts in
- [ ] p99 decision overhead < 50µs (bench)
- [ ] 95% line coverage on `gateway/src/cache/`
- [ ] `cargo clippy --workspace -- -D warnings` clean

---

## 14. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| CRITICAL bypass not actually enforced (the headline FR violation) | High | Phase 1 ships gate first; integration test is non-skippable |
| Cache poisoning via header dimensions deferred | Medium | Auth-gate bypass + no Vary support → authed responses never cached at all |
| Hot-reload race elevates risk during config change | Low | ArcSwap atomic; in-flight requests see consistent snapshot |
| Tag index unbounded growth | Low | Moka eviction listener cleanup + capacity cap |
| Clipping upstream `max-age` to 0 surprises operators | Low | Clear docs: tier policy is the floor, not negotiable |

---

## 15. Open Questions

1. Should `allow_authenticated: true` routes hash `Authorization` into the key, or refuse to cache and require an explicit `key_dims` extension? (v1: refuse — defer key_dims.)
2. Should `cache.yaml` live next to `rules/` (security rules) or under `configs/`? (Recommend `rules/` — it's hot-reloadable + per-deployment.)
3. Negative caching (4xx/5xx) policy — current schema only lists 200/203/301/404/410 as cacheable; 404 included to deflect recon scans, but is that desired given FR-019 (error scanning detection)? Possibly remove 404.
4. Per-tier cache size budgets (e.g. CRITICAL=0, HIGH=64MB, MEDIUM=192MB)? Currently single global cap.
