---
title: "FR-009 Smart Caching — Implementation"
description: "Tier-aware response cache with hot-reloadable rules/cache.yaml, auth bypass, tag-based purge. CRITICAL bypass non-overridable. Production-grade."
status: pending
priority: P0
effort: 10d
branch: main
tags: [waf, gateway, fr-009, caching, hot-reload, security]
created: 2026-05-02
blockedBy: []
blocks: []
---

## Source

Design doc (locked decisions, patterns, ACs): [`../reports/brainstorm-260502-2140-fr-009-smart-caching.md`](../reports/brainstorm-260502-2140-fr-009-smart-caching.md)

Builds on (complete): FR-002 [`../260429-1006-fr-002-tiered-protection/plan.md`](../260429-1006-fr-002-tiered-protection/plan.md) — `TierPolicy.cache_policy` + classifier already shipped.

Reference impl pattern: `crates/gateway/src/tiered/tier_config_watcher.rs` (notify + ArcSwap, mirror exactly).

## Scope

Close FR-009 acceptance criteria:
- AC-1: No cache for CRITICAL tier (non-overridable, defense-in-depth)
- AC-2: Aggressive cache for MEDIUM tier
- AC-3: Configurable TTL per route via YAML

Plus production hardening (locked):
- Auth-aware bypass (Authorization/Cookie/Set-Cookie)
- Hot-reloadable `rules/cache.yaml` (notify + ArcSwap)
- Tag-based purge admin API
- Ephemeral moka, no persistence

Out of scope (deferred): single-flight, conditional GET/ETag, Vary headers, disk persistence, cluster-shared cache.

## Design Patterns

| Pattern | Location |
|---|---|
| Chain of Responsibility | `cache::policy::CachePolicyResolver` |
| Strategy | `cache::gates::*` (TierGate, MethodGate, AuthGate, RouteRule, UpstreamCC, TierDefault) |
| Specification | `cache::rule::RouteMatcher` (host AND path AND method) |
| Observer + ArcSwap | `cache::watcher::CacheRuleWatcher` |
| Builder | `cache::config::CacheRuleSet::compile` |
| Repository | `cache::store::TagIndex` |
| Facade | `cache::ResponseCache` (preserves existing call sites) |

## Phases

| # | File | Effort | Status |
|---|---|---|---|
| 1 | [phase-01-tier-gate-wiring.md](./phase-01-tier-gate-wiring.md) | 1d | completed |
| 2 | [phase-02-module-refactor-pipeline.md](./phase-02-module-refactor-pipeline.md) | 2d | pending |
| 3 | [phase-03-yaml-config-hot-reload.md](./phase-03-yaml-config-hot-reload.md) | 3d | pending |
| 4 | [phase-04-tag-index-purge-api.md](./phase-04-tag-index-purge-api.md) | 2d | pending |
| 5 | [phase-05-tests-benches-coverage.md](./phase-05-tests-benches-coverage.md) | 2d | pending |

**Phase 1 ships the security invariant first** — even if 2-5 slip, CRITICAL traffic stops being cacheable.

## Critical Invariants (audit-defensible)

1. CRITICAL tier → cache bypass is **non-overridable** by YAML or upstream `Cache-Control`
2. `Set-Cookie` in response → never cache
3. Authorization/Cookie in request → bypass unless route opts in (v1 always bypasses)
4. YAML reload validates fully before ArcSwap; bad YAML → keep prior, never partial
5. Bad regex in route → drop rule (fail-closed for that route), never crash proxy

## Success Criteria (plan-level)

- [ ] All 5 phases complete
- [ ] Integration test: CRITICAL + upstream max-age=3600 → not cached
- [ ] Integration test: MEDIUM + static asset → cached, tag purge invalidates
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] 95% line coverage on `crates/gateway/src/cache/**`
- [ ] No `.unwrap()` / `todo!()` / `unimplemented!()` in production code (Seven Iron Rules)
- [ ] Decision pipeline p99 < 50µs (bench)

## Risks (plan-level)

| Risk | Mitigation |
|---|---|
| FR-001 reverse-proxy refactor (pending) touches gateway/src/ | Keep `cache/` module isolated; coordinate at integration |
| Cache poisoning via header dimensions (Vary deferred) | Auth-bearing requests bypass entirely — no auth-mixing risk |
| Tag index unbounded growth | Moka eviction listener + capacity cap |
| Hot-reload breaks production on typo | Validate-then-swap; keep prior on failure |

## Open Questions

1. Should `allow_authenticated: true` routes hash `Authorization` into key, or refuse to cache? (v1: refuse — defer key_dims)
2. Should `cache.yaml` live under `rules/` or `configs/`? (recommend `rules/` — hot-reloadable like other rule files)
3. Cache 404 to deflect recon, or skip 404 to keep FR-019 error-scan signal? (defer, keep 404 cacheable initially, document trade-off)
4. Per-tier cache size budgets (CRITICAL=0, HIGH=64MB, MEDIUM=192MB) vs single global cap? (start global, add per-tier in follow-up if needed)
