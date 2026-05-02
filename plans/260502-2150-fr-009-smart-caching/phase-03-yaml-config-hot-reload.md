# Phase 3 — YAML Config + RouteRule Gate + Hot Reload

**Effort:** 3d · **Priority:** P0 · **Status:** complete · **Depends on:** Phase 2

## Context

- Brainstorm: [`../reports/brainstorm-260502-2140-fr-009-smart-caching.md`](../reports/brainstorm-260502-2140-fr-009-smart-caching.md) §5, §9
- Reference watcher: `crates/gateway/src/tiered/tier_config_watcher.rs` (mirror pattern exactly)

## Goal

Per-route TTL via `rules/cache.yaml`, hot-reloadable. Add `AuthGate` and `RouteRule` gate to resolver.

## Related Code

**Read:**
- `crates/gateway/src/tiered/tier_config_watcher.rs` — reference (notify + ArcSwap + debounce)
- `crates/gateway/src/tiered/tier_policy_registry.rs` — ArcSwap registry pattern
- `crates/waf-common/src/url_validator.rs` — path normalization (reuse, do not duplicate)
- `Cargo.toml` workspaces — confirm `notify`, `arc-swap`, `serde_yaml`, `regex` already deps

**Modify:**
- `crates/gateway/src/cache/policy.rs` — add AuthGate + RouteRule to resolver
- `crates/gateway/src/cache/mod.rs` — wire watcher into `ResponseCache::new`

**Create:**
- `crates/gateway/src/cache/config.rs` — YAML schema + validation
- `crates/gateway/src/cache/rule.rs` — `CompiledRule`, `RouteMatcher` (host/path/method spec)
- `crates/gateway/src/cache/rule_set.rs` — `CompiledRuleSet` + `ArcSwap` holder
- `crates/gateway/src/cache/watcher.rs` — `CacheRuleWatcher` (notify + debounce)
- `crates/gateway/src/cache/gates/auth_gate.rs`
- `crates/gateway/src/cache/gates/route_rule_gate.rs`
- `rules/cache.yaml` — initial production-ready ruleset (commented)

## YAML Schema (locked)

See brainstorm §5. Authoritative example to ship in `rules/cache.yaml`:

```yaml
version: 1
defaults:
  max_body_bytes: 1048576
  respect_upstream_cache_control: true
  cacheable_status_codes: [200, 203, 301, 410]   # 404 deliberately excluded; FR-019 owns recon detection
rules:
  - id: static-assets
    match:
      host: "*"
      path: { regex: '^/(static|assets|images|js|css)/' }
      methods: [GET, HEAD]
    ttl_seconds: 86400
    tags: [static, public]
    allow_authenticated: false
```

## Resolver Order (post-Phase 3)

```
TierGate → MethodGate → AuthGate → RouteRule → UpstreamCcGate → TierDefaultGate
```

`AuthGate`: if request has `Authorization` OR `Cookie` AND no matching route has `allow_authenticated: true` → `Bypass(Authenticated)`. **v1 always bypasses** even if `allow_authenticated: true` (defer key-dim hashing — see plan.md open Q1).

`RouteRule`: walk compiled rules in declaration order, first match returns `Cache{ttl: rule.ttl_seconds, tags: rule.tags.clone()}`. `ttl_seconds == 0` → `Bypass(ExplicitDeny)`.

## Implementation Steps

1. **Schema types** (`config.rs`):
   ```rust
   #[derive(Deserialize)] pub struct CacheConfigDoc { version: u32, defaults: Defaults, rules: Vec<RuleDoc> }
   #[derive(Deserialize)] pub struct RuleDoc { id: String, match_: MatchDoc /* serde rename "match" */, ttl_seconds: u32, tags: Vec<String>, #[serde(default)] allow_authenticated: bool }
   #[derive(Deserialize)] pub struct MatchDoc { #[serde(default)] host: Option<String>, path: PathSpec, #[serde(default)] methods: Option<Vec<HttpMethod>> }
   #[derive(Deserialize)] #[serde(untagged)] pub enum PathSpec { Prefix { prefix: String }, Regex { regex: String } }
   ```
2. **Validation** (`config.rs::validate`):
   - `version == 1`
   - rule `id` unique
   - `tags` non-empty (else purge-by-tag is impossible)
   - `path.regex` compiles (use `regex::RegexBuilder::size_limit`)
   - total compiled regex bytes <1 MiB (DoS guard)
   - returns `Result<CompiledRuleSet, ConfigError>` with line-precise errors
3. **`CompiledRule` / `RouteMatcher`** (`rule.rs`):
   ```rust
   pub struct CompiledRule {
       id: Arc<str>,
       host: HostMatcher,        // exact | wildcard | any
       path: PathMatcher,        // Prefix(String) | Regex(regex::Regex)
       methods: SmallMethodSet,  // bitset over HttpMethod
       ttl: Duration,
       tags: Vec<Arc<str>>,
       allow_authenticated: bool,
   }
   impl CompiledRule { fn matches(&self, host: &str, path: &str, method: HttpMethod) -> bool }
   ```
4. **`CompiledRuleSet`** (`rule_set.rs`): `Arc<[CompiledRule]>` + defaults; held in `ArcSwap<Arc<CompiledRuleSet>>`. Lock-free `load()` on hot path.
5. **`CacheRuleWatcher`** (`watcher.rs`): copy-pattern of `tier_config_watcher.rs`. On debounced event:
   - parse + validate file
   - on success: `swap()`, log `cache_reload_ok`
   - on failure: keep prior, log `cache_reload_fail` with error context
6. **`AuthGate`** (`gates/auth_gate.rs`): probe `Authorization` and `Cookie` request headers. Cheap header lookup, no parsing.
7. **`RouteRuleGate`** (`gates/route_rule_gate.rs`): borrow `&CompiledRuleSet` from ArcSwap; iterate; first match wins.
8. **Wire**: `ResponseCache::new` accepts `Arc<ArcSwap<CompiledRuleSet>>` + spawns `CacheRuleWatcher`. Update `proxy.rs` boot to load `rules/cache.yaml` (path from `configs/default.toml::cache.rules_path`).
9. **Config plumbing** (`waf-common::config`): add `cache.rules_path: Option<PathBuf>` (default `rules/cache.yaml`).
10. **Boot semantics**:
    - Missing file → empty ruleset (warn-log), proceed
    - Parse error on boot → fail-fast (loud)
    - Parse error on reload → keep prior, log

## Todo

- [x] `cache/config.rs` schema + serde + validation
- [x] `cache/rule.rs` `CompiledRule` + matchers
- [x] `cache/rule_set.rs` `CompiledRuleSet` + ArcSwap holder
- [x] `cache/watcher.rs` notify + debounce + validate-then-swap
- [x] `cache/gates/auth_gate.rs`
- [x] `cache/gates/route_rule_gate.rs`
- [x] Resolver insert order: AuthGate before RouteRule before UpstreamCcGate
- [x] `rules/cache.yaml` shipped with comments
- [x] `configs/default.toml` `cache.rules_path` documented
- [x] Unit tests: schema parse (valid + invalid cases)
- [x] Unit tests: matcher (host wildcard, path regex/prefix, method bitset)
- [x] Integration test: write yaml → ruleset picks up new TTL after debounce
- [x] Integration test: bad yaml on reload → prior config still serves
- [x] Clippy clean, no `.unwrap()` in non-test code

## Success Criteria

- Static asset path matches → cached at YAML-specified TTL
- `Authorization: Bearer ...` request → bypass (regardless of route match)
- File watcher detects edit; new TTL applied on next request after debounce window
- Bad YAML reload → prior ruleset still serves, warn logged with line number
- Empty `rules/cache.yaml` valid (zero rules), only TierDefaultGate effective

## Risks

| Risk | Mitigation |
|---|---|
| Regex catastrophic backtrack | rust `regex` crate is linear-time; size_limit cap |
| Hot-reload race during traffic spike | ArcSwap atomic; in-flight requests see consistent snapshot |
| YAML schema drift between versions | `version: 1` field; reject unknown versions |
| Cookie header bypass too aggressive (kills cache hit rate for sites using session cookies on public pages) | Document trade-off; future `allow_authenticated` + key dims (open Q1) |
| Path normalization mismatch with proxy | Reuse `waf-common::url_validator` — single source of truth |

## Security Considerations

- `AuthGate` is conservative-by-default (any Cookie → bypass). Reduces cache poisoning surface to near zero for v1.
- `Set-Cookie` in response → bypass (already in UpstreamCcGate from Phase 2; double-check coverage).
- Bad regex → drop *that rule only* (fail-closed for the rule, not the whole ruleset). If too many rules drop, log error rate.
- No symlink following on `rules/cache.yaml` (rely on Pingora deployment hardening; document in plan).
- Watcher thread errors must not panic — `.expect("BUG: ...")` only for compile-time invariants; runtime errors logged + continue.

## Next Steps

→ Phase 4: tag index + admin purge API.
