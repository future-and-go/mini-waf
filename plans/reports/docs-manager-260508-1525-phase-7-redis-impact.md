# Phase 7 Redis Cluster Backend — Documentation Impact Assessment

## Status
**Docs impact: MAJOR** — Phase 7 Redis implementation requires updates across 3 critical doc files.

---

## Summary

Phase 7 adds `RedisRiskStore` backend for FR-025 cumulative risk scoring, enabling cluster-wide shared risk state via atomic Lua scripts. This is a production-critical feature for distributed deployments but is **completely undocumented in current guides**.

---

## Files Created (Phase 7)
- `crates/waf-engine/src/risk/store/redis.rs` (23.7 KB) — Main `RedisRiskStore` impl
- `crates/waf-engine/src/risk/store/redis_lua.rs` (6.7 KB) — Lua scripts (APPLY, FORCE_MAX, MINT_OR_GET_OWNER)
- `crates/waf-engine/src/risk/tests/conformance_redis.rs` — Conformance tests vs memory impl
- `crates/waf-engine/src/risk/tests/redis_failover.rs` — Fail-open circuit breaker tests

## Files Modified (Phase 7)
- `crates/waf-engine/src/risk/config.rs` — Added `RedisStoreConfig` struct with 5 tunable parameters
- `crates/waf-engine/src/risk/store/mod.rs` — Conditional export of `redis` module
- `crates/waf-engine/src/risk/mod.rs` — Feature gate `#[cfg(feature = "redis-store")]`

---

## Key Implementation Details

### Configuration (YAML)
```yaml
risk:
  store:
    backend: "redis"           # "memory" or "redis"
    redis:
      url: "redis://127.0.0.1:6379"
      key_prefix: "waf:risk:"
      op_timeout_ms: 100
      breaker_threshold: 5
      cache_capacity: 10000
```

**Tunable parameters:**
| Param | Default | Range | Purpose |
|-------|---------|-------|---------|
| `url` | `redis://127.0.0.1:6379` | String | Redis connection (with TLS support) |
| `key_prefix` | `waf:risk:` | String | Namespace isolation (useful for multi-tenant) |
| `op_timeout_ms` | 100 | 50–1000 | Per-operation timeout (100ms = p99 acceptable) |
| `breaker_threshold` | 5 | 1–20 | Consecutive failures before circuit opens |
| `cache_capacity` | 10,000 | 1K–100K | Fail-open LRU cache size (fallback if Redis down) |

### Key Layout
- `waf:risk:state:{owner_id}` → JSON RiskState (TTL = `ttl_secs` from YAML)
- `waf:risk:idx:ip:{ip}` → owner_id (collision index)
- `waf:risk:idx:fp:{fp_hash}` → owner_id (fingerprint index)
- `waf:risk:idx:sid:{session_hex}` → owner_id (session index)

### Atomic Lua Scripts
Three scripts execute single-RTT for consistency:

| Script | Purpose | Replaces |
|--------|---------|----------|
| `APPLY_SCRIPT` | GET → decay → fold deltas → SET with TTL | Memory `apply()` + `decay()` combined |
| `FORCE_MAX_SCRIPT` | Set score=100 with pin (canary hit) | Memory `force_max()` |
| `MINT_OR_GET_OWNER_SCRIPT` | Atomic owner_id creation (race-safe) | Memory `get_or_create_owner()` |

### Feature Flag
- **Required for builds:** `cargo build --features redis-store`
- **Conditional compilation:** `#[cfg(feature = "redis-store")]`
- **Backward compatible:** Defaults to MemoryRiskStore if disabled
- **Docker:** Not yet enabled in Dockerfile (`gateway/valkey` feature present, but not `waf-engine/redis-store`)

### Fail-Open Behavior
- Consecutive errors (≥5 per config) → circuit breaker opens
- LRU cache (10K entries default) used during outage
- Gracefully degrades (no 503s, no blocking on Redis latency)
- 100ms timeout prevents request path slowdown

---

## Documentation Gaps

### 1. **docs/deployment-guide.md**
Missing section: **Redis Cluster Setup for Risk Store**

**Required additions:**
- Prerequisites (Redis 6+, network connectivity)
- Single-node Redis setup (development)
- Redis Cluster setup (production HA — 3+ nodes)
- Connection string format with TLS examples
- Failover behavior + circuit breaker explanation
- Monitoring + alerting for Redis outages
- Backup strategy for risk state (if needed)

**Location:** Add after "Configuration Reference" section (line ~370)

**Length estimate:** 80–120 LOC

---

### 2. **docs/system-architecture.md**
Missing subsection under "WafEngine → Risk Scorer (FR-025)" (line 224)

**Current gap:** Lines 275–287 show YAML config but **never mention Redis backend option**. Docs describe only memory store behavior.

**Required additions:**
- Redis backend overview (cluster coherence, atomic Lua scripts)
- Key layout explanation (triple-index + owner_id minting)
- Decay behavior (Lua-atomic vs memory sequential)
- Circuit breaker + fail-open fallback strategy
- Performance implications (single-RTT vs memory O(1))
- Example Redis config with tuning guidance
- Architecture diagram: Risk Scorer with Redis path

**Location:** Expand section "WafEngine → Risk Scorer (FR-025)" (line 224)

**Length estimate:** 120–180 LOC

---

### 3. **docs/code-standards.md**
Missing subsection: **Redis Store Backend Conventions**

**Current gap:** File documents risk delta conventions but **omits backend-specific guidance**.

**Required additions:**
- When to use Memory vs Redis (single-node vs cluster)
- Key design decisions (triple-index strategy, owner_id semantics)
- Lua script maintenance guidelines
- Fail-open LRU cache tuning (capacity, eviction)
- Testing recommendations (conformance vs memory impl parity)
- Circuit breaker thresholds and monitoring

**Location:** Add new section at end, after risk delta table

**Length estimate:** 40–60 LOC

---

### 4. **docs/codebase-summary.md** (auto-generated via repomix)
Needs update to reflect Phase 7 additions

**Required sections:**
- Risk store module breakdown (memory, redis, conformance tests)
- Lua script inventory
- Feature flag documentation
- Redis dependency notes

---

## Building & Deployment Notes

### Build Requirements
```bash
# Enable Redis risk store
cargo build --release --features redis-store

# Current Docker build does NOT include redis-store
# Dockerfile line: cargo build --release --features gateway/valkey
# TODO: Add --features waf-engine/redis-store when ready for release
```

### Configuration Scenarios

**Single-Node Development (Memory Store)**
```yaml
risk:
  store:
    backend: "memory"
```

**3-Node Production Cluster (Shared Redis)**
```yaml
risk:
  store:
    backend: "redis"
    redis:
      url: "redis://redis-primary:6379"
      key_prefix: "prx:prod:risk:"
      op_timeout_ms: 100
      breaker_threshold: 5
      cache_capacity: 50000
```

**HA Redis Cluster (Sentinel or Cluster mode)**
```yaml
risk:
  store:
    backend: "redis"
    redis:
      url: "redis://sentinel-primary:26379/0?name=mymaster"  # Sentinel URL
      key_prefix: "prx:ha:risk:"
      op_timeout_ms: 200
      breaker_threshold: 3
      cache_capacity: 100000
```

---

## Validation Checklist

- [ ] `deployment-guide.md` updated with Redis cluster setup (80–120 LOC)
- [ ] `system-architecture.md` expanded with Redis backend details (120–180 LOC)
- [ ] `code-standards.md` added with Redis conventions (40–60 LOC)
- [ ] `codebase-summary.md` regenerated with `repomix` to reflect Phase 7
- [ ] Example `configs/risk.yaml` created with Redis backend sample
- [ ] Dockerfile updated to enable `waf-engine/redis-store` feature (optional for Phase 7, ready for merge)
- [ ] Redis connection examples tested (TLS, Sentinel, Cluster modes)

---

## Recommendations

### Priority 1 (Blocking Release)
1. **Update `system-architecture.md`** with Redis backend section — operators need to understand cluster coherence
2. **Update `deployment-guide.md`** with Redis cluster setup — production admins need runbook

### Priority 2 (Before Stability Release)
3. **Update `code-standards.md`** with Redis conventions — developers need guidelines
4. **Regenerate `codebase-summary.md`** with `repomix` — LLM tools need accurate inventory

### Priority 3 (Nice to Have)
5. Create example `configs/risk-redis.yaml` with inline comments
6. Add Redis monitoring section to Troubleshooting guide
7. Document Lua script parity testing methodology

---

## Risk Flags

- **Build Feature Not Enabled:** Dockerfile doesn't enable `redis-store` yet. If Phase 7 is merged, builds won't include Redis risk store unless Dockerfile is updated.
- **Config Complexity:** 5 tunable parameters (timeout, cache capacity, breaker threshold) may confuse operators unfamiliar with circuit breaker patterns.
- **Fail-Open Semantics:** LRU cache fallback is correct but undocumented — operators may assume Redis is strictly required.

---

## Next Steps

1. **Create Phase 7 docs plan** with specific doc file targets and LOC budgets
2. **Delegate to docs team** with clear sections and examples
3. **Verify Redis config examples** against actual behavior (especially Sentinel/Cluster modes)
4. **Test documentation accuracy** by running Redis risk store in staging cluster
5. **Mark as READY FOR REVIEW** once all sections complete and cross-references validated

---

## Unresolved Questions

1. Should Dockerfile enable `redis-store` feature on Phase 7 release, or keep it optional?
2. Do we need separate documentation for Redis Sentinel vs Cluster vs standalone modes?
3. Should LRU cache sizing recommendations be per-deployment-scale (single-node vs 3-node cluster)?
4. Is there a need for Redis connection pool tuning docs (redis crate defaults)?
