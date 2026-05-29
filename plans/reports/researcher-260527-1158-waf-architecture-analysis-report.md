# WAF Architecture & Modularity Research Report

**Date:** 2026-05-27 | **Author:** Researcher Agent  
**Scope:** Crate dependencies, shared state patterns, feature module architecture  
**Objective:** Understand how to add new capabilities without breaking existing code

---

## Executive Summary

The mini-WAF is architected as a **7-crate microkernel** with clear separation of concerns. New features follow an established **Feature Module Pattern** (FMP) exemplified by rate-limiting (FR-004) and challenge rendering (FR-025). The codebase enforces strict trait boundaries (`Check`, `RateLimitStore`, `RuleReloader`) for plugin-like extension, shared state via `Arc<T>` + `ArcSwap<T>` for hot-reload, and deterministic composition through the engine's checker pipeline.

**Key finding:** Trait-based modularity + atomic-swap hot-reload eliminates the need for global locks or service restarts when adding detection checks, rate-limit backends, or custom rule formats.

---

## 1. Crate Dependency Graph

### Linear Dependency Chain
```
waf-common (leaf — no internal deps)
    ↓
waf-storage
    ↓
[waf-engine, gateway]
    ↓
waf-api
    ↓
waf-cluster
    ↓
prx-waf (binary — depends on all)
```

### Detailed Graph

| Crate | Depends On | Purpose | Lines of Code |
|-------|-----------|---------|----------------|
| **waf-common** | serde, bytes, regex, ipnet, aes-gcm, sha2, url | Shared types, config, crypto, tier matching | ~2,000 |
| **waf-storage** | waf-common, sqlx, tokio | PostgreSQL layer, models, CRUD | ~1,500 |
| **waf-engine** | waf-common, waf-storage, wasmtime, rhai, libinjection, redis (opt) | Core detectors, rules, plugins, device-fp, CrowdSec | ~18,000 |
| **gateway** | waf-common, waf-engine, waf-storage, pingora, moka, quinn, h3 | Proxy, TLS, HTTP/3, cache, filters, pipeline | ~12,000 |
| **waf-api** | waf-common, waf-storage, waf-engine, waf-cluster, gateway, axum | Admin REST API, WebSocket, JWT, embedded UI | ~8,000 |
| **waf-cluster** | waf-common, waf-engine, quinn, rustls | QUIC/mTLS peer sync, leader election | ~4,000 |
| **prx-waf** | All above + pingora, tokio, clap | Binary entry, CLI, bootstrap, service wiring | ~1,500 |

### Key Constraint
- **No reverse dependency:** Lower crates (waf-common, waf-storage) do NOT import from upper crates (gateway, waf-api). This allows top-level crates to inject behavior at runtime without circular deps.
- **Vendored Pingora:** Custom fork at `vendor/pingora/` patched with TLS/HTTP2 inspector hooks (FR-010 device fingerprinting). Crates.io refs redirected via `[patch.crates-io]`.

---

## 2. Shared State Patterns

### AppState (waf-api)
**File:** `crates/waf-api/src/state.rs:16` (142 lines)

```rust
pub struct AppState {
    pub db: Arc<Database>,                      // PostgreSQL pool (sqlx)
    pub engine: Arc<WafEngine>,                 // Detection engine (hot-reloadable components)
    pub router: Arc<HostRouter>,                // Host → upstream routing table
    pub cache: Arc<ResponseCache>,              // moka-backed LRU + Valkey optional
    pub request_counter: Arc<AtomicU64>,        // Metrics (no Mutex)
    pub blocked_counter: Arc<AtomicU64>,
    pub ws_connections: Arc<AtomicU32>,
    pub plugin_manager: Arc<PluginManager>,     // WASM/Rhai plugins (hot-loadable)
    pub tunnel_registry: Arc<TunnelRegistry>,   // Reverse tunnels
    pub crowdsec_cache: Option<Arc<DecisionCache>>, // CrowdSec optional
    pub community_reporter: Option<Arc<CommunityReporter>>,
    pub cluster_state: Option<Arc<waf_cluster::NodeState>>, // HA cluster optional
    // ... + security config, rate limiters, logs handler, etc.
}
```

**Injection Pattern:**
- Created once in `prx-waf/src/main.rs` at startup.
- Cloned & passed as `Extension<AppState>` to Axum handlers.
- Engine hot-reloadable checks stored in `Arc<ArcSwap<Config>>` — config snapshots swapped atomically without blocking readers.

### Engine Checker Composition
**File:** `crates/waf-engine/src/engine.rs:60-120`

```rust
pub struct WafEngine {
    pub store: Arc<RuleStore>,
    pub custom_rules: Arc<CustomRulesEngine>,
    pub sensitive: Arc<SensitiveCheck>,
    pub hotlink: Arc<AntiHotlinkCheck>,
    checkers: Vec<Box<dyn Check>>,     // Dynamic pipeline
    owasp: Arc<OWASPCheck>,
    geo_check: Arc<GeoCheck>,
    sqli_check: Arc<SqlInjectionCheck>,
    // Optional components set via OnceLock:
    crowdsec_checker: OnceLock<Arc<CrowdSecChecker>>,
    community_checker: OnceLock<Arc<CommunityChecker>>,
    geoip: OnceLock<Arc<GeoIpService>>,
    // Hot-reloadable configs:
    rate_limit_cfg: Arc<ArcSwap<RateLimitConfig>>,
    device_fp_cfg: Arc<ArcSwap<DeviceFingerprint>>,
    // ... + file watchers for custom rules, rate-limit yaml, etc.
}
```

**Key insight:** Checkers registered in `checkers` vector at construction. Each implements `trait Check { fn check(&self, ctx) -> Option<DetectionResult> }`. New detectors added by instantiating + registering without modifying existing checks.

---

## 3. Test Infrastructure

**Test Count by Crate:**
- `waf-engine`: ~80 test functions (inline `#[cfg(test)]` + integration suites)
- `gateway`: ~40 tests (inline per filter + benchmarks)
- `waf-api`: ~25 tests (handler + auth + middleware tests)
- `waf-common`: ~15 tests (config, crypto, URL validation)
- `waf-cluster`: ~20 tests (election, peer eviction, sync)
- `waf-storage`: ~10 tests (migrations, models)
- **Total:** ~189 test files/modules across workspace

**Test Infrastructure:**
- **Inline tests:** `#[cfg(test)] mod tests { ... }` in each file — encourages co-location.
- **Fixtures:** `tempfile`, `wiremock`, `testcontainers` (Postgres) for integration.
- **Mocking:** `mockall` for trait mocks, custom `MockClock` for deterministic time in rate-limit/DDoS tests.
- **Benchmark suite:** Criterion benchmarks in `benches/` — tier classifier, cache resolver, SQL injection patterns, rule eval, relay lookup, device-fp pipeline.
- **Coverage gate:** 95% line coverage enforced on gateway filters/policies via `cargo-llvm-cov`.

---

## 4. Feature Module Pattern (FMP)

### Exemplar: Rate Limiting (FR-004)

**Structure:**
```
crates/waf-engine/src/checks/rate_limit/
├── mod.rs           # Public re-exports, RateLimitConfig struct
├── config.rs        # YAML schema (RateLimitFileConfig, TierMap, LimitCfg)
├── check.rs         # RateLimitCheck impl of Check trait
├── key.rs           # Key construction (IP / session keying logic)
├── reload.rs        # RateLimitReloader watches rate-limit.yaml, swaps ArcSwap
├── store/           # Trait + implementations
│   ├── mod.rs       # RateLimitStore trait definition
│   ├── memory.rs    # MemoryStore (HashMap, Arc<Mutex>)
│   └── redis.rs     # RedisStore (optional, gated by `redis-store` feature)
├── algo/            # Token-bucket + sliding-window math
└── conformance.rs   # Shared test suite for store implementations
```

**Integration into Engine:**

```rust
// In engine.rs constructor:
let rl_store = Arc::new(MemoryStore::new()); // or RedisStore
let rl_check = RateLimitCheck::new(rl_store.clone(), cfg.clone());
engine.checkers.push(Box::new(rl_check));

// In hot-reload watcher:
engine.rate_limit_cfg.store(Arc::new(new_cfg)); // atomically swap
// In-flight requests see new config next time check() runs
```

**Files Modified at Integration:**
1. `checks/mod.rs` → Re-export RateLimitCheck + RateLimitConfig
2. `checks/rate_limit/mod.rs` → Public API (check, config, reload)
3. `engine.rs` → Register check in checkers vec + set OnceLock for reloader
4. `lib.rs` → Export RateLimitCheck if public; else hide

**Trait Boundary:**
```rust
pub trait Check: Send + Sync {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult>;
    fn on_response(&self, ctx: &RequestCtx, status: u16) {} // optional
}

pub trait RateLimitStore: Send + Sync {
    async fn check(&self, key: &str, cfg: &LimitCfg, now_ms: u64) 
        -> Result<Decision, anyhow::Error>;
}
```

Any new backend (e.g., DynamoDB, Memcached) only requires impl of `RateLimitStore` + registration in engine's initialization. Existing pipeline code unchanged.

### Exemplar 2: Challenge Rendering (FR-025)

**Structure:**
```
crates/waf-engine/src/challenge/
├── mod.rs           # Public API
├── config.rs        # YAML schema (ChallengeConfig, DifficultyConfig)
├── pow.rs           # Proof-of-Work verification logic
├── renderer.rs      # HTML + JS template rendering
├── page_template.rs # Hardcoded challenge page (<5KB)
└── reload.rs        # ChallengeReloader watches challenge.yaml
```

**No trait required:** Challenge is a one-off response handler, not a Check. Wired into gateway's response path:

```rust
// In gateway proxy.rs (response phase):
if decision == WafDecision::Challenge {
    let challenge_response = engine.challenge.render(ctx)?;
    return Ok(Some(challenge_response));
}
```

**Key lesson:** Not all features need trait-based modularity. A feature module can be:
1. A **Check** (implements `Check` trait) — runs in parallel with other checks.
2. A **Config-driven handler** (e.g., response rewriter) — invoked directly, watches YAML for hot-reload.
3. A **Backend store** (implements trait like `RateLimitStore`) — swappable impl.

---

## 5. Gateway Response Pipeline

**File:** `crates/gateway/src/pipeline/response_filter_chain.rs:15-47`

```rust
pub struct ResponseFilterChain {
    filters: Vec<Arc<dyn ResponseFilter>>,
}

impl ResponseFilterChain {
    pub fn apply_all(&self, resp: &mut ResponseHeader, fctx: &FilterCtx) 
        -> pingora_core::Result<()> 
    {
        for filter in &self.filters {
            filter.apply(resp, fctx)?; // short-circuit on first error
        }
        Ok(())
    }
}
```

**Trait Definition:**
```rust
pub trait ResponseFilter: Send + Sync {
    fn apply(&self, resp: &mut ResponseHeader, fctx: &FilterCtx) 
        -> pingora_core::Result<()>;
    fn name(&self) -> &'static str;
}
```

**Current Filters (in order):**
1. `response_body_filter` — gzip decompress, catalog scan (FR-033), regex masking (AC-17), JSON redaction (FR-034)
2. `response_header_blocklist_filter` — drop forbidden headers
3. `response_server_policy_filter` — rewrite `Server` header
4. `response_location_rewriter` — rewrite `Location` redirects
5. `response_via_strip_filter` — remove `Via` hop-by-hop header

**To Add X-WAF-* Headers:**
1. Create `src/filters/response_waf_headers_filter.rs`
2. Impl `ResponseFilter` trait — mutate `resp.headers_mut()` to insert custom headers
3. Register in `filters/mod.rs` + `pipeline/response_filter_chain.rs` at startup
4. No existing filter code touched

---

## 6. waf-common Type Boundaries

**File:** `crates/waf-common/src/lib.rs:1-7`

```rust
pub mod config;          // AppConfig, HostConfig, SecurityConfig (TOML)
pub mod types;           // DetectionResult, WafAction, WafDecision, etc.
pub mod tier;            // Tier enum, TierPolicy
pub mod tier_match;      // Host+path → Tier router
pub mod crypto;          // AES-GCM sealing, SHA-2 hashing
pub mod url_validator;   // URL normalization
```

**Key Exports:**
- `DetectionResult` — Every check returns this (phase, rule_id, detail, action)
- `RequestCtx` — Passed to every check (host, client_ip, tier, headers, cookies, etc.)
- `WafDecision` — Enum: Allow | Block | Challenge | Monitor | CustomAction
- `HostConfig` — Per-virtual-host config (upstream pool, rate-limit, geo rules, etc.)
- `Tier` / `TierPolicy` — Request classification + per-tier fail-mode, DDoS threshold

**Architectural role:** waf-common is the **contract layer**. Engine checks accept only `&RequestCtx`, return only `Option<DetectionResult>`. Gateway builds RequestCtx, interprets WafDecision. This strict boundary makes new detection logic decoupled from proxy logic.

---

## 7. Existing Feature Modules & Their Wiring

| Feature | Module | Config Reload | Backend Swappable | Test Pattern |
|---------|--------|----------------|-------------------|--------------|
| **Rate Limiting** | `checks/rate_limit` | YES (ArcSwap) | YES (Store trait) | MockClock + conformance suite |
| **DDoS Detection** | `checks/ddos` | YES (ArcSwap) | YES (CounterStore trait) | Per-IP, per-tier, per-FP detectors |
| **Device Fingerprinting** | `device_fp/` | YES (ArcSwap) | YES (IdentityStore trait) | Capture hooks on TLS/H2 frame |
| **GeoIP** | `geoip.rs` | YES (file watcher) | NO (MaxMind + IP2Region) | Static fixtures, no DB query in test |
| **Challenge/PoW** | `challenge/` | YES (ArcSwap) | NO (renderer only) | Unit tests on PoW solver |
| **Rules Engine** | `rules/` | YES (hot-reload) | YES (multi-format support) | YAML, JSON, ModSecurity parsers |
| **Custom Rules** | `rules/custom_file_loader` | YES (file watcher) | YES (Rhai + WASM) | Plugin test harness |
| **CrowdSec** | `crowdsec/` | Lazy init (OnceLock) | NO (LAPI client only) | Mock HTTP responses |
| **Community** | `community/` | Lazy init (OnceLock) | NO (shared reporter) | Enrollment tests |

**Pattern:** Config-hot-reload via `Arc<ArcSwap<Config>>` + file watcher. Stateful backends swap via trait impl. Optional features use `OnceLock` — set once at startup, no reload.

---

## 8. Adoption Risk & Maturity Assessment

### Maturity: High ✓
- **Stable core:** 1.1.0 release; 7 production-ready crates.
- **Breaking change history:** Minimal — no major API rewrites post-v1.0.
- **Community adoption:** Vendored Pingora fork stable; upstream patches upstream-tracked.

### Architectural Fit for New Features
- ✓ **Trait-based checks** (new detection, rate-limit backends): Zero coupling, adds 1 file per module.
- ✓ **Config-driven handlers** (challenge, blocklists): Hot-reload built-in; no service restart.
- ✓ **Response filters** (header injection, masking): Composable chain; can insert mid-pipeline.
- ✓ **Storage integration** (new tables, migrations): `sqlx` provides typed queries; no shared state conflicts.
- ✓ **Cluster sync** (replicating new config): Existing `sync/` module already abstracts; extend `Message` enum.

### Adoption Risks
- **Trait impls require lifetimes/async:** New Check must handle `async_trait`, `Arc<dyn Trait>`. Junior Rust devs may struggle with bounds.
- **Test conformance suites:** Rate-limit + DDoS store impls must pass `conformance.rs` before production. Skipping = silent data loss risk.
- **Feature flags:** `redis-store`, `valkey` gated by optional deps. CI matrix must test all combinations.
- **Cluster replay:** New message types in `waf-cluster` require hand-rolled serialization (lz4 + HMAC). Serde alone insufficient — consider migration story.

---

## 9. Unresolved Questions

1. **Device fingerprinting identity store scaling:** Redis backend (`redis-store` feature) added in phase-08 but no benchmark vs memory store under 10k concurrent IPs. Backpressure model if Redis fails?

2. **Challenge token nonce expiry:** `challenge/config.rs` defines nonce TTL but file-watching reload does not invalidate in-flight tokens. Race condition if admin drops TTL from 10min → 1min?

3. **Rate-limit store conformance suite coverage:** `rate_limit/conformance.rs` tests token-bucket math but does not exercise concurrent writers to Redis. Test coverage vs production concurrency mismatch?

4. **Cluster sync message versioning:** New `Message` variant in `waf-cluster/src/protocol.rs` requires main node to know worker's schema. Backward compat story if a worker is behind one release?

5. **WASM plugin sandbox:** `plugins/` uses `wasmtime` with default permissions. No capability-based isolation; plugins can make HTTP calls, read env. Expected threat model (trusted plugins only)?

---

## Recommendations for Adding New Capabilities

### Pattern A: Detection Check
```
1. Create crates/waf-engine/src/checks/my_check.rs
2. Impl Check trait { fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> }
3. Register in engine.rs: engine.checkers.push(Box::new(MyCheck::new(...)))
4. Add inline tests + criterion bench if stateful
5. Export from checks/mod.rs
```
**Effort:** ~300 lines code, ~1 week (includes OWASP rule integration).

### Pattern B: Rate-Limit Backend
```
1. Create crates/waf-engine/src/checks/rate_limit/store/my_backend.rs
2. Impl RateLimitStore trait
3. Pass conformance suite: cargo test -p waf-engine rate_limit::conformance
4. Register in engine constructor
```
**Effort:** ~500 lines code, ~2 weeks (includes conformance tests + cluster sync).

### Pattern C: Response Filter (Header Injection)
```
1. Create crates/gateway/src/filters/response_my_filter.rs
2. Impl ResponseFilter trait { fn apply(&self, resp, fctx) }
3. Register in response_filter_chain.rs at startup
4. Add 95% line coverage tests
```
**Effort:** ~200 lines code, ~3 days.

### Pattern D: Config-Driven Feature (like Challenge)
```
1. Create crates/waf-engine/src/my_feature/ (config, reload, logic)
2. Define YAML schema (deny_unknown_fields)
3. Spawn file watcher in main.rs, swap Arc<ArcSwap<Config>>
4. Integrate into decision logic (engine.rs or gateway response path)
```
**Effort:** ~800 lines code, ~2 weeks (includes YAML schema + hot-reload tests).

---

## Conclusion

The mini-WAF codebase demonstrates **mature modular architecture** suitable for production feature velocity. Trait-based boundaries (`Check`, `RateLimitStore`, `ResponseFilter`) eliminate coupling; `Arc<ArcSwap<T>>` hot-reload eliminates service restarts. The **Feature Module Pattern** is proven by 7+ shipping features (rate-limit, DDoS, challenge, device-fp, CrowdSec, community, custom rules).

**Critical success factors for new features:**
- Use trait abstractions; avoid global state.
- Write conformance test suites before production backend impls.
- Enforce 95% line coverage on filters/checks.
- Serialize cluster messages with HMAC + lz4; version explicitly.

**Expected effort for typical feature:** 1–3 weeks for a complete, tested, production-ready module following these patterns.
