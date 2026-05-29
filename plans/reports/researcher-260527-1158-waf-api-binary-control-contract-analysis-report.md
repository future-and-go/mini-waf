# WAF API Layer & Binary Contract Analysis

## Executive Summary

**Finding**: WAF API is fully architected but **missing `__waf_control/*` control endpoints** (v2.3 contract §2), missing challenge endpoint (§4), and binary name mismatch (`prx-waf` vs `waf`). All other elements present.

---

## 1. Route Files & Endpoints Inventory

**Files**: All routes defined in single `server.rs` (not modularized by domain).
- **Path**: `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-api/src/server.rs` (lines 59–293)
- **Module index** (`lib.rs` lines 1–26): cache_api, cluster, crowdsec, handlers, health, logs, notifications, plugins, rules_api, stats, tunnels, websocket.

**Route Groups Found**:
- `/api/auth/*` — login, logout, refresh (lines 81–83)
- `/api/hosts/*` — CRUD operations (lines 89–93)
- `/api/{allow,block}-{ips,urls}/*` — IP/URL lists (lines 95–111)
- `/api/attack-logs` — logs (line 113)
- `/api/security-events` — events (lines 115–116)
- `/api/status` — system status (line 118)
- `/api/panel-config` — admin panel runtime config (line 120)
- `/api/reload` — rules reload (line 122)
- `/api/sqli-scan/reload` — SQL injection config reload (line 124)
- `/api/custom-rules/*` — FR-001 phase 3 (lines 126–135)
- `/api/sensitive-patterns/*` — FR-001 phase 3 (lines 137–144)
- `/api/hotlink-config` — anti-hotlink policy (lines 146–149)
- `/api/lb-backends/*` — load-balance backends (lines 151–155)
- `/api/certificates/*` — TLS certificates (lines 157–161)
- `/api/stats/*` — timeseries/geo/endpoints (lines 163–167)
- `/api/threat-intel/status` — reputation status (line 169)
- `/api/notifications/*` — PATCH 4 alerts (lines 171–177)
- `/api/plugins/*` — WASM plugins (lines 179–182)
- `/api/tunnels/*` — tunnel management (lines 184–185)
- `/api/cache/*` — **cache operations** (lines 187–198)
- `/api/bot-patterns/*` — bot signatures (lines 203–204)
- `/api/rules/*` — registry/import/reload (lines 205–208)
- `/api/rule-sources/*` — external rule sources (lines 210–213)
- `/api/cluster/*` — cluster status/nodes (lines 215–219)
- `/api/crowdsec/*` — CrowdSec integration (lines 221–233)
- `/api/v1/logs/*` — VictoriaLogs query proxy (lines 237–239)
- `/api/admin/logs/level` — dynamic log level (line 241)
- **WebSocket**: `/ws/events`, `/ws/logs`, `/ws/tunnel` (lines 254–257)
- **UI**: `/ui/`, `/ui/{*path}`, root redirects (lines 265–269)

**Control Endpoints Missing** (contract v2.3 §2):
- `/__waf_control/status` — NOT FOUND
- `/__waf_control/cache-flush` — NOT FOUND
- `/__waf_control/rules-reload` — NOT FOUND
- `/__waf_control/challenge-verify` — NOT FOUND

---

## 2. Router Construction & Middleware

**File**: `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-api/src/server.rs` (lines 59–280)

**Function**: `pub fn build_router(state: Arc<AppState>) -> Router`

**Architecture**:
- **Public routes** (lines 80–84): auth + health — NO JWT required
- **Protected routes** (lines 87–250): all `/api/*` — JWT required via `require_auth` middleware (line 242)
- **Middleware stack** (lines 243–250):
  - `require_auth` — JWT enforcement (line 242)
  - `admin_ip_check_middleware` — allowlist filtering (lines 245, 258)
  - `rate_limit_middleware` — per-IP throttling (lines 249, 259)
- **WebSocket routes** (lines 254–259): protected by admin IP + rate limit only (auth is query-param inside handlers)
- **CORS layer** (lines 62–77): empty allowlist = permissive (Any), or strict via config
- **Security headers** (line 276): applied to entire app
- **Trace layer** (line 278): Axum request tracing

**New Route Registration**: Add to `protected_routes` before layer application (after line 241, before line 242).

**JWT Auth**: `require_auth` middleware from `auth.rs`; extracts bearer token, validates via `jsonwebtoken`.

---

## 3. Binary Entry Point & Startup

**File**: `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/prx-waf/src/main.rs` (lines 1–350+)

**Binary name**: `prx-waf` (Cargo.toml line 8), NOT `waf` as per contract v2.3 §8.

**CLI Structure** (lines 25–65):
```rust
struct Cli {
    config: String,  // default: "configs/default.toml"
    command: Commands,
}

enum Commands {
    Run,           // starts proxy + API
    Migrate,       // DB migrations
    SeedAdmin,     // init admin user
    Crowdsec(...), // CrowdSec mgmt
    Rules(...),    // rule management
    Sources(...),  // rule sources
    Bot(...),      // bot patterns
    Geoip(...),    // GeoIP db
    Community(...),// threat intelligence
    Cluster(...),  // cluster mgmt
}
```

**Startup Sequence** (lines 284–349):
1. Install rustls CryptoProvider (lines 296–299) — fixes ring/aws-lc-rs panic
2. Setup tracing + VictoriaLogs layer (lines 306–316)
3. Parse CLI (line 318)
4. Load config (lines 321–324) — fallback to defaults on error
5. Match command:
   - `Run`: spawn Tokio runtime → `run_server()` (lines 339–348)
   - Others: single-threaded runtime for CLI work (lines 328–338)

**Config loading**: `load_config(&cli.config)` from `waf-common::config` — reads TOML, defaults to `configs/default.toml`.

**Default config path**: `configs/default.toml` (Cli line 29).

**API startup**: Called from `run_server()` (not shown in excerpt), invokes `start_api_server(listen_addr, state)` from `waf-api::server`.

**Current issue**: Binary is `prx-waf`, but contract v2.3 §8 expects executable at `./waf` with `./waf run` command.

---

## 4. Cache Flush/Purge Mechanisms

**File**: `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-api/src/cache_api.rs` (lines 1–350+)

**Endpoints** (registered at lines 187–198 in server.rs):
- `DELETE /api/cache` — flush entire cache (line 192 handler)
- `DELETE /api/cache/host/{host}` — flush host entries (line 205)
- `DELETE /api/cache/key?key=...` — flush specific key (line 219)
- `POST /api/cache/purge/tag` — purge all entries with tag (line 138)
- `POST /api/cache/purge/route` — purge by route_id (line 164)

**Request/Response**:
- All operations async via `state.cache.{flush, purge_host, purge_key, purge_by_tag, purge_by_route_id}()` methods
- Return JSON: `{"flushed": true}` or `{"purged": count, "duration_ms": N}`
- Warnings on cluster backend (SCAN ops are best-effort, node-local)

**Cache API contract**: Present and functional; no mapping to `__waf_control/cache-flush` as v2.3 §2 requires.

---

## 5. HostConfig `log_only_mode` Field

**File**: `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-common/src/types.rs` (line 331)

**Structure**:
```rust
pub struct HostConfig {
    // ... other fields ...
    pub log_only_mode: bool,  // line 331
    // ... rest of config ...
}
```

**Scope**: **Per-host only** — stored in database, per HostConfig entry. NOT a feature-flag, NOT a per-policy mode.

**Usage context**: 
- Loaded from hosts table (waf-storage)
- Propagated via RequestCtx at request time
- Consumed by engine decision logic (not visible in excerpt; check waf-engine)

**Missing**: No per-policy/per-rule log-only override; log_only_mode is all-or-nothing per host.

---

## 6. Request Context Generation

**File**: `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/gateway/src/ctx_builder/request_ctx_builder.rs` (lines 1–250+)

**req_id Generation** (line 174):
```rust
req_id: Uuid::new_v4().to_string(),  // UUID v4 as string
```
- **Type**: UUID v4 (random, no predictable component)
- **When**: Every request, in `build_from_parts()` function

**client_ip Extraction** (lines 77–82):
1. Direct peer address from Pingora session (lines 70–75)
2. Extract client IP via `extract_client_ip_from_session()` (lines 77–82, 194–207)
   - Honors `X-Forwarded-For` only if:
     - `trust_proxy_headers` is `true` AND
     - Peer IP is in `trusted_proxies` list (or list is empty = trust all)
   - Falls back to peer IP if no XFF or trust fails
3. Returns `IpAddr` (IPv4 or IPv6)

**Context assembly** (lines 156–192):
- Calls `build_from_parts()` with extracted parts
- Gathers headers into lowercase HashMap (line 87–92)
- Extracts path, query, content-length
- Determines TLS from session digest (line 68)
- Classifies tier if registry attached (line 117)

---

## 7. Default Configuration

**File**: `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/configs/default.toml` (lines 1–100+)

**Sections**:
- `[proxy]` — HTTP/TLS listeners
  - `listen_addr = "0.0.0.0:80"`
  - `listen_addr_tls = "0.0.0.0:443"`
  - TLS cert/key paths
- `[api]` — Admin API listener
  - `listen_addr = "0.0.0.0:9527"`
- `[storage]` — PostgreSQL config
  - Database URL, connection pool
- `[cache]` — Response cache
  - `backend = "memory"` (default), supports "embedded", "standalone", "cluster"
  - TTL config, rules path
  - `[cache.valkey]` — Valkey/Redis connection options
- `[http3]` — QUIC listener (disabled by default)
- `[security]` — Admin hardening
  - `admin_ip_allowlist`, `max_request_body_bytes`, `api_rate_limit_rps`, `cors_origins`
- `[panel]` — Admin panel runtime config
  - `config_path = "waf-panel.toml"`

**API listen**: Port 9527 (admin API), separate from proxy (80/443).

---

## 8. Challenge Endpoint & Verification

**Status**: Challenge **action type defined** but **no verification endpoint implemented**.

**Challenge in codebase**:
- `WafAction::Challenge` enum variant (waf-common types.rs)
- Test suite exists: `/crates/waf-engine/tests/challenge_flow.rs` (referenced in grep)
- **Issuer/Verifier classes**: `ChallengeIssuer`, `ChallengeVerifier`, `NonceStore` (from test imports)
- **No route**: `/__waf_control/challenge-verify` or `/api/challenge/verify` registered

**Missing contract implementation** (v2.3 §4):
- No handler for POST /challenge/verify (form or JSON)
- No nonce validation + cookie setting
- No integration with `require_auth` or public routes

---

## Gap Summary (Contract v2.3 vs. Current Implementation)

| Requirement | Spec | Current | Gap |
|---|---|---|---|
| Binary name | `./waf` | `prx-waf` | NAME MISMATCH |
| Binary run command | `./waf run` | `prx-waf run` | NAME MISMATCH |
| Control namespace | `/__waf_control/*` | `/api/*` | MISSING NAMESPACE |
| Status endpoint | `GET /__waf_control/status` | `/api/status` | PATH MISMATCH |
| Cache flush endpoint | `GET /__waf_control/cache-flush` | `DELETE /api/cache` | PATH + METHOD MISMATCH |
| Rules reload endpoint | `POST /__waf_control/rules-reload` | `POST /api/reload` | PATH MISMATCH |
| Challenge verify endpoint | `POST /__waf_control/challenge-verify` | NOT IMPLEMENTED | MISSING |
| Config file path | `./waf-config.toml` | `configs/default.toml` | PATH MISMATCH |
| Cache API coverage | Per spec | `DELETE /api/cache/*`, `POST /api/cache/purge/*` | PRESENT (non-compliant path) |
| req_id format | UUID v4 | UUID v4 string | COMPLIANT |
| client_ip extraction | XFF + trusted proxy | XFF + trusted proxy list | COMPLIANT |
| log_only_mode scope | Per-host | Per-host | COMPLIANT |

---

## Unresolved Questions

1. **Challenge flow implementation status**: Is `ChallengeIssuer/Verifier` used in production gateway code, or is it test-only?
2. **Binary renaming constraints**: Is renaming `prx-waf` → `waf` acceptable, or does it break existing deployment scripts?
3. **Control endpoint namespace adoption**: Should v2.3 contract use `/api/waf-control/*` instead of `/__waf_control/*` for consistency with existing API?
4. **Config path override**: Should binary support `-c ./waf-config.toml` via CLI, or is `configs/default.toml` non-negotiable?
5. **Challenge nonce store**: Is PostgreSQL-backed nonce storage intended, or in-memory with TTL?

---

## Next Steps (Planning)

1. **Rename binary**: Update Cargo.toml and all references (`prx-waf` → `waf`)
2. **Add control endpoints**: Wrap existing `/api/*` handlers in `/__waf_control/*` routes (proxy pattern or direct handlers)
3. **Implement challenge endpoint**: Wire `ChallengeIssuer/Verifier` into public route, add nonce store middleware
4. **Update config path**: Support CLI override and document new path discovery
5. **API conformance tests**: Verify all 4 endpoints (v2.3 §2) + challenge flow respond per spec
