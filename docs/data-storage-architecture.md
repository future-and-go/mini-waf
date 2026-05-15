# Data Storage & Cluster Architecture

See also: [System Architecture](./system-architecture.md) for request lifecycle and component interactions.

---

## Data Flow (In-Memory vs Storage)

### Configuration (Startup → Runtime)

```
config.toml (disk)
    │
    ▼
AppConfig struct (parsed by toml crate)
    │
    ▼
Arc<AppConfig> (shared, immutable)
    │
    ├─► Pingora (proxy config)
    ├─► WafEngine (rule config, check params)
    ├─► WafAPI (API config, CORS, auth)
    └─► WafCluster (cluster config, election params)
```

**Note**: No runtime config changes. Changes require restart.

### Rules (Disk + Database → In-Memory)

```
Disk (rules/*.yaml)  ──┐
                       │
Database (custom_rules) ──► RuleRegistry (Arc<RwLock>)
                       │        │
                       │        ├─► On every request: check()
                       │        │
                       │        └─► Hot-reload: reload_rules()
                       │
File watcher (notify) ─┘
```

**Cache**: Rules versioned (u64). Workers sync incremental diffs.

### Admin Control Plane: Panel Config API

**Panel-Config** (`waf-panel.toml`) holds operational settings via `GET/PUT /api/panel-config`. Validates risk thresholds, CIDR/IP syntax, honeypot paths. Atomic write-through to file. Frontend: settings page with i18n.

### Custom File-Based Rules (FR-003)

File watcher on `rules/custom/*.yaml` auto-loads YAML docs marked `kind: custom_rule_v1`. Per-file error isolation, 500ms debounce, forward-compat checks. Atomically loaded via RuleRegistry.

**FR-025 Risk Scoring:** Rules support `risk_delta: i16` (score contribution) and `risk_action: String` (override action). Deltas clamped at 100; `X-WAF-Rule-Id` header set to dominant contributor. See `code-standards.md` for delta convention.

### Logs (Per-Request → Batch → Database)

```
WafEngine.check() → decision

If Block:
    event = SecurityEvent {
        timestamp,
        client_ip,
        rule_id,
        action,
        path,
        ...
    }
    
    db.create_security_event(event).await?
        │
        ▼
    PostgreSQL: security_events table
        │
        ▼
    (Async) db.broadcast(event)  ──► WebSocket subscribers (/ws/events)
```

### Statistics (In-Memory Counter → Database)

```
RequestStats (parking_lot::Mutex) ──┐
    total_requests: u64              │
    blocked_requests: u64            │
    top_rules: DashMap               │
    top_ips: DashMap                 │
    top_countries: DashMap           │
                                     │
                        ┌────────────┘
                        │
                        ▼ (every 30s via tokio::time::interval)
                        
                    db.update_stats()
                        │
                        ▼
                    PostgreSQL: request_stats table
```

---

## Storage Layer (PostgreSQL)

### Schema Overview

**Configuration Tables**
- `hosts` — Virtual host config (upstream, ports, LB backends, SSL)
- `allow_ips`, `block_ips` — IP CIDR lists
- `allow_urls`, `block_urls` — URL patterns
- `certificates` — TLS certificates (Let's Encrypt + custom)
- `custom_rules` — User-created rules (Rhai/JSON)
- `sensitive_patterns` — PII/credential keywords
- `load_balance_backends` — Backend servers
- `hotlink_config` — Anti-hotlink rules per host

**Security Tables**
- `security_events` — Rule match events (10K+ rows/day in production)
- `attack_logs` — Full attack payloads + geo (100K+ rows/day)
- `request_stats` — Aggregated metrics (RPS, top rules, top IPs, top countries)

**Admin Tables**
- `admin_users` — Username, password hash (Argon2), TOTP secret (encrypted)
- `refresh_tokens` — JWT refresh tokens + expiry
- `audit_log` — Admin action history (who did what, when)

**Cluster Tables**
- `cluster_nodes` — Peer metadata (role, last_heartbeat, rules_version)
- `cluster_sync_queue` — Pending updates to workers
- `cluster_ca_key` — Encrypted CA private key (AES-GCM)

**Integration Tables**
- `plugins` — WASM plugin binaries (code, checksum, enabled)
- `tunnels` — Reverse tunnel configs (client_id, key, allowed_paths)
- `crowdsec_cache` — Bouncer decision cache (IP, action, ttl)
- `notifications` — Alert channels (email, webhook, telegram)

### Indexes for Performance

```sql
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX idx_security_events_rule_id ON security_events(rule_id);
CREATE INDEX idx_attack_logs_client_ip ON attack_logs(client_ip);
CREATE INDEX idx_request_stats_timestamp ON request_stats(timestamp DESC);
```

---

## Caching Strategy

### Response Cache (moka LRU) + Per-Route TTL (FR-009 Phase 3) + Tag-Based Purge (FR-009 Phase 4)

**What's cached?**
- Static content (CSS, JS, images)
- API responses (if Cache-Control header allows)
- Size limit: 256 MB (configurable)
- TTL: Determined by cache resolver gate pipeline (see below)

**Cache resolver gate pipeline (Phase 3 — new):**

```
Request → TierGate (tier default TTL)
        → MethodGate (method filter: GET/HEAD/OPTIONS only)
        → AuthGate (cookies/Authorization header → bypass)
        → RouteRuleGate (per-route YAML rules — ttl_seconds, tags)
        → UpstreamCcGate (upstream Cache-Control header)
        → TierDefaultGate (fallback: tier default TTL)
        
Verdict: { ttl_seconds, reason }
Reasons: Tier, Method, Authenticated, ExplicitDeny (ttl=0), UpstreamCc, TierDefault
```

**Cache bypass conditions:**
- Authenticated requests (AuthGate) — cookie or Authorization header present
- Explicit deny (RouteRuleGate) — `ttl_seconds: 0` in `rules/cache.yaml`
- Set-Cookie in response — not cached
- Cache-Control: no-cache, no-store — UpstreamCcGate respects
- Non-cacheable methods (POST, PUT, DELETE, etc.) — MethodGate filters
- Cookies in request → different cache key (unless explicitly allowed per RouteRuleGate)

**Config:**
```toml
[cache]
enabled = true
max_size_mb = 256
default_ttl_secs = 60
rules_path = "rules/cache.yaml"  # Hot-reloaded (500ms debounce)
```

**YAML schema** (`rules/cache.yaml`):
```yaml
version: 1
defaults:
  ttl_seconds: 60
rules:
  - id: "api-endpoints"
    match:
      path_pattern: "^/api/.*"
    ttl_seconds: 10
    tags: ["api", "fast-changing"]
  - id: "static-assets"
    match:
      path_pattern: "\\.(css|js|png|jpg)$"
    ttl_seconds: 3600
    tags: ["static"]
  - id: "no-cache"
    match:
      path_pattern: "^/admin"
    ttl_seconds: 0  # Explicit deny
    tags: ["admin", "sensitive"]
```

**Tag index + purge:** Entries tagged by rule ID + YAML tags. In-memory `DashMap<tag, Set<keys>>` auto-cleaned. Purge by tag via `POST /api/cache/purge/tag` (admin-only, JWT + allowlist). Stats: `purges_tag`, `purges_route`, `tag_index_size`.

**Stats:** `bypassed_authenticated`, `bypassed_explicit_deny`, `purges_tag`, `purges_route`, `tag_index_size`.

**Key:** `host + path + query_string + (cookies if allowed)`

### Rule Cache (In-Memory)

**RuleRegistry** (Arc<RwLock>)
- All rules loaded at startup (from disk + database)
- No TTL; rules persist until explicitly updated
- Hot-reload: atomic swap of entire registry
- Workers sync from main: incremental updates or full snapshot

### Statistics Cache (In-Memory)

**RequestStats** (parking_lot::Mutex)
- Counters incremented on every request (zero-copy)
- Flushed to PostgreSQL every 30s
- DashMap for top-N tracking (top 100 IPs, top 100 rules, etc.)

### Bouncer Cache (PostgreSQL + In-Memory)

**CrowdSec decisions**
- Query LAPI on each active decision
- Cache in PostgreSQL (crowdsec_cache) with TTL
- In-memory DashMap for fast lookups
- Fallback action if LAPI unreachable (configurable)

---

## Cluster Architecture

### Single-Node (Standalone)

```
┌─────────────────────────┐
│   PRX-WAF Process       │
├─────────────────────────┤
│ Pingora (proxy)         │
│ WafEngine (checks)      │
│ WafAPI (admin UI)       │
│ PostgreSQL Client       │
└─────────────────────────┘
         │
         ▼
   PostgreSQL 16+
```

### 3-Node Cluster (High Availability)

```
                  QUIC mTLS Mesh (port 16851)
                    ┌──────────────────┐
                    │                  │
        ┌───────────▼──────────┐       │
        │    Node A (Main)     │       │
        ├──────────────────────┤       │
        │ Pingora proxy        │───────┼─────────┐
        │ WafEngine            │       │         │
        │ WafAPI (read-write)  │       │         │
        │ PostgreSQL client    │       │         │
        │ Role: control plane  │       │         │
        └──────────┬───────────┘       │         │
                   │                   │         │
                   ▼                   │         │
            PostgreSQL 16+             │         │
           (primary)                   │         │
                   ▲                   │         │
                   │                   │         │
           ┌───────┴───────┐           │         │
           │               │           │         │
   ┌───────▼──────────┐ ┌──▼──────────▼──────┐  │
   │  Node B (Worker) │ │  Node C (Worker)   │  │
   ├──────────────────┤ ├────────────────────┤  │
   │ Pingora proxy    │ │ Pingora proxy      │  │
   │ WafEngine        │ │ WafEngine          │  │
   │ WafAPI (fwd)     │ │ WafAPI (fwd)       │  │
   │ RuleRegistry     │ │ RuleRegistry       │  │
   │ Role: data plane │ │ Role: data plane   │  │
   │ (no DB)          │ │ (no DB)            │  │
   └────────┬─────────┘ └──────────┬─────────┘  │
            │                      │            │
            │ Write requests       │            │
            │ forwarded to main    │            │
            └──────────┬───────────┘            │
                       │                        │
                       ▼                        │
         ┌─ Main's API handler ◄───────────────┘
         │ (via QUIC ApiForward stream)
         │
         ▼
    Persists to PostgreSQL
    Broadcasts to other nodes
```

**Data Flow in Cluster:**

1. **Worker receives request** → checks rules (in-memory RuleRegistry)
2. **Admin edits rule on main** → main writes to PostgreSQL
3. **Rule sync triggers** → main sends RuleSyncResponse to all workers
4. **Worker receives rule update** → updates in-memory RuleRegistry (version++)
5. **Worker processes request** → uses updated rule (no downtime)

### Leader Election (Raft-Lite)

```
Node A (Main)          Node B (Worker)        Node C (Worker)
    │                      │                       │
    │──────── heartbeat ───────────►               │
    │                      │                       │
    │                      ◄──── heartbeat ack ────┤
    │
    ├─ If no heartbeat from A within 150-300ms:
    │
    └─► Become Candidate
        ├─ Increment term (e.g., 5 → 6)
        ├─ Vote for self
        ├─ Send ElectionVote to all peers
        │
        B & C receive ElectionVote(term=6, candidate=B)
        ├─ Grant vote (if term > current term)
        ├─ Send ElectionResult back
        │
        B receives 2 votes (self + C)
        ├─ Majority reached (2/3)
        ├─ Become Main
        ├─ Broadcast ElectionResult(term=6, elected=B)
        │
        C receives ElectionResult
        └─ Demote to Worker, accept B as Main
```

**Election Timeline:**
- Detection: <150ms (if main dies suddenly)
- Voting round: <100ms
- New main operational: <500ms total

---

## Admin UI Architecture

**Stack:** Vue 3, Vite, Tailwind, Pinia (state), vue-router (hash mode), axios, vue-i18n (11 locales), TypeScript.

### View Structure (21 pages)

| Path | Purpose |
|------|---------|
| `/login` | JWT + TOTP authentication |
| `/dashboard` | Overview: RPS, top attacks, blocked %, geo heatmap |
| `/hosts` | Vhost CRUD (backend config, SSL, LB) |
| `/ip-rules` | IP allow/block lists (CIDR CRUD) |
| `/url-rules` | URL allow/block patterns (regex CRUD) |
| `/rules` | Built-in rules (enable/disable, info) |
| `/custom-rules` | User-defined rules (Rhai/JSON editor) |
| `/certificates` | TLS cert management (Let's Encrypt, manual) |
| `/security-events` | Real-time attack stream (WebSocket) |
| `/attack-logs` | Historical attacks (export as CSV/JSON) |
| `/cc-protection` | Rate limiting config |
| `/bot-detection` | Bot rule management |
| `/sensitive-patterns` | PII pattern management |
| `/notifications` | Alert channels (email, webhook, telegram) |
| `/crowdsec-settings` | CrowdSec bouncer + AppSec config |
| `/crowdsec-decisions` | Active CrowdSec bans/blocks |
| `/crowdsec-stats` | CrowdSec metrics |
| `/cluster-overview` | Topology, node health, rules version |
| `/cluster-nodes/:id` | Node detail (health, stats, sync status) |
| `/cluster-tokens` | Join token management |
| `/cluster-sync` | Per-node sync status + drift alerts |

### Data Flow

```
View Component
    │
    ▼
store.getters (Pinia)
    │
    ▼
api/index.ts (axios client)
    │
    ├─ JWT token from store
    ├─ 15s timeout
    ├─ Auto-logout on 401
    │
    ▼
Axum handler: /api/...
    │
    ├─ JWT verify middleware
    ├─ IP allowlist check
    ├─ Rate limit check
    │
    ▼
Business logic
    │
    ├─ Query PostgreSQL
    ├─ Update RuleRegistry
    ├─ Broadcast to cluster peers
    │
    ▼
JSON response
    │
    ▼
View component (re-render)
```

### WebSocket Subscriptions

**`/ws/events`** — Real-time security event stream
```json
{
  "timestamp": "2026-04-17T10:30:45Z",
  "client_ip": "203.0.113.45",
  "method": "POST",
  "path": "/api/login",
  "rule_id": "CRS-941100",
  "action": "block",
  "severity": "high",
  "geo_country": "RU",
  "node_id": "node-a"
}
```

**`/ws/logs`** — Real-time access log stream
```json
{
  "timestamp": "2026-04-17T10:30:45Z",
  "client_ip": "203.0.113.45",
  "method": "GET",
  "path": "/index.html",
  "status": 200,
  "response_time_ms": 12,
  "bytes_sent": 45230,
  "host": "example.com"
}
```

---

## Security Boundaries

### 1. Admin API (127.0.0.1:9527)

**Boundary**: Only trusted administrators
- IP allowlist (configured via config.toml)
- JWT bearer token (signed with secret)
- TOTP 2FA (optional)
- Per-endpoint permission checks (admin only)

### 2. WebSocket Streams

**Boundary**: Authenticated users only
- Requires valid JWT token
- IP allowlist applied
- Stream-specific read permissions

### 3. Cluster QUIC (0.0.0.0:16851)

**Boundary**: Cluster nodes only (mTLS)
- Server: verifies client cert against cluster CA
- Client: verifies server cert against cluster CA
- Mutual authentication (both sides prove identity)
- Ed25519 signatures for control messages

### 4. Rule Evaluation (Sandboxed)

**Boundary**: Rhai scripts cannot escape
- No file I/O (Rhai limited stdlib)
- No network access
- No external function calls (unless explicitly exposed)
- Memory limit: stack-based (no heap allocation in Rhai)

### 5. WASM Plugins (Sandboxed)

**Boundary**: wasmtime isolation
- Linear memory isolated from host
- No syscalls (WASI disabled)
- Only exposed functions callable
- CPU instruction limit (timeout)

### 6. Database Secrets (Encrypted)

**Boundary**: AES-256-GCM at-rest encryption
- Cluster CA private key
- Admin user TOTP secrets
- CrowdSec API keys
- Webhook authentication tokens
- Encryption key derived from config passphrase (KDF)

---

## Performance Optimization

### Request Path (0.5ms baseline)

1. **TCP accept** (Pingora) — <0.1ms
2. **TLS handshake** (if new conn) — amortized via pooling
3. **HTTP parse** (Pingora) — <0.05ms
4. **IP allow/block checks** (phase 1-2) — <0.05ms (hash lookup)
5. **URL pattern matching** (phase 3-4) — <0.1ms (compiled regex)
6. **Rate limiter** (phase 5) — <0.05ms (atomic counter)
7. **Payload analysis** (phases 8-11) — <0.15ms (compiled patterns)
8. **Custom rules** (phase 12) — <0.05ms (Rhai JIT)
9. **Backend routing** — <0.1ms (vhost hash lookup)

**Total**: ~0.5ms per request (99th percentile)

### Optimization Techniques

Compiled regexes (startup once), Arc<RwLock> reads (minimal contention), arc-swap for lock-free cluster reads, DashMap sharded counters, moka LRU response cache, multi-threaded Tokio, PostgreSQL connection pooling, batch event writes (cluster), DNS caching.

---

## Deployment Topologies

### Topology 1: Single-Node (Development)

```
┌──────────────┐
│  PRX-WAF     │  docker: 16880/16843 (proxy)
│  PostgreSQL  │         16827 (API/UI)
└──────────────┘
```

**docker-compose.yml** — One container, one database.

### Topology 2: 3-Node Cluster (Production HA)

```
┌─────────────────────────────────────────┐
│      Docker Compose Cluster             │
├─────────────────────────────────────────┤
│ postgres:16-alpine (primary)            │
│ node-a (main)      - port 16880/16843  │
│ node-b (worker)    - port 16828/16829  │
│ node-c (worker)    - port 16828/16829  │
└─────────────────────────────────────────┘
```

**docker-compose.cluster.yml** — One database, three proxy nodes.

### Topology 3: Systemd Multi-Node (Enterprise)

```
Server A (main)              Server B (worker)         Server C (worker)
┌─────────────────┐       ┌─────────────────┐      ┌─────────────────┐
│ prx-waf daemon  │       │ prx-waf daemon  │      │ prx-waf daemon  │
│ config.toml     │       │ config.toml     │      │ config.toml     │
│ role=main       │       │ role=worker     │      │ role=worker     │
└────────┬────────┘       └────────┬────────┘      └────────┬────────┘
         │                        │                         │
         └────────────────┬───────┴─────────────────────────┘
                          │
                    QUIC mTLS (port 16851)
                          │
                          ▼
                  PostgreSQL (primary, 5432)
              (backed up to standby servers)
```

---

## Testing & Validation Pipeline

### E2E Test Suite (1,812 LOC)

**Orchestrator**: `tests/e2e-cluster.sh` (main runner)

**5 Modular Test Runners**
1. **rules-engine.sh** — YAML/ModSec/JSON rule parsing, schema validation
2. **gateway.sh** — HTTP/1.1, HTTP/2, HTTP/3 (QUIC), load balancing, SSL termination
3. **api.sh** — REST endpoints, JWT/TOTP auth, rate limiting, CRUD operations
4. **cluster.sh** — QUIC mTLS, leader election, rule sync, failover scenarios, peer fencing
5. **report-renderer.sh** — Artifact generation (JUnit, JSON, Markdown, HTML)

**Coverage**
- 63+ acceptance tests for SQLi (all pattern types, encoding bypasses)
- Cluster failover tests (main node death, partition recovery)
- Rule sync tests (incremental + full snapshot)
- Performance benchmarks (p99 latency, throughput)

**Artifacts**: JUnit XML (CI integration), JSON (programmatic), Markdown (human-readable), HTML (visual dashboard)

### Rust Integration Tests

- Unit tests in-line (per module)
- Integration fixtures in `tests/common/`
- Chaos tests: network simulation, node kill, partition tolerance

---

## Monitoring & Observability

### Metrics Exported

- `prx_waf_requests_total` (counter) — Total requests
- `prx_waf_requests_blocked` (counter) — Blocked requests
- `prx_waf_request_duration_ms` (histogram) — Request latency
- `prx_waf_rule_matches_total` (counter, per rule_id) — Rule hits
- `prx_waf_backend_latency_ms` (histogram) — Upstream latency
- `prx_waf_cache_hit_ratio` (gauge) — Cache effectiveness
- `prx_waf_cluster_election_time_ms` (histogram) — Election duration

### Logs (Structured Tracing)

All events logged via `tracing` crate:
- Startup/shutdown
- Rule reload
- Election events
- Cluster peer join/leave
- Database errors
- Authentication failures
- High request latency

### VictoriaLogs Archive (opt-in)

When `[victoria_logs] enabled = true`, the WAF runs a managed VictoriaLogs
sidecar (loopback only, validated at config load) and ships two independent
streams into it:

| Stream | Source | Schema |
|--------|--------|--------|
| `waf_tracing` | `tracing_subscriber::Layer` (`waf-engine::logging::VictoriaLogsLayer`) | `_time`, `_msg`, `level`, `target`, span fields |
| `waf_audit` | `WafEngine::send_audit_event` (one record per non-Allow decision) | `event_type`, `rule_name`, `client_ip`, `host`, `method`, `path`, `tier`, `detail`, `req_id` |

Both streams share a fail-open batch buffer (`waf-engine::logging::BatchSender`):
saturated channels drop entries with a 30 s rate-limited warn, so the WAF
request path never blocks on observability.

The admin panel queries this archive through admin-only proxy endpoints —
`GET /api/v1/logs/{query,stats,streams}` — which validate JWT + role,
reject `LogsQL` write/delete pipes, and cap responses at 50 MiB. No SSRF
surface: the proxy targets only the loopback `base_url()`.

---

## Disaster Recovery

### Backup Strategy

1. **PostgreSQL**: Daily backup (pg_dump) to S3/NFS
2. **Rules**: Git version control (rules/*.yaml)
3. **Certificates**: Periodic export of Let's Encrypt renewal keys
4. **Cluster CA Key**: Encrypted backup of cluster-ca.key

### Recovery Procedures

**Database Loss**: Restore from backup, replay rules from Git
**Main Node Failure**: Promote worker to main (automatic via election)
**Cluster Split**: Quorum-based split-brain prevention (no decision if <N/2+1 nodes)

See [Deployment Guide](./deployment-guide.md) for operational runbooks.

---

## Response Body Content Scanning (FR-033)

The gateway runs a built-in catalog scanner over upstream response bodies to
detect and redact common leakage. It complements the existing AC-17 operator
regex masker (`response_body_mask_filter.rs`) and the planned PR-18 JSON field
redactor (FR-034); the three layers run in `response_body_filter` in this
order:

```
FR-033 catalog scan + gzip decompress
   │
   ▼
FR-034 JSON field redact (placeholder until PR #18 merges)
   │
   ▼
AC-17 operator regex mask
```

### Categories

- Stack traces (Java, Python, Rust, Node.js, .NET, Go, PHP) — Aho-Corasick over
  distinctive multi-byte literals plus line-anchored multi-line regexes per
  language.
- Verbose error messages — Spring, ASP.NET, Postgres, Oracle SQL syntax markers.
- API keys / secrets — AWS, GitHub PAT, Slack, Stripe, JWT, Google API,
  OpenAI, Anthropic, Twilio, generic PEM private-key block markers.
- Internal IPs — strict-parsed RFC-1918 / loopback / link-local IPv4 (rejects
  octal / leading-zero aliasing) and IPv6 ULA.

### ReDoS hardening

- Multi-byte literals routed through `aho_corasick::AhoCorasick` (linear time,
  no backtracking) — Cloudflare 2019 outage class.
- Each `regex::bytes::Regex` compiled via `RegexBuilder` with `size_limit(1
  MiB)` and `dfa_size_limit(2 MiB)`. Every quantifier has explicit
  `{min,max}` bounds; patterns whose `regex_syntax::hir::Hir::properties()
  .maximum_len()` exceeds 1024 are rejected at build time.
- Internal-IP detection uses a byte-scan candidate finder + strict
  `std::net::Ipv4Addr::from_str` — no regex CIDR alternation.

### Decompression

Gzip-only in v1 via `flate2::read::MultiGzDecoder`. Defenses:

- 4 MiB output cap (`MAX_DECOMPRESS_BYTES`) gated pre-allocation by
  `Read::take`.
- 8 MiB input cap (`MAX_INPUT_BYTES`).
- 100:1 output / input ratio guard (`MAX_DECOMPRESS_RATIO`) once at least
  1 KiB of input has been observed.

Fail-open: any decoder error or cap breach forwards the original encoded
bytes untouched + a `tracing::warn!`. The WAF does not 502 the host on decode
failure (research §5).

deflate, brotli, zstd, and lz4 are deliberately deferred to FR-033b — brotli
has historical panic-isolation risk on adversarial input, and gzip is by far
the dominant real-traffic encoding.

### Action

Single mode: replace each match span with the hardcoded module constant
`MASK_TOKEN = b"[redacted]"`. Whole-body block remains FR-005's
responsibility (request-time block at the WAF engine layer).

### Header mutations

When the scanner enables for a response, `Content-Length` and
`Transfer-Encoding` are dropped unconditionally; Pingora re-emits chunked.
`Content-Encoding` is dropped only when gzip decompression succeeded — i.e.
the downstream sees identity bytes. A Content-Type allowlist at
`response_filter` filters to only `text/*`, `application/json`,
`application/xml`, `application/problem+json`, `application/javascript`, and
skips `application/grpc*`, `text/event-stream`, and `application/octet-stream`
so gRPC trailers and streaming endpoints are not corrupted.

### Caching

`WafProxy::body_scan_cache` is a content-hash `DashMap<(host, xxhash64(
body_scan_*)), Arc<CompiledScanner>>`. The hash includes the host name and
all FR-033 host-config fields, so a config reload that produces an `Arc` at
the same address as a different host's prior config cannot bleed compiled
state across hosts. AC-17 (`body_mask_cache`) and FR-034 (`body_redact_cache`)
currently use `Arc::as_ptr` keys with the same address-reuse hazard; backport
is tracked in a separate ticket.

### Configuration

Per-host `HostConfig` exposes only two opt-in fields (defaults preserve
zero-cost passthrough):

- `body_scan_enabled: bool` (default `false`)
- `body_scan_max_body_bytes: u64` (default `1 << 20`)

Mask token, decompression caps, ratio limits, and tail-buffer size are
hardcoded module constants; operators have AC-17 (`internal_patterns`) for
catalog extras.

---

## Outbound Protection

### FR-034 — Sensitive Field Redaction (Response JSON Bodies)

Per-host JSON field redactor that masks values whose KEYS are in a configurable
catalog. Field-name catalogs (PCI / banking / identity / secrets / PII / PHI)
are hard-coded in `gateway::filters::response_json_field_redactor`; per-host
activation via `HostConfig::redact_*` fields. Operators extend the catalog
with `redact_extra_fields[]`.

Hook: Pingora `response_body_filter`, dispatched directly from
`WafProxy::response_body_filter`. Buffers chunks until `end_of_stream` or
`redact_max_bytes` (default 256 KiB), then parses with `serde_json`, walks
the value tree, replaces matched values with `redact_mask_token` (default
`***REDACTED***`), re-serialises, and emits the full body.

**Composition with AC-17**: FR-034 runs first; AC-17 internal-ref masker
then runs over the redacted output. While FR-034 is buffering, `*body` is
set to `None` so AC-17 sees nothing.

**Skip conditions**: non-identity `Content-Encoding`, non-JSON
`Content-Type`, no-op redactor (no families on, no extras). Failure mode is
fail-open with `tracing::warn!`. Defaults all OFF — zero behaviour change
for hosts that don't opt in.

References: PCI-DSS Req 3.4, HIPAA §164.514, OWASP API3:2023, CWE-200.
Plan: `plans/260428-1357-GH-034-sensitive-field-redaction/`.

### AC-17 — Internal-Reference Body Masking

Sibling filter to FR-034. Byte-level regex value masking driven by
`HostConfig::{internal_patterns, mask_token, body_mask_max_bytes}`. Streams
chunk-by-chunk; suitable for masking internal hostnames, IPs, build
identifiers in response bodies.
