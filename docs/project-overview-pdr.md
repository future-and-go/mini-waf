# PRX-WAF Product Overview & PDR (v0.2.0)

## Product Vision

PRX-WAF is a production-grade, horizontally scalable Web Application Firewall (WAF) built on Pingora. It enables organizations to protect web applications with:
- Multi-phase attack detection (16 phases)
- Industry-standard rule sets (OWASP CRS, CVE patches)
- Extensibility via Rhai scripts and WASM plugins
- Enterprise clustering with automatic failover
- Transparent integration with existing infrastructure (reverse proxy at layer 7)

---

## Problem Statement

Organizations deploying web applications face evolving threats:
1. **Volume**: Modern attacks target multiple vectors simultaneously (SQLi, XSS, RCE, SSRF, protocol violations)
2. **Complexity**: Manual rule authoring is error-prone; rule maintenance is ongoing
3. **Availability**: Single WAF instance is a SPOF; cluster solutions are expensive or vendor-locked
4. **Observability**: Attackers evolve; blind WAFs miss new patterns
5. **Latency**: Traditional WAFs add 50-200ms to request path; organizations need <1ms added latency

**PRX-WAF Solution:**
- Efficient rule evaluation (Rust + compiled regexes, not interpreted)
- Rule hot-reload without restart
- Clustering with QUIC (0-RTT, multiplexed)
- Deep observability (WebSocket real-time logs, CrowdSec integration)
- Minimal latency overhead (<5ms per request)

---

## Target Users

1. **DevOps/Platform Teams**: Deploy WAF at infrastructure layer, manage via Kubernetes ConfigMaps
2. **Application Teams**: Protect APIs with custom rules (Rhai scripting)
3. **Security Teams**: Centralized policy (rule sources), audit logging, threat intelligence (CrowdSec)
4. **Managed Service Providers**: Multi-tenant clustering, rule templates per customer
5. **Consultants**: Customizable WASM plugins for client-specific logic

---

## Core Requirements

### Functional

**F1: Reverse Proxy**
- HTTP/1.1, HTTP/2, HTTP/3 (QUIC)
- Weighted round-robin load balancing
- Backend health checks
- Connection pooling

**F2: Multi-Phase Detection Pipeline**
- IP allow/block (CIDR lists)
- URL allow/block (regex/string lists)
- Rate limiting (CC/DDoS per IP)
- Scanner detection (fingerprints)
- Bot detection (User-Agent, headless browser signatures)
- SQL injection (libinjection + regex-based)
- XSS (libinjection + regex-based)
- RCE / command injection
- Directory traversal (path normalization)
- Custom rules (Rhai scripts, JSON DSL)
- OWASP CRS (24 rules)
- Sensitive data leakage (PII, credentials)
- Anti-hotlink (Referer validation)
- CrowdSec bouncer + AppSec integration

**F1.1: Tiered Protection (FR-002)** ✓
- Per-request classification to Critical / High / Medium / CatchAll tiers
- Priority-sorted classifier (path-exact/prefix/regex, host-suffix, method, headers)
- Per-tier policy bus: fail_mode, ddos_threshold_rps, cache_policy, risk_thresholds
- Hot-reload via `ArcSwap` (lock-free, zero-copy on swap)
- Downstream consumers: FR-005 (DDoS), FR-006 (challenge), FR-009 (cache), FR-027 (TBD)

**F1.2: Access Lists (FR-008)** ✓
- Phase-0 gate: per-tier IP whitelist + blacklist (Patricia trie, dual-stack v4/v6) + per-tier Host whitelist
- Decision order: Host gate → IP blacklist → IP whitelist (deny wins)
- Per-tier dispatch on `full_bypass` vs `blacklist_only` strategy
- Hot-reload from `rules/access-lists.yaml`; soft-warn ≥50k, hard-reject ≥500k entries
- Audit fields: `access_decision`, `access_reason`, `access_match` stamped on every request

**F3: Rule Management**
- YAML, ModSecurity, JSON rule formats
- **File-based custom rules (FR-003)**: `rules/custom/*.yaml` auto-loaded with `kind: custom_rule_v1`, per-file error isolation, 500ms debounce
- Hot-reload without downtime
- Version tracking and incremental sync (cluster)
- Remote source loading (auto-update)
- Built-in rules (compiled into binary)

**F4: Clustering**
- QUIC mTLS mesh (port 16851)
- Automatic leader election (Raft-lite)
- Rule sync (incremental or full snapshot)
- Attack log aggregation
- Worker write forwarding to main
- Phi-accrual failure detection

**F5: Admin UI**
- JWT + TOTP authentication
- Dashboard (traffic, top attacks, blocked requests)
- Host management (vhost proxy config)
- Rule management (enable/disable, CRUD)
- Certificate management (Let's Encrypt, custom)
- Custom rules (Rhai/JSON editor)
- **Settings page**: Panel-Config API for operational policy (response filtering, trusted bypass, rate limits, auto-block)
- Security event stream (real-time WebSocket)
- Cluster topology view
- Audit logging (all admin actions)
- i18n (11 locales)

**F6: Storage**
- PostgreSQL 16+ persistence
- All config (hosts, rules, certs, settings)
- Attack logs and statistics
- Admin audit trail
- Notification channels
- WASM plugins

**F7: Observability**
- Real-time event streaming (WebSocket)
- Attack log export (CSV, JSON)
- Time-series statistics (RPS, blocked %, geo)
- Notification system (Email, Webhook, Telegram)
- CrowdSec event push
- Audit log (Admin UI changes)

**F8: Extensibility**
- Rhai scripting engine (sandboxed custom rules)
- WASM plugin system (wasmtime 43; sandboxed execution)
- Remote rule sources (async loading, auto-update)
- Custom checkers via modular design

### Non-Functional

**NF1: Performance**
- Request latency: <5ms added overhead (99th percentile)
- Throughput: >10,000 RPS per node
- Rule evaluation: <1ms per request (all 16 phases)
- Cache hit ratio: >80% (typical web app)

**NF2: Reliability**
- Uptime: 99.99% (cluster mode)
- Graceful degradation (rule parse errors don't crash)
- Cluster consensus: survive 1 node failure (3-node cluster)
- Election time: <500ms (LAN)

**NF3: Security**
- No unsafe code in production (only in tests)
- No unwrap/panic in production path
- mTLS encryption (cluster communication)
- AES-256-GCM at-rest encryption (secrets in DB)
- Constant-time secret comparison
- No secret logging (tokens, keys, passwords sanitized)

**NF4: Maintainability**
- Rust 2024 edition, rustfmt max width 120
- Clippy -D warnings (all pedantic + nursery)
- Comprehensive tests (243 regression tests in v0.2.0)
- Code ownership clear (7 crates, modular)
- Documentation (architecture, API, admin guides)

**NF5: Scalability**
- Horizontal: add more nodes to cluster
- Vertical: multi-threaded Tokio runtime (CPU-bound rule matching)
- Database: connection pooling (20 conns default, tunable)
- Cache: moka LRU (configurable size, TTL)

---

## Scope (In / Out)

### In Scope

- Web application firewall (L7 HTTP/S)
- Reverse proxy (load balancing, vhost routing)
- PostgreSQL storage
- Clustering (QUIC mTLS mesh)
- Admin UI (Vue 3, embedded static)
- Docker/Podman and systemd deployment
- CrowdSec integration (bouncer + AppSec)
- WASM plugins (wasmtime sandboxed)
- Let's Encrypt automation
- Rhai custom rule scripting

### Out of Scope (v1)

- mDNS auto-discovery (static seeds only)
- WASM plugin binary sync (workers run without plugins)
- Multi-region clustering (single LAN cluster only)
- Distributed rate limiting (per-node CC tracking)
- OpenTelemetry tracing (structured logging only)
- eBPF kernel module (user-space reverse proxy only)
- IPv6 support (v0 is IPv4-only; v1 adds IPv6)

---

## Success Metrics

### v0.2.0 Release (2026-03-27) — Achieved

1. **Clustering MVP**: 3-node cluster, QUIC mTLS, leader election, rule sync — stable in production
2. **Security Hardening**: 8 panic elimination, SSRF validation, DNS rebinding guard, API security headers
3. **SQLi Modularization**: 19-pattern engine (SQLI-001..019), 3 scanner modules, 63+ acceptance tests; p99 <500µs clean, <1ms malicious
4. **E2E Test Suite**: 1,812 LOC, 5 shell runners, multi-artifact output (JUnit/JSON/Markdown/HTML)
5. **Rule Coverage**: libinjection SQLi/XSS detection active; 51 built-in rules
6. **Regression Testing**: 243 regression tests (116 added in v0.2.0); all passing
7. **Dependency Audit**: 0 unaddressed CVEs; wasmtime upgraded (23→43, 5 CVEs fixed)

### v0.3.0 (Proposed — Metrics)

1. **Observability**: OpenTelemetry integration, distributed tracing across cluster
2. **Metrics**: Prometheus endpoint (/metrics), histogram latency, rule hit counts
3. **Documentation**: Complete API reference (70+ endpoints), operator runbooks
4. **Performance**: <3ms added latency (99th percentile), >15,000 RPS/node
5. **Vue UI Tests**: >80% code coverage for admin-ui components

### Long-term (Post v1)

1. **Multi-region**: Cross-datacenter clustering with region-aware routing
2. **WASM Sync**: Binary plugin distribution to worker nodes
3. **Machine Learning**: Anomaly detection (request patterns, attack patterns)
4. **Kubernetes Operator**: Native K8s integration (CRDs for rules, hosts, certificates)

---

## Key Design Decisions

### D1: Rust + Pingora (Not Go/Python/Java)

**Why**: Cloudflare's Pingora is production-proven (10M+ RPS internally), memory-safe (Rust), and modular. Alternative: NGINX ModSecurity (C, battle-tested but less extensible).

**Trade-off**: Longer compile time, steeper learning curve, but security + performance + maintainability benefits outweigh.

### D2: PostgreSQL Storage (Not SQLite or In-Memory)

**Why**: Multi-node cluster needs shared state (rules, config, logs). PostgreSQL is ACID-compliant, has excellent Tokio drivers (sqlx), and scales horizontally with read replicas.

**Trade-off**: Operational complexity (manage DB), but essential for production.

### D3: QUIC mTLS Cluster (Not gRPC/HTTP/WireGuard)

**Why**: QUIC is 0-RTT, multiplexes streams, built-in TLS 1.3, and already in `gateway` crate for HTTP/3. gRPC adds tonic + protobuf build overhead. WireGuard requires kernel setup.

**Trade-off**: QUIC is newer (RFC 9000, 2021); implementations mature in production (Cloudflare, Google, Facebook), but fewer team members familiar.

### D4: Rhai + WASM for Extensibility (Not Lua)

**Why**: Rhai is pure Rust (no C FFI), sandboxed, and syntax familiar to Rust developers. WASM isolates untrusted code and allows polyglot plugins (AssemblyScript, Go, Rust).

**Trade-off**: Rhai smaller ecosystem than Lua, but Rust integration is seamless; WASM startup overhead mitigated by caching.

### D5: Hot-Reload via File Watcher (Not API-Only)

**Why**: Operators prefer deploying rules via ConfigMap/Git, not API calls. File watcher (notify) enables GitOps workflow.

**Trade-off**: File-based rules + DB custom rules = two sources of truth (mitigated by clear ownership: built-in YAML = file, custom rules = DB).

### D6: Embedded Admin UI (Not Separate Service)

**Why**: Single binary deployment; no extra containers or inter-service auth. rust-embed compiles Vue SPA into binary.

**Trade-off**: Binary size +2MB, but simplifies deployment (no nginx reverse-proxy needed).

### D7: Cluster as Opt-In (Not Mandatory)

**Why**: Clustering adds operational complexity (cert management, election timeouts, QUIC tuning). Single-node deployments should not pay that cost.

**Trade-off**: Code paths must handle both standalone and cluster modes; testing matrix larger.

---

## v0.2.0 Status Snapshot

### Completed

- **Cluster Consensus**: QUIC mTLS, Raft-lite election, phi-accrual failure detection
- **Rule Sync**: Incremental (changelog ring buffer) + full snapshot (lz4 compression)
- **Security Hardening**: 8 panic elimination, SSRF/DNS rebinding/encoding bypass guards
- **Dependency Upgrades**: wasmtime 23→43, axum 0.7→0.8.8, jsonwebtoken OpenSSL→rustls
- **Regression Tests**: 243 total (144 new in v0.2.0)

### Known Limitations

- **WASM on Workers**: Not synced; workers run without WASM plugins (v1 feature)
- **IPv6**: Not yet supported (future)
- **mDNS**: Static seeds only; no auto-discovery (future)
- **Distributed Rate Limiting**: Per-node CC tracking; no shared counters

### Testing

- **Unit Tests**: 80+ (election, crypto, frame codec)
- **Integration Tests**: 20+ (2-node connect, rule sync, failover)
- **Chaos Tests**: Kill main → worker election in <500ms
- **E2E Tests**: 3-node docker-compose cluster, rule creation + sync
- **Performance**: Baseline ~0.5ms per request (on i7 6-core)

---

## Implementation Roadmap

| Phase | Status | Key Deliverables |
|-------|--------|------------------|
| **v0.1.0** | Complete | Core WAF, rules, admin UI, basic clustering (P1–P3) |
| **v0.1.0-rc.1** | Complete | Cluster P1–P5 (QUIC, election, sync, UI, docker) |
| **v0.2.0** | Complete | Security hardening, SSRF/DNS guards, 243 regression tests |
| **v0.3.0** | Proposed | Observability (metrics, tracing), Vue UI tests, performance |
| **v1.0.0** | Proposed | WASM sync, multi-region, ML anomaly detection |

---

## Stakeholders & Roles

| Role | Responsibility | Examples |
|------|---|---|
| **Platform Teams** | Deploy + operate, tune performance | DevOps, SRE |
| **Security Teams** | Policy authoring, threat intel, audit | CISO, AppSec, SOC |
| **Application Teams** | Custom rules, integration testing | Backend engineers, QA |
| **Infrastructure** | DB backups, cert renewal, scaling | DBAs, Network ops |

---

## Exit Criteria (Release Readiness)

**v0.2.0 achieved all criteria:**

- [x] 243 regression tests passing
- [x] 0 high/critical security issues (7 medium/low fixed)
- [x] Cluster stable (3-node test, election <500ms)
- [x] Crash-free (no panics in production path)
- [x] Performance baseline (0.5ms/request, >10k RPS/node)
- [x] Documentation (architecture, deployment, API)
- [x] Code review (all changes peer-reviewed)

---

## Questions & Decisions Logged

**Q: IPv6 support — when?**
- A: v0.3.0 or later; current priority is observability

**Q: Multi-region clustering?**
- A: Post-v1.0; requires distributed consensus (Raft or equivalent) + geo-aware routing

**Q: WASM plugin sync to workers?**
- A: v1.0; requires binary distribution + versioning; current v0.2 limitation documented

**Q: Lua instead of Rhai?**
- A: Rhai chosen for native Rust integration; Lua considered for polyglot teams but rejected (C FFI complexity)
