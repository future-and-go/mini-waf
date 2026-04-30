# Project Roadmap

## Release History & Status

### v0.1.0-rc.1 (2026-03-16) — Complete

**Cluster Foundation (P1–P5)**
- [x] QUIC mTLS transport (quinn + rustls + rcgen)
- [x] Raft-lite leader election with phi-accrual failure detection
- [x] Rule sync (incremental changelog + full snapshot)
- [x] Admin UI cluster dashboard (4 new pages)
- [x] docker-compose cluster setup (3-node, 1 main + 2 workers)
- [x] End-to-end integration tests (20+ cluster scenarios)

**Core WAF**
- [x] 16-phase detection pipeline
- [x] 51 built-in rules (OWASP CRS, CVE patches, advanced patterns)
- [x] WASM plugin system (wasmtime 23)
- [x] Rhai custom rule scripting
- [x] CrowdSec bouncer + AppSec integration
- [x] PostgreSQL persistence layer
- [x] Vue 3 admin UI (19 pages)

---

### v0.2.0 (2026-03-27) — Complete ✓

**Status**: Production-ready, all acceptance criteria met

**Security Hardening**
- [x] 8 panic-capable unwrapping → safe degradation (panic elimination)
- [x] SSRF protection (url_validator module, DNS rebinding guard)
- [x] Iterative URL decoding (up to 3 rounds, encoding bypass prevention)
- [x] Remote rule source hardening (30s timeout, 10MB size limit, no redirects)
- [x] Admin API security middleware (IP allowlist, rate limiting, security headers)
- [x] Login rate limiting (per-IP configurable)
- [x] WebSocket IP allowlist
- [x] Cluster peer fencing (stale peer eviction)
- [x] XFF trusted-proxy CIDR validation (config error, not runtime panic)
- [x] Rule deletion atomic swap (RuleRegistry in-memory sync)

**Rule Engine Enhancements**
- [x] libinjectionrs integration (detect_sqli, detect_xss operators)
- [x] OWASP CRS rule operators now fully evaluated (CRS-942100, CRS-941100)
- [x] Remote rule source async loading (background fetch post-startup)
- [x] Rule source URL validation (public IP only, no RFC-1918)

**Dependency Upgrades (Security + Compatibility)**
- [x] wasmtime: 23.0.3 → 43.0.0 (5 CVEs fixed)
- [x] axum: 0.7 → 0.8.8
- [x] tower: 0.4 → 0.5.3
- [x] jsonwebtoken: 9 → 10 (OpenSSL → rust_crypto)
- [x] reqwest: 0.12 → 0.13
- [x] tokio-tungstenite: 0.23 → 0.26
- [x] serde_yaml: 0.9 → serde_yaml_ng 0.10
- [x] sqlx: set default-features = false (drop rsa dep)

**Testing & Quality**
- [x] E2E test suite (1,812 LOC): 5 shell runners (rules-engine, gateway, api, cluster, report-renderer)
- [x] 63+ SQLi acceptance tests (19 patterns, encoding bypasses, false positives)
- [x] 116 new regression tests (suite total: 243)
- [x] SSRF validation tests
- [x] Encoding bypass prevention tests
- [x] SQLi/XSS detection tests
- [x] Cluster peer fencing tests
- [x] Dependency upgrade compatibility tests
- [x] Zero unaddressed high/critical CVEs

**Deliverables**
- [x] Release notes (CHANGELOG.md)
- [x] Security advisory (panic elimination, SSRF guard)
- [x] Build & test automation (CI passing)
- [x] Documentation (architecture, deployment, code standards)

**Metrics v0.2.0**
- Regression test coverage: 243 tests (↑116 from v0.1); E2E suite 1,812 LOC with 5 modular runners
- SQLi modularization: 19 patterns (SQLI-001..019), 3 scanner modules (classic/blind/error-based)
- SQLi benchmarks: p99 <500µs clean traffic, <1ms malicious payloads
- Security issues fixed: 10 (8 panics, SSRF, DNS rebinding, encoding bypass)
- Performance: <0.5ms per request (99th percentile, unchanged)
- Cluster stability: 3-node election <500ms (unchanged)

---

## Unreleased (In Progress — 2026-04-29)

### FR-002 — Tiered Protection (Complete ✓)

Implements a four-tier request classification and per-tier policy bus that all downstream feature-requests (FR-005, FR-006, FR-009, FR-027) consume. Every request is mapped to `Critical / High / Medium / CatchAll` by a priority-sorted classifier (path-exact, path-prefix, path-regex, host-suffix, method, header matchers); the matched tier's `TierPolicy` — carrying `fail_mode`, `ddos_threshold_rps`, `cache_policy`, and `risk_thresholds` — is attached to `RequestCtx` before Phase 1 runs. The policy registry is backed by `ArcSwap` for lock-free atomic hot-swaps: the `TierConfigWatcher` thread monitors `configs/default.toml`, debounces editor-burst events (200 ms window), and publishes validated snapshots without restarting the gateway. On parse or validation failure the previous config is retained and a `tracing::warn!` is emitted; the gateway never panics on bad config.

- [x] `waf-common::tier` — `Tier` enum, `TierPolicy`, `TierClassifierRule`, `TierConfig::validate()`, TOML schema
- [x] `gateway::tiered::TierClassifier` — compiled rules, priority sort, first-match-wins
- [x] `gateway::tiered::TierPolicyRegistry` — `ArcSwap<TierSnapshot>`, lock-free classify
- [x] `gateway::tiered::TierConfigWatcher` — `notify`-based hot-reload, debounce, atomic swap
- [x] `gateway::ctx_builder` — wires classifier into `RequestCtxBuilder`; `ctx.tier` set before checks
- [x] E2E integration tests (`crates/gateway/tests/tier_e2e.rs`) — 6 tests covering all 4 tiers, default fallback, TOML round-trip, and hot-reload
- [x] Criterion bench (`crates/gateway/benches/tier_classifier_bench.rs`) — 50-rule classify over 1000 paths
- [x] Consumer doc (`docs/tiered-protection.md`) — API reference for FR-005/006/009/027 implementers
- [x] Architecture diagram — Mermaid tier flow added to `docs/system-architecture.md`

### FR-003 — File-Based Custom Rule Loader (Complete ✓)

Scans `rules/custom/*.yaml` and auto-loads YAML documents marked with `kind: custom_rule_v1`. Per-file error isolation: bad files skip gracefully, previous versions retained, errors logged. Hot-reload via `notify` watcher (500ms debounce). Forward-compat: unknown `custom_rule_v*` versions rejected on parse.

- [x] `crates/waf-engine/src/rules/custom_file_loader.rs` — watcher loop, scan + load
- [x] `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs` — multi-doc YAML parser, `kind` discriminator
- [x] Rule registry integration: clear stale, `add_file_rule` per result
- [x] Tests: `custom_rule_file_load.rs`, `custom_rule_hot_reload.rs`
- [x] Updated `docs/custom-rules-syntax.md` (already current)

### FR-008 — Whitelist + Blacklist (Complete ✓)

Phase-0 access-control gate that runs before the 16-phase rule pipeline: per-tier IP whitelist (Patricia trie via `ip_network_table`), IP blacklist, per-tier Host (FQDN) whitelist, with `full_bypass` / `blacklist_only` per-tier dispatch (Strategy). Snapshot lives behind `Arc<ArcSwap<AccessLists>>`; the `notify`-driven reloader watches `rules/access-lists.yaml`, debounces editor save bursts (~250 ms), and atomically swaps validated snapshots — bad YAML keeps the previous snapshot live with a `tracing::warn!` (D8). Decision chain runs Host gate → IP blacklist → IP whitelist (deny wins over allow); audit fields `access_decision` / `access_reason` / `access_match` stamp every request. Soft-warn ≥50k entries, hard-reject ≥500k.

- [x] `crates/waf-engine/src/access/{config,ip_table,host_gate,evaluator,reload}.rs` — schema, trie adapter, host gate, chain evaluator, watcher
- [x] `crates/gateway/src/pipeline/access_phase.rs` — Phase-0 wiring
- [x] `crates/waf-engine/tests/access_hot_reload.rs`, `access_reload_under_load.rs` — hot-reload integration
- [x] `crates/waf-engine/benches/access_lookup.rs` — bench: v4 p99 ≤2µs @ 10k, v6 ≤4µs
- [x] Operator doc (`docs/access-lists.md`) + sample YAML (`rules/access-lists.yaml`)
- [x] Cross-links: `tiered-protection.md` §10, `codebase-summary.md`, `system-architecture.md`

Deferred follow-ups: Tor exit list (FR-042), bad ASN classification (FR-007), validated XFF `ctx.client_ip` (FR-007).

### Panel-Config API (Complete ✓)

Atomic read/write of `waf-panel.toml` (operational policy settings) via `GET/PUT /api/panel-config`. Config struct `WafPanelConfig` with nested sections: `ResponseFilteringPanel`, `TrustedBypassPanel`, `RateLimitsPanel`, `AutoBlockPanel`. Validates risk thresholds (allow < challenge < block), CIDR syntax, honeypot paths. Atomic write-through semantics.

- [x] `crates/waf-common/src/panel_config.rs` — TOML schema + validation
- [x] `crates/waf-api/src/panel_api.rs` — `GET/PUT /api/panel-config` handlers
- [x] Frontend: `web/admin-panel/src/pages/settings/index.tsx` — settings UI with i18n
- [x] i18n locales updated (all 11 locales)

---

## v0.3.0 (Proposed — Q3 2026)

**Theme**: Observability & Developer Experience

### Metrics & Monitoring
- [ ] Prometheus `/metrics` endpoint (counter, gauge, histogram types)
- [ ] Metrics exported:
  - `prx_waf_requests_total` (counter, by host + rule_id)
  - `prx_waf_blocked_requests_total` (counter, by rule_id)
  - `prx_waf_request_duration_ms` (histogram, P50/P95/P99)
  - `prx_waf_rule_matches_total` (counter, per rule_id)
  - `prx_waf_backend_latency_ms` (histogram)
  - `prx_waf_cache_hit_ratio` (gauge)
  - `prx_waf_cluster_election_time_ms` (histogram)
- [ ] Grafana dashboard templates (JSON)
- [ ] Alert examples (Prometheus rules)

### Distributed Tracing
- [ ] OpenTelemetry integration (optional, off by default)
- [ ] Trace propagation (W3C Trace Context)
- [ ] Spans: HTTP request, rule eval, database query
- [ ] Exporter: Jaeger, Zipkin, Datadog
- [ ] Admin UI: trace correlation with security events

### Admin UI Testing
- [ ] Vitest + Vue Test Utils (unit tests)
- [ ] Cypress (E2E tests)
- [ ] Target: >80% code coverage (views + components)
- [ ] Accessibility tests (axe-core)

### Documentation Enhancements
- [ ] API reference (70+ endpoints, all documented)
- [ ] Operator runbooks (troubleshooting, incident response)
- [ ] Performance tuning guide
- [ ] Security best practices
- [ ] Multi-language docs (at least: EN, ZH, RU)

### Performance Baseline
- Target: <3ms added latency (99th percentile, vs <5ms today)
- Target: >15,000 RPS per node (vs >10,000 today)
- Profiling: continuous benchmarks in CI

### Quality
- [ ] Code coverage: >85% (unit + integration)
- [ ] Zero panics in any code path
- [ ] Zero high/critical security issues
- [ ] Full audit of all dependencies (cargo-audit + cargo-deny)

**Effort Estimate**: 120–150 engineer-hours (or ~30 Claude-hours)

---

## v1.0.0 (Proposed — Q4 2026 or early 2027)

**Theme**: Advanced Features & Enterprise Scale

### WASM Plugin Sync
- [ ] Binary plugin distribution to worker nodes
- [ ] Plugin versioning (semantic)
- [ ] Plugin marketplace (community-curated list)
- [ ] Plugin update mechanism (no downtime)
- [ ] Sandboxing enhancements (memory limits, CPU time budgets)

### Multi-Region Clustering
- [ ] Cross-datacenter clustering (georeplicated)
- [ ] Region-aware traffic routing (failover to healthy region)
- [ ] Bandwidth-efficient sync (delta compression)
- [ ] Latency-optimized election (region-aware quorum)

### Machine Learning (Optional)
- [ ] Anomaly detection (request pattern, traffic baseline)
- [ ] Bot detection ML model (decision tree or shallow NN)
- [ ] False positive reduction (feedback loop)

### Kubernetes Native
- [ ] Operator CRDs (Helm-installable)
  - `WAFCluster` — cluster topology
  - `WAFHost` — vhost proxy config
  - `WAFRule` — custom rule definition
- [ ] Auto-scaling policy (HPA integration)
- [ ] Health probes (liveness, readiness, startup)
- [ ] NetworkPolicy templates

### Enterprise Features
- [ ] SAML/OIDC authentication (vs JWT-only)
- [ ] Multi-tenancy (per-customer namespace + RBAC)
- [ ] Customer-specific rule sets
- [ ] Compliance reporting (SOC2, PCI-DSS)
- [ ] Audit log retention policies

### API v2
- [ ] GraphQL endpoint (alternative to REST)
- [ ] Server-sent events (SSE) as WebSocket alternative
- [ ] gRPC interface (for high-performance integrations)

### Performance Target
- [ ] <2ms added latency (99th percentile)
- [ ] >20,000 RPS per node
- [ ] <100ms cluster consensus latency (multi-region)

**Effort Estimate**: 200+ engineer-hours (very large scope)

---

## Future Considerations (Post-v1)

### IPv6 Support
- Full IPv6 support (currently IPv4-only)
- Dual-stack proxy
- IPv6 geolocation

### Edge Computing
- CloudFlare Workers integration
- Fastly Compute integration
- Deploy WAF rules to CDN edge

### AI-Powered Rules
- Natural language rule authoring (GPT + semantic parsing)
- Auto-remediation (auto-tuning rule thresholds)
- Attack prediction (threat modeling)

### Advanced Integrations
- Splunk integration (log streaming)
- Datadog integration (metrics + traces)
- AWS WAF federation
- Azure WAF federation

### Hardware Accelerators
- GPU-accelerated regex matching
- FPGA-optimized rule evaluation
- Intel QuickAssist for encryption

### Developer Tools
- WAF rule testing framework (pytest-style)
- Local dev environment (docker-compose + tester)
- Browser extension for rule debugging
- VS Code extension for rule editing

---

## Priority Alignment

### P0 (Must-Have, Blocking Release)
- [x] v0.2.0: Security hardening (panics, SSRF, encoding bypass)
- [ ] v0.3.0: Observability (metrics, tracing)
- [ ] v1.0.0: Kubernetes operator (enterprise requirement)

### P1 (High Value, Quick ROI)
- [x] Clustering (v0.1)
- [ ] Admin UI testing (v0.3)
- [ ] Multi-region clustering (v1.0)
- [ ] WASM plugin sync (v1.0)

### P2 (Nice-to-Have, Lower Priority)
- [ ] IPv6 (post-v1)
- [ ] Edge computing (post-v1)
- [ ] AI rules (post-v1)
- [ ] Hardware accelerators (post-v1)

### P3 (Deferred, Community-Contributed)
- [ ] OIDC/SAML (v1.0, but can defer)
- [ ] Splunk integration (v1.0+)
- [ ] Developer tools (v1.0+)

---

## Known Limitations

### v0.2.0

| Limitation | Impact | Workaround | Target Fix |
|-----------|--------|-----------|-----------|
| WASM plugins not synced to workers | Workers lack plugin features | Run plugins on main only, or accept feature gap | v1.0 |
| IPv4-only | No IPv6 support | Use IPv4 upstream, add IPv6 reverse proxy | v0.3 or v1.0 |
| Single-region clustering | Can't cross-datacenter | Use separate clusters per region | v1.0 |
| Per-node rate limiting | No shared CC counters | Accept per-node limits | v1.0 |
| No distributed tracing | Hard to debug requests | Parse logs manually | v0.3 |
| No API v2 (GraphQL) | REST-only | Continue using REST | v1.0 |

---

## Dependency Upgrade Plan

### Q2 2026 (Monthly)
- [ ] Check cargo-audit for CVEs
- [ ] Review cargo-deny output
- [ ] Plan upgrades (minor + patch)
- [ ] Test upgrade compatibility

### Q3 2026 (Major Version Candidates)
- [ ] Tokio: 1.x → follow latest (1.40+)
- [ ] Pingora: 0.8 → 0.9+
- [ ] Axum: 0.8 → 0.9+ (if available)
- [ ] wasmtime: 43 → latest (stay current)

### Deprecation Policy
- **MSRV**: Rust 1.86 (2024 Edition)
- **Support**: Latest stable + 1 minor version back
- **Deprecation notice**: Minimum 1 release ahead

---

## Success Metrics (By Release)

### v0.2.0
- [x] 0 unaddressed high/critical CVEs
- [x] 243 regression tests passing
- [x] <0.5ms request latency (99th percentile)
- [x] <500ms cluster election
- [x] 100% uptime in staging (1-week burn-in)

### v0.3.0 (Proposed)
- [ ] Prometheus metrics exported successfully
- [ ] OpenTelemetry traces in Jaeger
- [ ] Admin UI unit test coverage >80%
- [ ] E2E test suite >50 scenarios
- [ ] Documentation: 100+ pages
- [ ] <3ms request latency (99th percentile)
- [ ] >15,000 RPS/node in production

### v1.0.0 (Proposed)
- [ ] Kubernetes operator deployable via Helm
- [ ] Multi-region cluster tested (DR failover <1min)
- [ ] WASM plugins synced to all workers
- [ ] Enterprise customer deployments (>3)
- [ ] <2ms request latency (99th percentile)
- [ ] >20,000 RPS/node in production

---

## Community Contribution Areas

**Welcome contributions from community:**
1. **Rule Pack**: Additional OWASP/vendor rule sets
2. **Integrations**: Splunk, Datadog, Prometheus exporters
3. **Localization**: Additional language translations (currently 11 locales)
4. **Documentation**: Guides, tutorials, troubleshooting
5. **WASM Plugins**: Community plugin marketplace
6. **Performance**: Benchmarking, optimization tips

**Not for community (core team only):**
1. Clustering protocol changes
2. Election algorithm
3. Core WAF engine phases
4. Security-critical paths

---

## Version Support Matrix

| Version | Released | Support Ends | Status |
|---------|----------|--------------|--------|
| **v0.1.0-rc.1** | 2026-03-16 | 2026-06-30 | Bug fixes only |
| **v0.2.0** | 2026-03-27 | 2026-09-30 | Active support |
| **v0.3.0** | TBD Q3 2026 | TBD Q4 2027 | Planned |
| **v1.0.0** | TBD Q4 2026 | TBD Q4 2028 | Planned |

---

## Milestones (Gantt-style)

```
Q1 2026 [===========]                                 (v0.2.0 released, security hardening complete)
         └─ Clustering P1–P5 ✓
         └─ SSRF/DNS guard ✓
         └─ 243 regression tests ✓

Q2 2026            [=================]                 (v0.3.0 planning & design)
         └─ Observability design
         └─ Metrics framework
         └─ Distributed tracing design
         └─ Admin UI test strategy

Q3 2026                         [=====================] (v0.3.0 implementation)
         └─ Prometheus metrics
         └─ OpenTelemetry integration
         └─ Admin UI tests (Vitest + Cypress)
         └─ Operator docs

Q4 2026                                      [=============================] (v0.3.0 RC + v1.0.0 start)
         └─ v0.3.0 RC testing
         └─ WASM plugin sync design
         └─ Multi-region clustering design
         └─ Kubernetes operator start

Q1 2027                                                          [===========] (v1.0.0 implementation)
         └─ Kubernetes operator (Helm)
         └─ Multi-region clustering
         └─ WASM plugin binary sync
         └─ Enterprise features (SAML/OIDC)

Q2 2027                                                                      [==========] (v1.0.0 RC)
         └─ Multi-region cluster testing
         └─ Operator testing in EKS/GKE
         └─ Performance optimization
         └─ Documentation

Q3+ 2027                                                                                [future releases]
```

---

## Feedback & Questions

**How to submit feedback:**
1. GitHub Issues (bugs, feature requests)
2. GitHub Discussions (ideas, feedback)
3. Security issues: security@openprx.dev

**Roadmap review cycle:** Quarterly (Q-end review + next-Q planning)
