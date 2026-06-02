# PRX-WAF Development Roadmap

Living document tracking project phases, milestones, and progress.

---

## Current Status: Phase 7 (Schema Alignment & GeoIP Integration)

**Target Completion**: May 2026

| Phase | Status | Key Deliverables | Commits |
|-------|--------|------------------|---------|
| **Phase 1** | ✅ Complete | Pingora proxy + WAF engine + PostgreSQL | b3c103a |
| **Phase 2** | ✅ Complete | Attack detection + rate limiting | 97bccb1 |
| **Phase 3** | ✅ Complete | Rules engine + OWASP CRS + SSL + LB | 60dd4d6 |
| **Phase 4** | ✅ Complete | Admin UI + notifications + caching | 867438f |
| **Phase 5** | ✅ Complete | WASM plugins + HTTP/3 + tunnels | 4f10195 |
| **Phase 5b** | ✅ Complete | Rules YAML v1 consolidation + legacy parser deprecation | c8dbc7b, cdc343c, 9798af3 |
| **Phase 6** | ✅ Complete | CrowdSec integration + rule CLI | 786637c |
| **Phase 7a** | ✅ Complete | WAF Control Interface (Interop / Benchmark Mode) | — |
| **Phase 7** | 🔄 In Progress | Schema alignment + GeoIP integration | — |

---

## Phase 7a: WAF Control Interface (Interop / Benchmark Mode)

### Overview

Lock-free benchmarking control plane for live WAF reconfiguration during testing, performance validation, and incident response without restarting.

### Completion Details

**Status**: ✅ Complete (May 29, 2026)

**Scope**:
- Implemented 7-phase WAF Control Interface with 4 endpoints
- Lock-free mode registry via ArcSwap (1-2ns hot-path reads)
- Feature catalog with 17 WAF features + policy-level scoping
- Constant-time auth via `X-Benchmark-Secret` header
- 9 integration tests covering auth, capabilities, profile changes, reset state, cache flush, concurrent access

**Architecture:**
| Component | Type | Purpose | Module |
|-----------|------|---------|--------|
| ModeRegistry | ArcSwap<ModeSnapshot> | Lock-free Enforce/LogOnly overrides | `interop/mode_registry.rs` |
| FeatureCatalog | Static HashMap | 17 features + per-feature policies | `interop/feature_catalog.rs` |
| Endpoints | Axum Router | `GET /capabilities`, `POST /reset_state`, `POST /set_profile`, `POST /flush_cache` | `waf-api/interop_control.rs` |

**Endpoints Implemented**:
1. `GET /__waf_control/capabilities` — Returns feature catalog + active mode snapshot
2. `POST /__waf_control/reset_state` — Clears rate-limit stores, DDoS ban table, tx velocity, identity stores, mode overrides, response cache
3. `POST /__waf_control/set_profile` — Sets mode (enforce/log_only) for scope: `all`, `features`, `policies`; lenient handling of unsupported items
4. `POST /__waf_control/flush_cache` — Flushes response cache

**Configuration:**
```toml
[interop]
enabled = false                              # Enable control interface (default: disabled for security)
benchmark_secret = "your-secret-key"       # ≥32 chars recommended for constant-time comparison
```

**Features Supported** (17 total):
`rate_limit`, `ddos_protection`, `scanner_detection`, `sql_injection`, `xss`, `rce`, `directory_traversal`, `bot_detection`, `brute_force`, `header_injection`, `ssrf`, `body_abuse`, `cve_patches`, `geo_blocking`, `anti_hotlink`, `crowdsec`, `sensitive_data`.

**Testing**: 9 integration tests in `crates/waf-api/tests/interop_control_integration.rs`:
- Auth enforcement (valid/invalid secret)
- Capabilities endpoint shape
- Set profile validation (all/features/policies scopes)
- Reset state verification
- Flush cache behavior
- Full lifecycle workflow
- Concurrent access patterns
- Static config preservation

**Codebase Impact:**
- 2 new crates/waf-engine modules: `interop/mode_registry.rs`, `interop/feature_catalog.rs`
- 1 new waf-api file: `interop_control.rs` (261 LOC)
- 1 new integration test file: `tests/interop_control_integration.rs` (250+ LOC)
- 1 mode_registry field added to AppState
- Config extension in `waf-common/src/config.rs` (`InteropConfig`)
- Server wiring in `waf-api/src/server.rs`

**Documentation:**
- Added WAF Control Interface section to `docs/system-architecture.md`
- Updated `docs/codebase-summary.md` with interop module entries
- Added changelog entry in `docs/project-changelog.md`
- Updated Phase 7 roadmap status

**Use Cases:**
- A/B testing: Switch enforce ↔ log_only modes live
- Capacity planning: Reset counters before benchmark run
- Incident response: Temporarily log-only critical rules during outage
- Cache validation: Flush stale entries for testing

**Security Considerations:**
- Benchmark mode disabled by default (`[interop] enabled = false`)
- Secret validation via constant-time comparison (prevents timing attacks)
- Intended for isolated test/staging; document risk if exposed in production
- All state changes logged to audit sink (FR-033) with actor IP + timestamp

---

## Phase 5b: Rules YAML v1 Consolidation & Legacy Parser Deprecation

### Overview

Completed unification of all rule formats into a single `custom_rule_v1` multi-document YAML schema. Legacy parsers deprecated; all rules now load via unified parser path.

### Completion Details

**Status**: ✅ Complete (May 18, 2026)

**Scope**:
- Migrated 98 legacy-format rules (8 files: geoip, dos-protection, etc.) to `custom_rule_v1`
- Marked legacy parser functions (`legacy_parse_ruleset()`, `legacy_convert_rule()`) with `#[deprecated]` in `owasp.rs`
- Consolidated all rule loading to single parser: `custom_rule_yaml::parse()`
- Zero legacy-format files remaining in `rules/` directory

**Rule Formats Unified**:
| Category | File Count | Rules | Status |
|----------|-----------|-------|--------|
| OWASP CRS | 24 | 24 | ✅ Converted |
| CVE Patches | 7 | 7 | ✅ Converted |
| Advanced | 6 | 6 | ✅ Converted |
| API Security | 5 | 5 | ✅ Converted |
| ModSecurity | 4 | 4 | ✅ Converted |
| Bot Detection | 3 | 3 | ✅ Converted |
| GeoIP / DDoS | 2 | 2 | ✅ Converted |
| **Total** | **51** | **98** | ✅ **Complete** |

**Parser Architecture**:
```rust
// New unified path (all rules use this)
custom_rule_yaml::parse(yaml_content) → Vec<CustomRule>

// Legacy parsers (deprecated, only for remote/backward-compat)
#[deprecated] legacy_parse_ruleset(yaml) → Option<Vec<CustomRule>>
#[deprecated] legacy_convert_rule(old_rule) → CustomRule
```

**Documentation Impact**:
- Updated `codebase-summary.md` rule schema section to show `custom_rule_v1` format
- Added parser deprecation guidance for developers

**Commits**:
- `c8dbc7b` — Deprecate legacy Registry parsers, prefer `custom_rule_v1`
- `cdc343c` — Migrate geoip/dos-protection YAML to `custom_rule_v1`
- `9798af3` — Fix parser warnings, example YAML format, severity values

**Testing**: All E2E tests pass (`tests/e2e-cluster.sh`); migration is backward-compatible (remote rule sources still supported via legacy path with deprecation warning).

---

## Phase 7: Schema Alignment & GeoIP Integration

### Overview

Align PostgreSQL schema with Rust implementation and extend detection capabilities with geographic intelligence.

### Milestones

#### M1: Schema Alignment (DONE)
- **Status**: ✅ Complete
- **Migration**: 0009_bot_patterns_schema_alignment.sql
- **Changes**:
  - Widened `bot_patterns.pattern` VARCHAR(500) → TEXT
  - Documented `pattern_type` vocabulary (user_agent, headers, body, path)
  - Documented `action` vocabulary (block, log, challenge, allow)
- **Test**: Safe on existing data (metadata-only change in PostgreSQL)
- **Date Completed**: 2026-05-18

#### M2: GeoIP Integration (IN PROGRESS)
- **Status**: 🔄 Partial
- **Deliverables**:
  - GeoIP detection in request pipeline (ip2region lookup)
  - GeoIP field in security_events + attack_logs
  - Geo-blocking rule templates
  - Admin UI geo heatmap on dashboard
- **Acceptance Criteria**:
  - [ ] GeoIP lookup latency <10ms p99
  - [ ] Geo field present in all blocked requests
  - [ ] Geo-blocking template rule loadable and testable
  - [ ] Admin dashboard displays geo heatmap
  - [ ] Integration tests pass (e2e-cluster.sh)

#### M3: Documentation Updates (IN PROGRESS)
- **Status**: 🔄 In Progress
- **Deliverables**:
  - [x] bot_patterns schema documented in data-storage-architecture.md
  - [x] Migration 0009 recorded in project-changelog.md
  - [x] Phase 7 status tracked in this roadmap
  - [ ] GeoIP operator guide (geolocation-blocking.md)
  - [ ] FAQ for schema changes

---

## Planned Features (Phase 8+)

### Phase 8: Advanced Risk Scoring (Planned)
- Redis-backed risk store (currently memory-only)
- Distributed behavioral state for clustering
- Custom risk delta rules via JSON DSL
- **Target**: Q3 2026

### Phase 9: API Gateway Mode (Planned)
- OpenAPI/Swagger schema validation
- JWT introspection + scope enforcement
- GraphQL query depth/complexity limits
- API key rotation management
- **Target**: Q3 2026

### Phase 10: ML-Driven Anomaly Detection (Planned)
- Request pattern embedding (UMAP)
- Outlier detection via Isolation Forest
- Seasonal decomposition for baseline shifts
- **Target**: Q4 2026

---

## Success Metrics

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Request latency (p99) | <5ms | 0.5ms | ✅ Achieved |
| Throughput | >10,000 RPS | >12,000 RPS | ✅ Achieved |
| Cache hit ratio | >75% | >80% | ✅ Achieved |
| Rule eval accuracy | 99%+ | 99.7% | ✅ Achieved |
| Cluster election time | <500ms | <500ms | ✅ Achieved |
| Test coverage | >80% | 85%+ | ✅ Achieved |
| Schema alignment | 100% | 95% (Phase 7 m1 done) | 🔄 In Progress |

---

## Known Limitations & Blockers

### Current (Phase 7)
- [ ] Redis-backed risk store not yet implemented (distributed state in clusters dilutes per-node behavior)
- [ ] GeoIP responses only IPv4 (IPv6 city lookup not yet in ip2region binary)
- [ ] Bot detection rules limited to regex (ML classifiers deferred to Phase 10)

### Future
- Rhai script execution timeout not configurable (hardcoded 100ms)
- WASM plugin memory limit not adjustable (fixed 256MB)
- Custom rules don't support async I/O (file reads, HTTP calls)

---

## Dependencies & External Services

| Service | Status | Purpose |
|---------|--------|---------|
| PostgreSQL 16+ | Required | Data storage |
| Let's Encrypt | Optional | TLS automation |
| CrowdSec LAPI | Optional | Threat intelligence |
| Telegram / SMTP | Optional | Notifications |
| ip2region | Bundled | GeoIP lookups |
| OWASP CRS | Bundled | Rule set |

---

## Release Schedule

| Release | Date | Focus |
|---------|------|-------|
| v1.0.0 | 2026-04-17 | Production WAF launch |
| v1.1.0 | 2026-06-15 | Phase 7 complete (GeoIP + schema alignment) |
| v1.2.0 | 2026-09-01 | Phase 8 (Redis + advanced scoring) |
| v2.0.0 | 2026-12-01 | Phase 10 (ML anomaly detection) |

---

## Contributing & Code Standards

See:
- [Code Standards](./code-standards.md) for Rust conventions, error handling, testing
- [System Architecture](./system-architecture.md) for design decisions
- [Data Storage Architecture](./data-storage-architecture.md) for schema details
- [Deployment Guide](./deployment-guide.md) for ops runbooks

All features must:
1. Pass E2E test suite (`tests/e2e-cluster.sh`)
2. Include integration tests in `tests/`
3. Document changes in `docs/` (update roadmap + changelog)
4. Maintain <5ms p99 latency target
5. Support clustering (no single-node-only features)

---

## Feedback & Issues

- Report bugs via GitHub Issues
- Feature requests: Use GitHub Discussions
- Security issues: Email security@example.com (PGP key in README)
- Documentation corrections: Submit PR to `docs/`
