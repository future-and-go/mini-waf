# PRX-WAF Project Changelog

All notable changes to PRX-WAF are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added
- **FR-030 — Endpoint Heatmap**: Real-time attack distribution by endpoint + stats overview filters (commit 54d642b)
- **Admin Panel**: Rule analytics dashboard + security event detail view (commit 5faa764)

### Fixed
- **Bot Detection**: Fixed bot management logic (commit 98a2216)
- **TLS Listener**: Reverted native TLS listener (listen_addr_tls) — back to nginx fronting; separated TLS-terminate intent from upstream-TLS with proper H2 host routing (commits efc90a1, 0f0c051)
- **Security**: Dependency bump astral-tokio-tar 0.6.1 → 0.6.2 (RUSTSEC-2026-0145) (commit ac38cd0)

### Documentation
- Clarified FR-008 access-list dry-run behavior, Phase-0 ordering
- Added FR-025 risk scoring documentation and new rule fields (commit 19f61ba)
- Corrected request-pipeline Phase-0 ordering: Host gate → IP blacklist → IP whitelist

### Changed
- **Migration 0009**: Widened `bot_patterns.pattern` VARCHAR(500) → TEXT; expanded `pattern_type` + `action` vocabulary
- **Admin UI**: Enhanced security event detail with FR-030 analytics

---

## [v1.0.0] - 2026-04-17

### Added
- Production-grade reverse proxy WAF with 16-phase detection pipeline
- Clustering support with QUIC mTLS mesh, Raft-lite leader election, rule sync
- Comprehensive OWASP CRS rule set (24 rules)
- Device fingerprinting (FR-010) with JA3/JA4/Akamai H2 hashing
- Behavioral anomaly detection (FR-011) with per-actor cadence/path classifiers
- Transaction velocity detection (FR-012) for fintech fraud detection
- Cumulative risk scoring (FR-025) with IP/fingerprint/session triple-index
- Challenge credit tokens (phase 8) with HMAC-SHA256 signing
- DDoS detection (FR-005) with per-IP, per-fingerprint, per-tier adaptive thresholds
- Rate limiting (FR-004) with token-bucket + sliding-window, dual IP+session keys
- Access lists (FR-008) with Patricia trie IP whitelist/blacklist
- Custom rule file loader (FR-003) with hot-reload on `rules/custom/*.yaml`
- Response caching (FR-009) with per-route TTL and tag-based purge
- GeoIP blocking template (ip2region)
- Admin UI (Vue 3 + Refine) with 21 pages (hosts, rules, IP/URL lists, certificates, etc.)
- PostgreSQL persistence layer with 25+ tables
- WebSocket real-time event stream (`/ws/events`, `/ws/logs`)
- Notifications (email, webhook, Telegram)
- CrowdSec integration (bouncer + AppSec)
- WASM plugins + Rhai script engine (sandboxed)
- TLS automation (Let's Encrypt via instant-acme)
- Response header sanitization (FR-035)
- Response body content scanning (FR-033) with stack trace, API key, internal IP redaction
- Sensitive field redaction (FR-034) for JSON response bodies
- Internal-reference body masking (AC-17)
- Reverse tunnel support (encrypted WebSocket)
- HTTP/3 (QUIC) support
- Relay detection (FR-007) with XFF/X-Real-IP validation, ASN classification, Tor exit matching
- Tier classification (FR-002) with per-tier policies (rate limits, risk thresholds, caching)
- Device fingerprinting behavior recording (FR-011) with 16-slot alloc-free ring buffers

### Infrastructure
- 7-crate Rust workspace (~26K LOC)
- Pingora reverse proxy (HTTP/1.1, HTTP/2, HTTP/3)
- Tokio async runtime
- PostgreSQL 16+ with sqlx
- Docker + Docker Compose (single-node + 3-node cluster)
- Comprehensive test suite (1,812 LOC E2E tests)
- CI/CD via GitHub Actions

---

## Notes on Versioning

- **Phase 1** (commit b3c103a): Pingora proxy + WAF engine + PostgreSQL + API
- **Phase 2** (commit 97bccb1): Attack detection + rate limiting
- **Phase 3** (commit 60dd4d6): Rules engine + OWASP CRS + SSL + load balancing
- **Phase 4** (commit 867438f): Admin UI + notifications + caching + deployment
- **Phase 5** (commit 4f10195): WASM plugins + HTTP/3 + tunnels
- **Phase 6** (commit 786637c): CrowdSec integration + rule management CLI
- **Phase 7** (unreleased): GeoIP integration + schema alignment

Each phase introduced major feature sets. Migration 0009 (Phase 3 schema alignment) ensures the PostgreSQL bot_patterns table matches the Rust RuleAction enum and supports longer regex patterns.
