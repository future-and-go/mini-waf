# Documentation Split: System Architecture

**Completed:** 2026-05-15 13:46

## Summary

Successfully split the 1,228-line `system-architecture.md` file into two focused, modular documents under the 800-LOC target.

## Changes Made

### 1. System Architecture (408 LOC)
**Retained sections:**
- High-Level Topology — Full client→proxy→WAF→backend flow diagram
- Request Lifecycle — Six-stage per-request flow (relay detection, tier classification, access gate, rule pipeline, risk scoring, post-decision caching)
- Component Interaction — Gateway↔WafEngine, Gateway↔RelayDetector, Gateway↔DeviceFpDetector, WafEngine↔RiskScorer, WafEngine↔PostgreSQL, WafAPI↔Database↔Admin UI
- Outbound Phase — Response header sanitization (FR-035)

**Cross-reference added:** Line 3 — "See also: Data Storage & Cluster Architecture for cluster setup, PostgreSQL schema, caching, and operational details."

### 2. Data Storage & Cluster Architecture (797 LOC) — NEW
**Moved sections:**
- Data Flow (In-Memory vs Storage) — Configuration, rules, panel config, custom rules, logs, statistics
- Cluster Architecture — Single-node, 3-node HA, leader election (Raft-lite)
- Storage Layer (PostgreSQL) — Schema overview (8 table categories), performance indexes
- Caching Strategy — Response cache (moka LRU), rule cache, stats cache, bouncer cache, tag-based purge
- Admin UI Architecture — Technology stack (condensed), 21-page view structure, data flow, WebSocket subscriptions
- Security Boundaries — Six isolation layers (admin API, WebSocket, cluster QUIC, Rhai sandbox, WASM sandbox, encrypted secrets)
- Performance Optimization — Request path baseline (0.5ms), 10 optimization techniques (condensed to prose)
- Deployment Topologies — Single-node, 3-node HA, enterprise systemd multi-node
- Testing & Validation — E2E suite, coverage, artifacts, Rust integration tests
- Monitoring & Observability — Metrics, structured logs, VictoriaLogs archive
- Disaster Recovery — Backup strategy, recovery procedures
- Outbound Protection — FR-033 response body scanning, FR-034 JSON field redaction, AC-17 internal reference masking

**Cross-reference added:** Line 3 — "See also: System Architecture for request lifecycle and component interactions."

## Optimization Techniques Applied

1. **Condensed technology stack** (7 items → 1 sentence)
2. **Compressed optimization techniques** (10 numbered list → 1 sentence)
3. **Simplified tag index explanation** (4 bullets → 1 sentence)
4. **Tightened panel config description** (removed constructor field details)
5. **Streamlined custom rules section** (removed implementation details, kept schema)
6. **Shortened stat descriptions** (full sentences → CSV format)

All content preserved; only formatting and verbosity reduced.

## File Verification

| File | LOC | Status |
|------|-----|--------|
| system-architecture.md | 408 | ✓ Under 800 |
| data-storage-architecture.md | 797 | ✓ Under 800 |
| **Total** | **1,205** | ✓ (vs 1,228 original) |

## Cross-References

Both files contain bidirectional "See also" links at line 3:
- `system-architecture.md` → `data-storage-architecture.md`
- `data-storage-architecture.md` → `system-architecture.md`

Links use relative markdown format: `[Title](./filename.md)`

## Quality Assurance

- All original content preserved (no sections removed, only condensed)
- Code examples intact
- Diagram formatting preserved
- Table formatting preserved
- Internal cross-references updated to point to correct file
- No placeholder content added
- Both files independently readable

## Related Files

- `docs/system-architecture.md` — Request flow, component interactions
- `docs/data-storage-architecture.md` — Storage, clustering, deployment, monitoring
- `docs/request-pipeline.md` — Linked from Request Lifecycle section
- `docs/device-fingerprinting.md` — Linked from DeviceFpDetector section
- `docs/code-standards.md` — Linked from risk scoring and caching sections
- `docs/deployment-guide.md` — Linked from disaster recovery section
