---
name: FR-010 Device Fingerprinting
slug: fr010-device-fingerprinting
status: pending
created: 2026-05-01
priority: P0
blockedBy: []
blocks: []
relatedReports:
  - plans/reports/brainstorm-260501-2005-fr010-device-fingerprinting.md
---

# FR-010 Device Fingerprinting — Implementation Plan

**Spec:** `analysis/requirements.md` line 50 (FR-010, P0 mandatory)
**Brainstorm:** `plans/reports/brainstorm-260501-2005-fr010-device-fingerprinting.md`
**Pattern reference:** FR-007 `relay/` module (Strategy + Registry)

## Goal

Device fingerprinting subsystem covering JA3/JA4 TLS fingerprint, full Akamai HTTP/2 fingerprint, User-Agent entropy/churn, and "same device switching IPs" detection. YAML hot-reload, trait-driven extension, ≥90% test coverage. Production-ready.

## Architecture (Summary)

```
TLS handshake ──► TlsCapture (rustls hook)  ┐
                                              ├──► FingerprintAssembler ──► DeviceIdentity
H2 frames    ──► H2FrameTap (h2 layer)      ┘                                    │
                                                                                  ▼
              Arc<DeviceFpConfig> (YAML)                              IdentityStore (Memory|Redis)
              Arc<dyn IdentityStore>                                              │
                                                                                  ▼
                                                                          SignalProvider chain
                                                                                  │
                                                                                  ▼
                                                                          RiskAggregator (trait)
```

Module: `crates/waf-engine/src/device_fp/`. See brainstorm §4.2 for full layout.

## Phases

| # | Phase | Status | Effort |
|---|---|---|---|
| 01 | Pingora inspector primitives (Option B — L4 byte tap) | **completed** | S |
| 02 | Module skeleton, traits, YAML schema, hot reload | **completed** | M |
| 03 | Capture layer (TLS + h2) + fixtures | **completed (deferred: real-client captures + gateway wiring)** | M |
| 04 | Fingerprint providers: JA3, JA4, h2 Akamai | **completed (deferred: golden vectors + property tests + benches)** | M |
| 05 | IdentityStore trait + Memory impl + conformance suite | **completed (deferred: bloom prefilter + bench)** | S |
| 06 | Signal providers (5x) | **completed (deferred: integration stream test + <100µs bench)** | M |
| 07 | RiskAggregator trait + Noop default + wiring | pending | S |
| 08 | IdentityStore Redis impl (feature-flagged) | pending | S |
| 09 | Coverage gate, perf bench, docs sync | pending | S |
| 03-sub | Capture sub-phase: real-client fixtures + gateway listener patch | pending | M |

## Key Decisions (from brainstorm)

- **Pingora hook strategy:** custom patch via Cargo git pin; hooks expose ClientHello bytes + h2 frames pre-END_HEADERS
- **Identity store:** trait + 2 impls in v1 (Memory default, Redis behind feature flag `redis-store`)
- **Risk integration:** signal-only via `RiskAggregator` trait w/ `NoopAggregator` default; FR-025 plugs in later
- **UA entropy:** statistical (Shannon + churn) + YAML blocklist
- **H2 fingerprint:** full Akamai (SETTINGS + WINDOW_UPDATE + PRIORITY + pseudo-header order)
- **Hot reload:** `ArcSwap<DeviceFpConfig>` + existing `notify` watcher

## Performance Budget

p99 added latency < 300µs at 5k req/s. ClientHello hash <50µs, H2 hash <30µs, store observe <10µs, signals <100µs.

## Success Criteria

- All 4 AC mechanisms operational on real TLS+H2 traffic
- `cargo llvm-cov` coverage ≥90% lines on `device_fp/` (CI gated)
- Hot reload <1s, zero dropped requests
- Conformance suite passes for Chrome/Firefox/Safari/curl/curl-impersonate fixtures
- Memory + Redis store both pass shared trait conformance suite
- Backend toggle = config-only, no recompile
- p99 latency add <300µs at 5k req/s bench

## Risks

See brainstorm §5. Top three: Pingora patch upkeep (mitigation: pinned rev + conformance CI), DashMap memory under DDoS (TTL + cardinality cap + bloom pre-check), Redis latency spike (timeout + circuit breaker + degrade to memory).

## Unresolved Questions

1. Pingora fork hosting: org-owned vs `[patch.crates-io]` — affects CI/license
2. Redis topology v2: single / sentinel / cluster — affects sharding
3. PII: persist raw UA or hash only — compliance posture
4. `fp_conflict` session resolver: per-route YAML vs central interface
5. JA4+ extended (JA4S/JA4H/JA4X): v1 scope?
6. Coverage gate: per-crate or workspace-aggregate?
