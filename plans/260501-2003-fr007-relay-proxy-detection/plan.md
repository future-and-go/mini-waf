---
title: "FR-007 Relay & Proxy Detection — Implementation"
description: "Detect relay/proxy traffic via XFF validation, proxy-chain depth, ASN classification (residential/datacenter/Tor). YAML hot-reload, ArcSwap. Strategy + Registry + IntelProvider patterns. ≥90% coverage gate."
status: in-progress
priority: P0
effort: 5d (6/8 phases complete)
branch: feat/fr-007
tags: [waf, relay-detection, xff, asn, tor, hot-reload, fr-007]
created: 2026-05-01
blockedBy: []
blocks: []
---

## Source

Design (decisions LOCKED — module layout, traits, signals, YAML, intel sources):
[`../reports/brainstorm-260501-1957-fr007-relay-proxy-detection.md`](../reports/brainstorm-260501-1957-fr007-relay-proxy-detection.md)

Requirements: `analysis/requirements.md` line 47 (FR-007).

Upstream / reuse:
- Hot-reload watcher: `crates/waf-engine/src/access/reload.rs` (FR-008, shipped)
- mmdb pattern: `crates/waf-engine/src/geoip.rs`
- Request ctx + pipeline: `crates/gateway/src/proxy.rs`, `pipeline/`
- Workspace deps already present: `iprange`, `arc-swap`, `notify`, `serde_yaml`, `tokio`, `tracing`

## Scope

In-scope (closes FR-007 acceptance, brainstorm §2):
- XFF / X-Real-IP parser + validator (incl. IPv6 zone IDs, brackets, ports)
- Trusted-proxy CIDR strip + effective hop-depth signal
- ASN classifier: IPinfo Lite mmdb (primary), iptoasn TSV (fallback), MaxMind GeoLite2-ASN (alt)
- Datacenter override merge (hyperscaler ranges + X4BNet + operator YAML)
- Tor exit matcher + intel refresh (HTTP w/ ETag, atomic rename swap)
- YAML config hot-reload via `ArcSwap<RelayConfig>`, `ArcSwap<TorSet>`, `ArcSwap<AsnDb>`
- Pipeline integration: `RelayDetector::evaluate` early in `proxy.rs` → `ClientIdentity` on ctx
- Rule-engine signal predicates + risk-scorer delta consumption (FR-025/026)

Out-of-scope (deferred):
- RFC 7239 `Forwarded` header (additive via SignalProvider trait)
- MaxMind license-key vault integration beyond env-var/file
- Dashboard ASN visualization (FR-029/030 — separate ticket)

## Acceptance Criteria → Phase Map

| AC | Mechanism | Phase |
|---|---|---|
| Proxy chain detection | `ProxyChainAnalyzer` → `ExcessiveHopDepth(n)` | 02 |
| XFF validation | `XffValidator` → `XffSpoofPrivate`/`XffMalformed`/`XffTooLong` | 02 |
| ASN residential/datacenter | `AsnClassifier` mmdb + DC override | 03 |
| Tor exit | `TorExitMatcher` + refresh task | 04 |
| YAML rules + hot reload | `notify` watcher + ArcSwap | 01, 05 |
| Extensible design | `SignalProvider`/`IntelProvider` traits + registry | 01 |
| ≥90% test coverage | `cargo llvm-cov` CI gate | 07 |

## Module Layout

```
crates/waf-engine/src/relay/
├── mod.rs              ── RelayDetector facade + ClientIdentity
├── config.rs           ── YAML serde schema + builder
├── signal.rs           ── Signal enum + SignalProvider trait
├── registry.rs         ── provider registration / dispatch
├── reload.rs           ── plugs into access/reload.rs notify
├── providers/
│   ├── mod.rs
│   ├── xff_validator.rs
│   ├── proxy_chain.rs
│   ├── asn_classifier.rs
│   └── tor_exit.rs
└── intel/
    ├── mod.rs          ── IntelProvider trait + RefreshOutcome
    ├── tor_feed.rs     ── HTTP fetch w/ ETag → atomic swap
    ├── asn_feed.rs     ── IPinfo Lite mmdb (primary)
    └── asn_feed_iptoasn.rs ── iptoasn.com TSV (fallback)
```

Gateway integration: `crates/gateway/src/proxy.rs` (invoke detector), `crates/gateway/src/context.rs` (attach `ClientIdentity`).
Rule engine: `crates/waf-engine/src/rules/engine.rs` (signal predicates).

## Phases

| # | File | Owner files | Status | ACs |
|---|------|-------------|--------|-----|
| 01 | [phase-01-skeleton-and-config.md](phase-01-skeleton-and-config.md) | `relay/{mod,config,signal,registry}.rs`, Cargo.toml | completed | parse, traits |
| 02 | [phase-02-xff-and-proxy-chain.md](phase-02-xff-and-proxy-chain.md) | `relay/providers/{xff_validator,proxy_chain}.rs` | completed | XFF, hop-depth |
| 03 | [phase-03-asn-classifier.md](phase-03-asn-classifier.md) | `relay/providers/asn_classifier.rs`, `relay/intel/{asn_feed,asn_feed_iptoasn,datacenter_set}.rs` | completed | ASN |
| 04 | [phase-04-tor-exit-and-intel-refresh.md](phase-04-tor-exit-and-intel-refresh.md) | `relay/providers/tor_exit.rs`, `relay/intel/{mod,tor_feed}.rs` | completed | Tor, refresh |
| 05 | [phase-05-hot-reload-wiring.md](phase-05-hot-reload-wiring.md) | `relay/reload.rs`, ArcSwap glue | completed | hot-reload |
| 06 | [phase-06-gateway-rule-integration.md](phase-06-gateway-rule-integration.md) | `gateway/proxy.rs`, `gateway/context.rs` | complete (core), pending (rule engine) | detector integration, R/O for now |
| 07 | [phase-07-tests-bench-coverage.md](phase-07-tests-bench-coverage.md) | `crates/waf-engine/tests/relay_*`, `benches/relay_eval.rs` | complete (with deferrals) | tests, bench, deferred CI gates |
| 08 | [phase-08-docs-sync.md](phase-08-docs-sync.md) | `docs/{system-architecture,request-pipeline,custom-rules-syntax,deployment-guide}.md` | pending | docs |

## Integration Notes

- `RelayDetector::evaluate(peer_ip, headers, cfg)` called BEFORE rule engine in `proxy.rs::request_filter` (or earliest pipeline phase that has headers).
- Output `ClientIdentity { real_ip: IpAddr, asn_class: AsnClass, asn: Option<u32>, signals: Vec<Signal> }` attached to request ctx.
- FR-008 already merged: post-FR-007, FR-008's `RequestCtx.client_ip` SHOULD consume `ClientIdentity.real_ip` instead of `peer_ip` (one-line change, tracked in phase-06).
- Risk scorer (FR-025): per-signal `risk_score_delta` from YAML; detector emits signals only — no blocking decision here.
- Audit log (FR-032): emit `signals[]`, `asn_class`, `real_ip` per request.

## Key Dependencies

Workspace already has: `iprange`, `arc-swap`, `notify`, `serde`, `serde_yaml`, `tokio`, `tracing`, `anyhow`.
Verify-then-add (per phase):
- `maxminddb` — phase-03 (likely already via `geoip.rs`; check before add)
- `proptest` — phase-07 dev-dep
- `wiremock` — phase-07 dev-dep
- `criterion` — phase-07 dev-dep

## Success Criteria (consolidated)

1. All AC mappings pass dedicated integration tests (`cargo test -p waf-engine relay_`, `cargo test -p gateway relay_e2e`).
2. `cargo llvm-cov --package waf-engine --lcov` ≥90% line+branch on `src/relay/**`.
3. `cargo bench -p waf-engine relay_eval` p99 <50µs/evaluate on i7 baseline.
4. Hot-reload propagation ≤1s from file write to live request.
5. `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
6. `cargo fmt --all -- --check` clean.
7. Zero `.unwrap()` / `todo!()` / `unimplemented!()` in `relay/*` (grep gate).
8. Each `relay/` source file ≤200 LOC (CLAUDE.md modularization rule).

## Risks Summary (full table → brainstorm §6)

| Risk | Sev | Mitigation phase |
|---|---|---|
| Trusted-proxy strip bug → wrong `real_ip` | CRITICAL | 02 (proptest + adversarial), 07 |
| ASN feed compromise / wrong | High | 03/04 (ETag pin + content-length sanity + operator override wins) |
| XFF parser DoS (giant header) | High | 02 (8KB header cap, 32-entry chain cap) |
| DC list staleness → false positives | Medium | 03 (operator override YAML, risk delta not block) |
| Air-gap refresh failure | Medium | 04 (file-only mode auto when `refresh.url` absent) |
| IPv6 edge cases | Medium | 02 (proptest + RFC 4291 canonicalization) |

## Open Questions (from brainstorm §10)

1. **Initial datacenter ASN seed scope** — bundle hyperscaler-only minimal seed in `rules/threat-intel/`, X4BNet as optional refresh feed? (Recommend yes; resolve in phase-03.)
2. **mmdb-missing CRITICAL fail-close** — global refuse-start, or per-tier conditional (only when CRITICAL routes enabled)? (Recommend per-tier configurable; resolve in phase-03.)
3. **RFC 7239 `Forwarded` header** — v1 or queued as future provider? (Current: out-of-scope; trait keeps it additive.)
4. **MaxMind license-key handling** — env var with file fallback, no logging? (Resolve in phase-03 if MaxMind path enabled.)
