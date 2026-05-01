# Brainstorm Report — FR-007 Relay & Proxy Detection

**Date:** 2026-05-01
**Requirement:** FR-007 (P0, Mandatory)
**Source spec:** `analysis/requirements.md` line 47
**Target:** Production-ready (not MVP/POC)

---

## 1. Problem Statement

Implement Relay & Proxy Detection for the Mini WAF: proxy chain detection, X-Forwarded-For validation, ASN classification (residential/datacenter/Tor). Must integrate with cumulative risk scoring (FR-025/026), be configured via YAML with hot-reload, follow an extensible design pattern, and reach ≥90% test coverage.

## 2. Acceptance Criteria Mapping

| Criterion | Mechanism |
|---|---|
| Proxy chain detection | `ProxyChainAnalyzer` provider → effective hop count after trusted-CIDR strip → `ExcessiveHopDepth(n)` signal |
| X-Forwarded-For validation | `XffValidator` provider → parse XFF + X-Real-IP, strip trusted CIDRs, detect spoof/malformed/private-mid-chain |
| ASN classification (residential/datacenter/Tor) | `AsnClassifier` (IPinfo Lite mmdb + DC override list) + `TorExitMatcher` (HashSet) |
| YAML rules + hot reload | YAML config watched via existing `notify`-based reloader → `ArcSwap<RelayConfig>` |
| Extensible design pattern | Strategy + Registry: `SignalProvider` trait, providers registered from YAML |
| 90% test coverage | Unit + integration + proptest + wiremock + CI gate (`cargo llvm-cov`) |

## 3. Approaches Evaluated

### A. Inline check module under `checks/` (rejected)
Mirror existing `checks/owasp.rs`. Pro: consistent. Con: couples detection to rule evaluation, hard to unit-test signal emission in isolation, no clean extension point.

### B. Pingora middleware filter in `gateway/proxy.rs` (rejected)
Hook directly. Pro: fastest path. Con: hardest to test, mixes transport concerns w/ detection logic, blocks future reuse for non-HTTP paths.

### C. **Dedicated detector trait, pre-rule-engine (selected)**
New `relay/` module owning `RelayDetector`. Runs early, attaches `ClientIdentity` to request context. Rule engine + risk scorer consume signals. Clean separation, highly testable, future-proof.

## 4. Final Design

### 4.1 Architecture
```
peer_ip + headers ─► RelayDetector ─► ClientIdentity{ real_ip, asn_class, signals[] }
                          ▲                             │
                  Arc<RelayConfig> (YAML)               ▼
                  Arc<TorSet>                  RuleEngine ─► RiskScorer ─► Action
                  Arc<AsnDb>  (mmap)
```

### 4.2 Module Layout
```
crates/waf-engine/src/relay/
├── mod.rs              # RelayDetector facade + ClientIdentity
├── config.rs           # YAML schema (serde)
├── reload.rs           # plugs into access/reload.rs notify watcher
├── signal.rs           # Signal enum + SignalProvider trait
├── registry.rs         # provider registration / dispatch
├── providers/
│   ├── xff_validator.rs
│   ├── proxy_chain.rs
│   ├── asn_classifier.rs
│   └── tor_exit.rs
└── intel/
    ├── mod.rs          # IntelProvider trait
    ├── tor_feed.rs     # tokio task: HTTP fetch w/ ETag → atomic file swap
    ├── asn_feed.rs     # IPinfo Lite mmdb refresh (primary)
    └── asn_feed_iptoasn.rs  # iptoasn.com TSV (offline-friendly fallback)
```

### 4.3 Core Trait (Strategy + Registry)
```rust
pub trait SignalProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn evaluate(&self, ctx: &RelayCtx) -> Vec<Signal>;
}

pub trait IntelProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn refresh(&self) -> Result<RefreshOutcome>;
}
```
New intel source / signal = `impl trait` + register in YAML. No core changes.

### 4.4 Signals
`XffSpoofPrivate`, `XffMalformed`, `XffTooLong`, `ExcessiveHopDepth(n)`, `AsnDatacenter{asn,org}`, `AsnResidential`, `AsnUnknown`, `TorExit`. Each maps to a configurable `risk_score_delta` consumed by FR-025/026. **No hardcoded blocking** — composable with rule engine + risk thresholds.

### 4.5 ASN Data Source (revised — license-clean stack)
- **Primary:** **IPinfo Lite mmdb** (free, no license key, daily URL, `maxminddb` crate compatible)
- **Offline fallback:** **iptoasn.com** TSV (public domain, no auth, trivial parser)
- **Datacenter classification:** hyperscaler official published ranges (AWS/GCP/Azure/OCI/DO/OVH/Hetzner JSON) + **X4BNet/lists-datacenter** (MIT) + operator override YAML, merged at load
- **MaxMind GeoLite2-ASN:** supported via same `IntelProvider` trait but not default (license-key friction)

### 4.6 YAML Config (hot-reloaded)
```yaml
relay_detection:
  trusted_proxies:
    - 10.0.0.0/8
    - 173.245.48.0/20    # cloudflare sample
  max_chain_depth: 3
  headers:
    forwarded_for: [X-Forwarded-For, X-Real-IP]
  asn:
    provider: ipinfo_lite          # ipinfo_lite | iptoasn | maxmind
    mmdb_path: /var/lib/waf/ipinfo-lite.mmdb
    datacenter_lists:
      - /etc/waf/intel/x4bnet-datacenter.txt
      - /etc/waf/intel/hyperscaler-ranges.yaml
      - /etc/waf/intel/operator-overrides.yaml
    refresh:
      url: https://ipinfo.io/data/free/country_asn.mmdb
      interval: 24h
      etag: true
  tor:
    list_path: /var/lib/waf/tor-exit.txt
    refresh:
      url: https://check.torproject.org/torbulkexitlist
      interval: 1h
      etag: true
  signals:
    enabled: [xff_validator, proxy_chain, asn_classifier, tor_exit]
    risk_score_delta:
      xff_spoof_private: 30
      xff_malformed: 15
      xff_too_long: 10
      excessive_hop_depth: 20
      asn_datacenter: 25
      tor_exit: 50
      asn_residential: 0
```

### 4.7 Hot Reload
- Reuse `crates/waf-engine/src/access/reload.rs` `notify`-based watcher
- `ArcSwap<RelayConfig>` for config; `ArcSwap<TorSet>`, `ArcSwap<AsnDb>` for data
- Refresh tasks write `*.tmp` then `rename(2)` → watcher fires → atomic swap
- Per FR-031 (dashboard hot config): NO service restart required

### 4.8 Performance Budget
- IP-in-CIDR via `iprange` (already a workspace dep), O(log n)
- ASN lookup: `maxminddb` mmap, O(1)
- Tor set: `HashSet<IpAddr>` behind `ArcSwap`, O(1)
- Per-request target: <50µs (vs 5ms p99 NFR)

### 4.9 Failure Modes (FR-036/037 alignment)
- mmdb unreadable at startup on CRITICAL-tier-bound deploy → fail-close, refuse to start
- mmdb refresh fails post-startup → keep last good DB, warn, continue
- Tor list missing → degraded mode (skip TorExitMatcher, log warn)
- Outbound HTTP refresh blocked (air-gap) → file-only mode auto-detected when `refresh.url` absent

### 4.10 Integration Points
- `gateway/proxy.rs`: invoke `RelayDetector::evaluate()` early, attach `ClientIdentity` to request ctx
- `waf-engine/rules/engine.rs`: rule predicates match `signals.contains(...)`, `asn_class == "datacenter"`, `chain_depth > N`
- Risk scorer (FR-025): consume `signals[].risk_score_delta`
- Audit log (FR-032): emit signals + asn_class + real_ip per request
- Dashboard (FR-029/030): visualize ASN breakdown + Tor hit rate + chain-depth heatmap

## 5. Test Strategy (≥90% coverage, `cargo llvm-cov` gate in CI)

| Layer | Tooling | Scope |
|---|---|---|
| Unit | `#[test]` table-driven | Each provider in isolation |
| Property | `proptest` | XFF parser robustness (IPv6 brackets, zone IDs `fe80::1%eth0`, port suffixes, quoted strings, header folding) |
| Integration | `tokio::test` | End-to-end `RelayDetector::evaluate` with canned (peer_ip, headers, config) |
| Hot reload | `tempfile` + `notify` | Write file → assert in-flight requests see new config within ≤1s |
| Refresh tasks | `wiremock` | ETag honored, 304 short-circuit, atomic swap, partial-read prevention |
| Adversarial | hand-rolled | Trusted-proxy-spoof tail, double XFF header, RFC1918 mid-chain, oversized chain (DoS), Unicode header smuggling |
| Performance | `criterion` | <50µs per evaluate(), regression bench |
| Coverage gate | CI | Fail PR if `relay/*` < 90% line coverage |

## 6. Risks & Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Trusted-proxy stripping bug → real_ip confusion | **CRITICAL** | Exhaustive adversarial test suite; property tests; explicit invariants documented |
| ASN data feed compromised / wrong | High | Pin ETag + content-length sanity check; signature verification where vendor supports it; operator override list always wins |
| XFF parser DoS (giant header) | High | Hard cap header size (8KB) + entry count (32) before parse |
| Datacenter list staleness → false positives on legit cloud users | Medium | Operator override YAML; per-route exemption; risk delta not block |
| Outbound HTTP refresh in air-gap | Medium | File-only mode auto-detected; ops drop file via Ansible/cron |
| IPv6 edge cases | Medium | proptest fuzz + RFC 4291 canonicalization in parser |

## 7. Success Metrics

- All 6 acceptance-criterion mappings pass dedicated integration tests
- `cargo llvm-cov` reports ≥90% line + branch coverage for `relay/*`
- p99 RelayDetector latency <50µs on `criterion` bench (i7 baseline)
- Hot-reload propagation ≤1s file-write to live request
- Zero `.unwrap()` / `todo!()` in `relay/*` (per Seven Iron Rules)
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean

## 8. Implementation Considerations

- New crate dep additions: `maxminddb` (already may be present via geoip), `iprange`, `arc-swap`, `proptest` (dev), `wiremock` (dev), `criterion` (dev). Verify before adding.
- Module sized to keep files <200 LOC per CLAUDE.md (likely 8-12 files in `relay/`)
- Reuse, don't duplicate: `access/reload.rs` watcher abstraction; `geoip.rs` mmdb mmap pattern if applicable
- Documentation impact (`docs/`): `system-architecture.md`, `request-pipeline.md`, `custom-rules-syntax.md`, `deployment-guide.md` (intel feed setup), `code-standards.md` (if new patterns introduced)

## 9. Next Steps / Dependencies

- **Decision input needed:** seed datacenter ASN list scope (hyperscalers only, or include X4BNet bulk import?)
- **Upstream dep:** Risk Scorer interface (FR-025) shape — coordinate signal-delta contract
- **Upstream dep:** Request context type defined by gateway proxy — coordinate where `ClientIdentity` is attached

## 10. Unresolved Questions

1. Initial datacenter ASN seed: bundle hyperscaler-only minimal seed in repo, or pull X4BNet at first start? (Recommend: minimal hyperscaler seed in `rules/threat-intel/`, X4BNet as optional refresh feed.)
2. mmdb missing at startup — does CRITICAL fail-close apply globally or only to CRITICAL tier routes? (Suggest per-tier configurable, default: refuse-start when any CRITICAL route enabled.)
3. Should `Forwarded` (RFC 7239) header be in scope for v1, or queued as future provider? (Current answer: out of scope — trait makes it additive.)
4. License-key handling for MaxMind path (kept as alt provider): env var or sealed-secret file? (Suggest env var w/ fallback to file path, no logging.)
