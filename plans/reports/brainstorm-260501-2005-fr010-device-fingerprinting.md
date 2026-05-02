# Brainstorm Report — FR-010 Device Fingerprinting

**Date:** 2026-05-01
**Requirement:** FR-010 (P0, Mandatory)
**Source spec:** `analysis/requirements.md` line 50
**Target:** Production-ready (not MVP/POC)
**Reference pattern:** FR-007 (`relay/` Strategy + Registry) — `plans/reports/brainstorm-260501-1957-fr007-relay-proxy-detection.md`

---

## 1. Problem Statement

Build device fingerprinting subsystem: JA3/JA4 TLS fingerprint, full Akamai-style HTTP/2 fingerprint, User-Agent entropy/churn analysis, and "same device switching IPs" detection. YAML-configured w/ hot reload, extensible via traits, ≥90% test coverage, integrates w/ cumulative risk scoring (FR-025/026) when available.

## 2. Acceptance Criteria → Mechanism

| AC | Mechanism |
|---|---|
| TLS fingerprint (JA3/JA4) | `TlsCapture` rustls/boring `ClientHello` callback → bytes → `Ja3Hasher`/`Ja4Hasher` providers → fingerprint string attached to conn |
| HTTP/2 settings fingerprint | `H2FrameTap` Pingora h2 layer hook captures SETTINGS + WINDOW_UPDATE + PRIORITY tree + pseudo-header order → Akamai-format hash |
| User-Agent entropy | `UaEntropyProvider`: per-fingerprint UA-set sliding window + Shannon entropy + length/charset heuristics |
| Detect same device switching IPs | `IdentityStore` trait: `observe(fp_key, ip, ts)` → emits `IpHopping{count, window}` when distinct IPs > threshold per fp |
| YAML + hot reload | `device_fp.yaml` → `ArcSwap<DeviceFpConfig>`, watched via existing `notify` reloader (shared w/ FR-007) |
| Extensible design | Strategy + Registry: `FingerprintProvider` + `SignalProvider` traits, YAML-driven registration |
| 90% coverage | Unit + proptest (fp stability) + integration (rustls test handshakes, h2 frame fixtures) + `cargo llvm-cov` CI gate |

## 3. Approaches Evaluated

### A. Inline check module (rejected)
Add `checks/device_fp.rs`. Fast to add, but fingerprint capture happens at TLS/h2 layer well before rule eval — wrong layer, untestable in isolation.

### B. Sidecar fingerprinting service (rejected)
Out-of-process JA4 daemon over UDS. Decouples but adds correlation problem (5-tuple→request) and latency hit vs the p99 ≤ 5ms budget.

### C. Trust upstream proxy headers (rejected)
HAProxy/Envoy injects `X-JA4`. Simpler but adds infra dep, weakens trust boundary, and doesn't satisfy "production-ready" credibility.

### D. **Dedicated `device_fp/` module + Pingora patch (selected)**
Mirror FR-007's relay module pattern. Custom Pingora patch exposes `on_client_hello` and `on_h2_frames` hooks. Module owns capture → providers → identity store → signals. Clean, testable, extensible. Upgrade-pinned via Cargo path/git tag.

## 4. Final Design

### 4.1 Architecture

```
TLS handshake ──► TlsCapture (rustls hook) ──┐
                                              ├──► FingerprintAssembler ──► DeviceIdentity{ ja3, ja4, h2_hash, ua, ip }
H2 frames    ──► H2FrameTap   (h2 layer)  ───┘                                       │
                                                                                      ▼
                  Arc<DeviceFpConfig> (YAML)                                  IdentityStore (Memory|Redis)
                  Arc<dyn IdentityStore>                                              │
                                                                                      ▼
                                                                              SignalProvider chain
                                                                                      │
                                                                                      ▼
                                                                              RiskAggregator (trait)
                                                                                      │
                                                                                      ▼
                                                                            RuleEngine / RiskScorer
```

### 4.2 Module Layout

```
crates/waf-engine/src/device_fp/
├── mod.rs                  # DeviceFpDetector facade + DeviceIdentity
├── config.rs               # YAML schema (serde) + validation
├── reload.rs               # ArcSwap + notify integration
├── capture/
│   ├── tls.rs              # rustls ClientHello callback → JA3/JA4 raw
│   ├── h2.rs               # Pingora h2 frame tap → Akamai hash raw
│   └── conn_ctx.rs         # per-connection bag holding raw capture
├── fingerprint/
│   ├── ja3.rs              # canonical JA3 hash (md5)
│   ├── ja4.rs              # JA4 (a/b/c/d/h/x variants)
│   ├── h2_akamai.rs        # SETTINGS|WINDOW|PRIORITY|PSEUDO formatter
│   └── trait.rs            # FingerprintProvider trait
├── signal.rs               # Signal enum (re-uses FR-007 Signal where overlap)
├── providers/
│   ├── fp_conflict.rs      # same fp, multiple session/cookie identities
│   ├── ip_hopping.rs       # same fp, N distinct IPs in window
│   ├── ua_entropy.rs       # Shannon entropy + UA-churn per fp
│   ├── ua_blocklist.rs     # YAML regex/exact bad UA list
│   └── h2_anomaly.rs       # known bot h2 hashes (curl-impersonate, gorequest)
├── identity/
│   ├── trait.rs            # IdentityStore async trait
│   ├── memory.rs           # DashMap + tokio TTL janitor (v1 default)
│   └── redis.rs            # redis-rs cluster client (feature = "redis-store")
└── registry.rs             # Provider registration / dispatch
```

### 4.3 Core Traits

```rust
pub trait FingerprintProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn compute(&self, raw: &RawCapture) -> Option<FingerprintValue>;
}

pub trait SignalProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn evaluate<'a>(&self, ctx: &'a DeviceCtx<'a>) -> Vec<Signal>;
}

#[async_trait::async_trait]
pub trait IdentityStore: Send + Sync {
    async fn observe(&self, key: &FpKey, ip: IpAddr, ua: &str, ts: i64) -> Result<Observation>;
    async fn lookup(&self, key: &FpKey) -> Result<Option<IdentityRecord>>;
    async fn purge_expired(&self) -> Result<usize>;
}

#[async_trait::async_trait]
pub trait RiskAggregator: Send + Sync {
    async fn submit(&self, key: &FpKey, signals: &[Signal]);
}
```

Adding a new fp algorithm = `impl FingerprintProvider`. New behavioral signal = `impl SignalProvider`. New backing store = `impl IdentityStore`. No core changes.

### 4.4 YAML Schema (excerpt)

```yaml
device_fp:
  enabled: true
  capture:
    tls:
      enabled: true
      algorithms: [ja3, ja4]
    h2:
      enabled: true
      hash: akamai
  store:
    backend: memory          # memory | redis
    ttl_secs: 3600
    redis:
      url: "redis://..."     # only if backend=redis
      key_prefix: "wafp:"
  providers:
    - name: ip_hopping
      window_secs: 600
      max_distinct_ips: 3
      signal_weight: 25
    - name: ua_entropy
      window_secs: 1800
      max_distinct_ua: 4
      min_shannon: 2.5
      signal_weight: 15
    - name: ua_blocklist
      patterns: ["^curl/", "python-requests", "Go-http-client"]
      signal_weight: 30
    - name: h2_anomaly
      bad_hashes: ["46cc8...", "..."]
      signal_weight: 40
    - name: fp_conflict
      session_cookie: "SID"
      signal_weight: 35
  hot_reload: true
```

Hot reload swaps `Arc<DeviceFpConfig>` atomically; provider registry rebuilt on swap; no in-flight request disruption.

### 4.5 Pingora Patch Strategy

- Cargo dependency pinned: `pingora = { git = "...", branch = "mini-waf/device-fp-hooks", rev = "<sha>" }`
- Patch surfaces two extension points:
  1. `set_client_hello_inspector(Arc<dyn ClientHelloInspector>)` — invoked synchronously during rustls/boring handshake, receives raw ClientHello bytes + parsed extensions
  2. `set_h2_frame_inspector(Arc<dyn H2FrameInspector>)` — fires per-frame for SETTINGS / WINDOW_UPDATE / PRIORITY / HEADERS until first END_HEADERS, then detaches
- Hooks store raw capture into a per-connection slot (slab keyed by conn id) read by HTTP request filter
- Document in `docs/system-architecture.md` w/ upgrade SOP (rebase patch on Pingora release, run conformance test suite)

### 4.6 v1 → v2 Identity Store Path

- v1 ships **both** `MemoryIdentityStore` (default) and `RedisIdentityStore` (feature flag `redis-store`, off by default)
- Config selects backend; switching is a config + restart, no code change
- v2 = enable redis flag in build, point cluster at redis, swap config; same trait, zero call-site change
- Cluster sync (FR-044) reuses redis store directly when present

### 4.7 Risk Aggregator Bridge

- Define `RiskAggregator` trait now w/ `NoopAggregator` default implementation
- Module emits signals to whatever aggregator is registered
- When FR-025 lands, real `CumulativeRiskScorer` registers itself — zero churn in `device_fp/`

### 4.8 Performance Budget

| Stage | Target | Strategy |
|---|---|---|
| ClientHello → JA3/JA4 | < 50µs | Single allocation, precomputed grease set, `smallvec` for cipher list |
| H2 frame hash | < 30µs | Inline string builder, freeze on first END_HEADERS |
| Memory store observe | < 10µs | DashMap shard + atomic tick |
| Signal evaluation | < 100µs total | Providers iterate once, short-circuit on score cap |

Total fingerprint pipeline overhead target: **< 300µs p99**, leaving room under the 5ms global budget.

### 4.9 Test Strategy (≥90% coverage)

- **Unit**: each provider w/ canned `RawCapture`; IdentityStore impls share trait conformance suite
- **Property**: `proptest` invariant — same ClientHello bytes → same JA4; permutation of GREASE values → identical hash
- **Fixture**: real captured ClientHellos from Chrome/Firefox/Safari/curl/curl-impersonate/Go/Python committed under `tests/fixtures/clienthellos/`
- **Integration**: spawn rustls server w/ patched Pingora, drive real TLS handshakes, assert fingerprint
- **H2 fixtures**: raw frame byte streams parsed into expected Akamai hash
- **Hot reload**: write new YAML → assert provider set swapped within 1s, in-flight requests unaffected
- **Redis store**: testcontainers-rs Redis 7 + same conformance suite as memory
- CI gate: `cargo llvm-cov --workspace --fail-under-lines 90`

## 5. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Pingora upstream changes break patch | Pin to rev; conformance suite in CI; documented rebase SOP; abstraction layer hides Pingora types from `device_fp/` |
| JA4 spec drift | Use FoxIO reference vectors as golden tests; version the algorithm (`ja4_v1`) in config |
| TLS 1.3 ClientHello has fewer signals | JA4 already accounts for this; combine w/ h2 + UA + behavioral |
| GREASE non-determinism | JA4 spec strips GREASE; covered by property test |
| DashMap memory growth under DDoS | TTL janitor + max-cardinality cap + bloom-filter pre-check; DDoS path emits coarse signal w/o storing |
| Redis latency spike → p99 breach | `tokio::time::timeout` per-call + circuit breaker; degrade to memory store + log |
| False positives on shared NAT (corp/mobile) | `fp_conflict` only triggers on session-cookie mismatch, not ip-hopping alone; weights tuned conservatively in YAML |
| h2 hook ordering w/ Pingora's own h2 logic | Hook fires read-only on owned frame copies; Pingora processing untouched |

## 6. Success Metrics

- All 4 AC mechanisms wired end-to-end on real TLS+H2 traffic
- Coverage ≥ 90% (lines) on `device_fp/` per `cargo llvm-cov`
- p99 added latency < 300µs at 5k req/s under bench
- Hot reload completes < 1s; zero dropped requests
- Conformance suite passes for Chrome/Firefox/Safari/curl/curl-impersonate fixtures
- IdentityStore conformance suite passes for memory + redis
- Redis backend toggles via config alone — no recompile

## 7. Implementation Phasing (for follow-up `/ck:plan`)

1. Pingora patch (ClientHello + h2 hooks) + Cargo pin + CI build
2. `device_fp/` module skeleton, traits, YAML schema, hot-reload integration
3. Capture layer: `tls.rs`, `h2.rs`, raw fixtures + tests
4. Fingerprint providers: JA3, JA4, h2 Akamai + golden tests
5. IdentityStore trait + Memory impl + conformance suite
6. Signal providers: ip_hopping, ua_entropy, ua_blocklist, h2_anomaly, fp_conflict
7. RiskAggregator trait + Noop default + signal wiring
8. IdentityStore Redis impl behind feature flag + testcontainers tests
9. Coverage gate, perf bench, docs sync (`docs/system-architecture.md`, new `docs/device-fingerprinting.md`)

## 8. Next Steps

- Approve this design
- `/ck:plan` to generate phased implementation plan under `plans/260501-2005-fr010-device-fingerprinting/`
- Reserve a Pingora fork repo + initial patch PR before phase-1

## 9. Unresolved Questions

1. Pingora fork: maintain in `future-and-go` org or fork-and-patch via `[patch.crates-io]`? Affects CI + license obligations.
2. Redis topology assumption — single instance, sentinel, or cluster mode for v2? Affects key sharding strategy.
3. Privacy/PII: should raw User-Agent strings be persisted in `IdentityRecord`, or only hashed? Affects compliance posture.
4. Should `fp_conflict` provider read session cookies (often app-specific) from YAML per-route, or expect a centralized `session_id_resolver` interface?
5. JA4+ extended variants (JA4S server-side, JA4H HTTP, JA4X cert) — in scope for v1 or future?
6. Coverage gate enforcement — 90% per-crate or workspace-aggregate?
