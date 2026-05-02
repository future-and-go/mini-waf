# Device Fingerprinting (FR-010)

**Module:** `crates/waf-engine/src/device_fp/`
**Status:** GA — phases 01–09 complete (Redis backend behind feature flag).
**Spec:** `analysis/requirements.md` FR-010 (P0 mandatory).
**Last verified:** 2026-05-02

## 1. Overview & Threat Model

Device fingerprinting attaches a stable identity to a TCP/TLS connection
independent of source IP and User-Agent. The WAF uses it to detect:

| Threat | Mechanism |
|---|---|
| Same client rotating IPs (residential proxies, mobile NAT) | `ip_hopping` — single FP key seen across N IPs in window |
| Bots faking a browser UA (curl-impersonate, headless Chrome with mismatched H2) | `h2_anomaly`, `fp_conflict`, `ua_blocklist` |
| Low-entropy / heavily-rotated UAs | `ua_entropy` |
| Same FP key claiming multiple identities (UA churn) | `fp_conflict` |

Fail-open everywhere: if capture, store, or aggregator errors, the request
proceeds. The subsystem emits **signals** for downstream policy
(`RiskAggregator` trait, FR-025) — it does not block by itself.

## 2. YAML Configuration Reference

Single root key `device_fp`. Hot-reload via `notify` watcher (debounced
~250 ms). Empty file = disabled.

```yaml
device_fp:
  schema_version: 1            # required; bumped only on breaking changes
  enabled: true                # master switch
  hot_reload: true             # watch this file for changes

  capture:
    tls:
      enabled: true
      algorithms: [ja3, ja4]   # subset of {ja3, ja4}; unknown → reject at load
    h2:
      enabled: true
      hash: akamai             # only "akamai" supported in v1

  store:
    backend: memory            # memory | redis
    ttl_secs: 3600             # eviction window
    redis:                     # required iff backend=redis
      url: "redis://127.0.0.1:6379"
      key_prefix: "wafp:"

  providers:                   # ordered; duplicates rejected at load
    - name: ip_hopping
      window_secs: 600
      max_distinct_ips: 3
      signal_weight: 25        # 0..=100
    - name: fp_conflict
      window_secs: 600
      max_distinct_uas: 4
      signal_weight: 30
    - name: ua_entropy
      min_entropy_x100: 250    # Shannon entropy × 100 (integer-only YAML)
      signal_weight: 15
    - name: ua_blocklist
      blocklist_patterns:
        - "(?i)curl-impersonate"
        - "(?i)nuclei"
      signal_weight: 40
    - name: h2_anomaly
      signal_weight: 35
```

Validation rules (`config::DeviceFpConfig::validate`): unknown TLS
algorithm → reject; H2 hash other than `akamai` → reject; `redis` backend
without `redis:` block → reject; duplicate provider names → reject;
`signal_weight > 100` → reject.

## 3. Signal Catalog

| Signal name | Provider | Variant payload | Recommended weight |
|---|---|---|---|
| `ip_hopping` | `ip_hopping` | `distinct_ips: u16` | 25 |
| `fp_conflict` | `fp_conflict` | `distinct_uas: u16` | 30 |
| `low_entropy_ua` | `ua_entropy` | `entropy_x100: u16` | 15 |
| `ua_blocklisted` | `ua_blocklist` | `pattern: String` | 40 |
| `h2_anomaly` | `h2_anomaly` | `reason: H2AnomalyReason` | 35 |

`H2AnomalyReason` ∈ { `BadSettings`, `PseudoHeaderOrder`,
`InvalidPriority`, `ZeroWindowUpdate` }.

Stable name accessor: `Signal::name()` — use for log/metric labels.

## 4. IdentityStore: memory vs redis

| Backend | When to use | Trade-off |
|---|---|---|
| `memory` (`DashMap`) | Single-node deployments; dev / staging | Lost on restart; not shared across replicas |
| `redis` (feature `redis-store`) | Multi-replica gateways; need cross-node identity | Adds RTT; degrades to capture-only on Redis outage |

Build with `cargo build --features redis-store`. Both implementations
satisfy the same conformance suite (`identity::conformance`).

## 5. Operator Runbook

### Tuning false positives

1. Run with all providers at default weights, signals **logged-only**
   (`NoopAggregator` or `LoggingAggregator`).
2. Sample 24 h of signals from access logs. Per signal name, compute
   precision against a manually-labeled allowlist.
3. Raise `window_secs` (broader sampling) or `max_distinct_*` (looser
   threshold) on noisy providers; lower `signal_weight` if the signal is
   informative but not decisive.
4. Hot-reload by saving YAML; loader picks up within ~1 s.

### Reading audit logs

`tracing` target `device_fp::process` emits one structured event per
processed request: `peer_ip`, `fp_key`, `signal_count`, plus
provider-specific fields. Aggregator integrations (`LoggingAggregator`,
FR-025) carry the full `Signal` enum; `Signal::name()` is the join key.

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `unknown inspector trait` build error | Pingora patch not picked up | Verify `[patch.crates-io] pingora = { path = "vendor/pingora/pingora" }` and that `pingora-core` is in `[dependencies]` |
| `device_fp: unknown TLS algorithm` at load | Typo or v2-only algo in v1 build | Restrict to `ja3`, `ja4`; bump `schema_version` only after binary upgrade |
| Redis backend silently reverting to memory | Connection error logged at `warn` | Check `device_fp::process` warns; verify `redis` URL, ACL, TLS cert; circuit breaker re-arms after TTL |
| Hot reload not firing | Watching wrong dir (symlinked configs) | `notify` watches the parent dir; ensure the YAML's parent is writable and not a tmpfs that drops events |
| All requests get `fp_key = empty` | Capture disabled in YAML or Pingora hooks not wired | Confirm `capture.tls.enabled` / `capture.h2.enabled = true` and gateway listener uses the patched `pingora-core` |

## 7. Performance

Targets (plan §Performance Budget): added p99 < 300 µs at 5 k req/s.
Per-stage budgets:

| Stage | Budget |
|---|---|
| ClientHello parse | < 50 µs |
| H2 frame append | < 30 µs |
| Store observe (memory) | < 10 µs |
| Provider chain | < 100 µs (5 providers) |
| Aggregator submit (`Noop`) | < 5 µs |

Bench: `cargo bench -p waf-engine --bench device_fp_pipeline`.
Reports `device_fp_full_pipeline_warm` and `_cold`. Nightly CI job
`device-fp-bench` archives results.

Capacity planning: each `MemoryIdentityStore` entry ≈ 256 B. 1 M
distinct FPs ≈ 256 MB; tune `ttl_secs` to bound this. Redis sizing
follows the same per-key footprint plus protocol overhead.

## 8. Privacy Considerations

- Raw User-Agent strings are passed to providers but **not persisted**;
  the store keeps only the FP key, peer IP, and last-seen timestamp.
- Operators wanting strict PII minimization should hash UA at the gateway
  edge before invoking `process()` (the API takes `&str` — substitute the
  hash if desired).
- Retention is bounded by `store.ttl_secs`. Memory backend evicts on
  next access; Redis backend uses native `EXPIRE`.
- No fingerprint, IP, or UA is forwarded to upstream services.

## 9. Cross-References

- Architecture: [`system-architecture.md`](system-architecture.md) §Device fingerprinting
- Codebase map: [`codebase-summary.md`](codebase-summary.md) — `device_fp/` module
- Pingora patch SOP: [`code-standards.md`](code-standards.md) §Vendored dependencies
- Plan: `plans/260501-2005-fr010-device-fingerprinting/plan.md`
- Brainstorm: `plans/reports/brainstorm-260501-2005-fr010-device-fingerprinting.md`
