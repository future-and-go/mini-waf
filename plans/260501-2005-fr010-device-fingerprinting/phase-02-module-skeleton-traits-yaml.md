# Phase 02 — Module Skeleton, Traits, YAML Schema, Hot Reload

**Status:** completed | **Priority:** P0 | **Effort:** M | **Blocked by:** phase-01

## Context

Lay down `crates/waf-engine/src/device_fp/` module structure with all extension traits and YAML config. Mirrors FR-007 `relay/` Strategy + Registry pattern. Hot-reload reuses existing `notify` watcher.

## Requirements

### Functional
- Module compiles and exports public surface; empty implementations stubbed
- YAML schema fully serde-typed with `#[serde(deny_unknown_fields)]`
- `ArcSwap<DeviceFpConfig>` allows atomic config swap
- File watcher reloads config on change; provider registry rebuilt on swap; in-flight requests unaffected
- All traits documented w/ rustdoc + doc tests

### Non-functional
- Public API stable — adding new providers must not break existing callers
- Zero `.unwrap()` in non-test code (Iron Rule #1)

## Module Layout

```
crates/waf-engine/src/device_fp/
├── mod.rs                  # facade + DeviceIdentity + DeviceFpDetector
├── config.rs               # YAML schema (serde)
├── reload.rs               # ArcSwap + notify integration
├── signal.rs               # Signal enum
├── registry.rs             # ProviderRegistry
├── capture/                # (stubbed; impls in phase-03)
│   ├── mod.rs
│   ├── tls.rs
│   ├── h2.rs
│   ├── client_hello_inspector.rs  # from phase-01
│   ├── h2_frame_inspector.rs      # from phase-01
│   └── conn_ctx.rs
├── fingerprint/            # (stubbed; impls in phase-04)
│   ├── mod.rs
│   ├── trait.rs
│   ├── ja3.rs
│   ├── ja4.rs
│   └── h2_akamai.rs
├── providers/              # (stubbed; impls in phase-06)
│   ├── mod.rs
│   ├── fp_conflict.rs
│   ├── ip_hopping.rs
│   ├── ua_entropy.rs
│   ├── ua_blocklist.rs
│   └── h2_anomaly.rs
└── identity/               # (stubbed; impls in phase-05/08)
    ├── mod.rs
    ├── trait.rs
    ├── memory.rs
    └── redis.rs            # feature = "redis-store"
```

## Core Traits

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
    async fn observe(&self, key: &FpKey, ip: IpAddr, ua: &str, ts: i64)
        -> anyhow::Result<Observation>;
    async fn lookup(&self, key: &FpKey)
        -> anyhow::Result<Option<IdentityRecord>>;
    async fn purge_expired(&self) -> anyhow::Result<usize>;
}

#[async_trait::async_trait]
pub trait RiskAggregator: Send + Sync {
    async fn submit(&self, key: &FpKey, signals: &[Signal]);
}
```

## YAML Schema

```yaml
device_fp:
  enabled: true
  capture:
    tls: { enabled: true, algorithms: [ja3, ja4] }
    h2:  { enabled: true, hash: akamai }
  store:
    backend: memory          # memory | redis
    ttl_secs: 3600
    redis:
      url: "redis://..."
      key_prefix: "wafp:"
  providers:
    - name: ip_hopping
      window_secs: 600
      max_distinct_ips: 3
      signal_weight: 25
    # ... see brainstorm §4.4
  hot_reload: true
```

## Files

**Created:**
- All files in module layout (stubbed where deferred)
- `configs/device-fp.yaml` (default config)
- `crates/waf-engine/src/lib.rs` — add `pub mod device_fp;`

**Modified:**
- `crates/waf-engine/Cargo.toml` — add deps: `arc-swap`, `notify`, `dashmap`, `async-trait`, `serde`, `serde_yaml`
- `Cargo.toml` (workspace) — feature flag `redis-store` declaration

## Steps

1. Create directory structure with stub files
2. Define `Signal` enum (FpConflict, IpHopping, LowEntropyUA, UaBlocklisted, H2Anomaly, plus weight metadata)
3. Define `RawCapture`, `FingerprintValue`, `FpKey`, `DeviceCtx`, `DeviceIdentity`, `Observation`, `IdentityRecord` types
4. Implement `DeviceFpConfig` w/ serde + validation (e.g., signal_weight 0-100)
5. Implement `ArcSwap<DeviceFpConfig>` + hot reload via `notify::RecommendedWatcher` (factor shared loader from FR-007 if landed; otherwise duplicate w/ TODO to merge)
6. Implement `ProviderRegistry` — rebuild on config swap
7. Stub all trait impls returning empty/None (real impls in later phases)
8. Wire `DeviceFpDetector::new(config_path)` into `WafEngine` init (behind feature toggle in main config)
9. Add unit tests for config load, validation errors, hot reload triggers swap

## Todos

- [x] Create module directory tree + stubs
- [x] Define core types (Signal, FpKey, RawCapture, etc.)
- [x] Implement DeviceFpConfig serde + validation
- [x] Implement ArcSwap + notify hot reload
- [x] Implement ProviderRegistry
- [ ] Wire DeviceFpDetector into WafEngine — **deferred to phase-04+** (no signals to emit yet; premature integration violates KISS)
- [x] Default `configs/device-fp.yaml`
- [x] Unit tests: config load, invalid YAML, hot reload swap (24 tests pass)
- [x] `cargo clippy -p waf-engine --all-targets --all-features -- -D warnings` clean

## Success Criteria

- `cargo check --workspace` green
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- Config hot reload integration test: write → swap observed within 1s
- All public types have rustdoc

## Risks

- Notify reload races config consumers → mitigate w/ `ArcSwap::load()` (lock-free, always-valid snapshot)
- YAML schema churn → freeze v1 schema; version field `schema_version: 1`

## Security

- Reject unknown YAML fields (`deny_unknown_fields`)
- Validate file path in config loader; reject symlink escapes outside config dir

## Next

Phase 03 (capture impls) and Phase 05 (identity store) can begin in parallel.
