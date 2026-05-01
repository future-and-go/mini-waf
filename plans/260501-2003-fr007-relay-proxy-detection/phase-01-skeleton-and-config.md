# Phase 01 — Relay Module Skeleton + Config Schema

## Context Links
- Design: [`../reports/brainstorm-260501-1957-fr007-relay-proxy-detection.md`](../reports/brainstorm-260501-1957-fr007-relay-proxy-detection.md) §4.2–4.6
- Reuse pattern: `crates/waf-engine/src/access/config.rs` (FR-008 builder)

## Overview
**Priority:** P0 · **Status:** completed · **Effort:** 0.5 d

Land the public data model + traits + YAML parser. **No I/O, no provider logic yet** — phases 02–04 plug into stable types defined here.

## Key Insights
- Strategy + Registry: `SignalProvider` trait + `ProviderRegistry` keep providers swappable; YAML `signals.enabled` drives registration.
- Mirror FR-008 builder: `RelayConfig::from_yaml_path()` + `from_yaml_str()` returning `Arc<RelayConfig>` snapshot or `Err`.
- `Signal` is a flat enum (not trait object) — risk scorer needs to match exhaustively.
- Default safe: missing `signals.enabled` → empty registry → detector emits nothing (fail-open at config layer; runtime feed-missing fail-close handled phase-03/04).

## Requirements

### Functional
- Parse YAML matching brainstorm §4.6 schema verbatim.
- Define `Signal` enum, `SignalProvider`/`IntelProvider` traits, `RelayCtx`, `ClientIdentity`, `AsnClass`.
- `RelayConfig` validates: trusted CIDRs syntax, `max_chain_depth ≥ 1`, header names ASCII-only, durations parseable.
- `ProviderRegistry::dispatch(ctx)` iterates registered providers, collects signals.
- Reject malformed YAML with `anyhow::Context`.

### Non-functional
- Zero `.unwrap()` / `todo!()` / `unimplemented!()` outside `#[cfg(test)]`.
- Each file ≤200 LOC; split if exceeded.

## Architecture

```
RelayConfig (serde)            ── YAML 1:1
   │ build()
   ▼
RelayDetector (Arc-shared)
  ├── cfg:       Arc<ArcSwap<RelayConfig>>
  ├── registry:  ProviderRegistry
  ├── tor_set:   Arc<ArcSwap<TorSet>>      ── filled phase-04
  └── asn_db:    Arc<ArcSwap<AsnDb>>       ── filled phase-03

trait SignalProvider {
    fn name(&self) -> &'static str;
    fn evaluate(&self, ctx: &RelayCtx) -> Vec<Signal>;
}

trait IntelProvider {
    fn name(&self) -> &'static str;
    async fn refresh(&self) -> Result<RefreshOutcome>;
}

enum Signal {
    XffSpoofPrivate, XffMalformed, XffTooLong,
    ExcessiveHopDepth(u8),
    AsnDatacenter { asn: u32, org: String },
    AsnResidential, AsnUnknown, TorExit,
}

enum AsnClass { Residential, Datacenter, Tor, Unknown }

struct ClientIdentity {
    real_ip: IpAddr,
    asn: Option<u32>,
    asn_class: AsnClass,
    signals: Vec<Signal>,
}
```

## Related Code Files

### Create
- `crates/waf-engine/src/relay/mod.rs` — `RelayDetector` facade stub + `ClientIdentity` re-export
- `crates/waf-engine/src/relay/config.rs` — serde structs + `from_yaml_*`
- `crates/waf-engine/src/relay/signal.rs` — `Signal` enum + `SignalProvider` trait + `RelayCtx`
- `crates/waf-engine/src/relay/registry.rs` — `ProviderRegistry::register/dispatch`
- `crates/waf-engine/src/relay/providers/mod.rs` — module stub (filled phases 02–04)
- `crates/waf-engine/src/relay/intel/mod.rs` — `IntelProvider` trait + `RefreshOutcome`

### Modify
- `crates/waf-engine/src/lib.rs` — `pub mod relay;`
- `crates/waf-engine/Cargo.toml` — verify `iprange`, `arc-swap`, `serde_yaml` present (no add expected)

## Implementation Steps

1. **Verify deps** — grep `Cargo.toml` for `iprange`, `arc-swap`, `serde_yaml`. Add only what's missing.
2. **`relay/mod.rs`** — module declarations + `pub use config::*; pub use signal::*;`. Stub `RelayDetector::evaluate` returning a default `ClientIdentity { real_ip: peer_ip, asn_class: Unknown, asn: None, signals: vec![] }` so dependent phases compile.
3. **`signal.rs`** — define `Signal`, `AsnClass`, `RelayCtx { peer_ip, headers: &http::HeaderMap, now: Instant }`, `ClientIdentity`, `SignalProvider` trait. Derive `Debug, Clone` on `Signal`/`AsnClass`.
4. **`config.rs`** — serde structs:
   ```rust
   pub struct RelayConfig {
       pub trusted_proxies: Vec<IpNet>,
       pub max_chain_depth: u8,
       pub headers: HeaderConfig,
       pub asn: AsnConfig,
       pub tor: TorConfig,
       pub signals: SignalConfig,
   }
   pub struct SignalConfig {
       pub enabled: Vec<String>,
       pub risk_score_delta: HashMap<String, i32>,
   }
   ```
   Custom deserializers: CIDR parsing, duration parsing (`24h`, `1h`).
5. **`config.rs::validate()`** — `max_chain_depth ≥ 1`, header names match `^[A-Za-z][A-Za-z0-9-]*$`, all CIDRs parse, no duplicate signal names.
6. **`registry.rs`** — `ProviderRegistry { providers: Vec<Box<dyn SignalProvider>> }`, `register()`, `dispatch(&RelayCtx) -> Vec<Signal>` aggregates.
7. **`intel/mod.rs`** — `IntelProvider` trait + `RefreshOutcome { Updated, NotModified, Failed(Error) }`.
8. **`cargo check -p waf-engine`** — must pass clean. `cargo clippy -p waf-engine -- -D warnings` clean.

## Todo List
- [x] Verify Cargo deps; add only missing ones
- [x] Create `relay/{mod,signal,config,registry}.rs` + `providers/mod.rs` + `intel/mod.rs`
- [x] Define `Signal`, `AsnClass`, `ClientIdentity`, `RelayCtx`
- [x] Define `SignalProvider` + `IntelProvider` traits
- [x] Implement `RelayConfig` serde + custom CIDR/duration deserializers
- [x] Implement `RelayConfig::validate()`
- [x] Implement `ProviderRegistry::register/dispatch`
- [x] `cargo check` + `clippy` clean
- [x] Unit test: round-trip parse of brainstorm §4.6 sample YAML

## Success Criteria
- `cargo check -p waf-engine` clean.
- Unit test parses brainstorm §4.6 YAML sample without error; field counts match.
- Unit test: missing `signals.enabled` → empty registry, no panic.
- Unit test: invalid CIDR `999.0.0.0/8` → `Err` with descriptive context.
- Unit test: `max_chain_depth: 0` → `Err`.
- Each new file ≤200 LOC.

## Common Pitfalls
- `serde_yaml` needs explicit `default` attrs on optional fields — copy FR-008 pattern.
- `IpNet` deserialization via `String` then `FromStr` — implement `Deserialize` manually or via `serde_with`.
- `HeaderMap` not constructible in `RelayCtx` for unit tests without http crate; ensure http is workspace dep before phase-02.

## Risk Assessment
Low. Pure types + parsing.

## Security Considerations
`serde_yaml` on untrusted input — already vetted in FR-003/FR-008. No new surface.

## Next Steps
Phase 02 — implement `XffValidator` + `ProxyChainAnalyzer` providers.
