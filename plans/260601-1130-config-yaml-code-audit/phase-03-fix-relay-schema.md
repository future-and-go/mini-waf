---
phase: 3
title: "Fix Relay Schema"
status: pending
priority: P1
effort: "2h"
dependencies: [1]
---

# Phase 3: Fix Relay Schema

## Overview

Rewrite `configs/relay.yaml` to match the `RelayConfig` struct. Current file is silently ignored — all relay detection runs on defaults (effectively disabled). The engine struct is correct and tested.

## Red-Team Correction

**Watcher not bootstrapped**: `RelayReloader::start()` is never called from `main.rs`. Fixing the YAML alone doesn't change runtime behavior today.

**Serialize gap**: `RelayConfig`, `RelayDetectionDocument`, `HeaderConfig`, `AsnConfig`, `TorConfig`, `RefreshConfig`, `SignalConfig` do NOT derive `Serialize`. Must add it.

**Missing `deny_unknown_fields`**: `RelayDetectionDocument` should have `#[serde(deny_unknown_fields)]` to prevent silent field drops (root cause of the silent-ignore behavior).

## Requirements

- Functional: `configs/relay.yaml` must parse through `RelayConfig::from_yaml_path()` without error
- Functional: All Relay config structs must derive `Serialize`
- Functional: `RelayDetectionDocument` must have `#[serde(deny_unknown_fields)]`
- Functional: Admin API `GET /api/relay/config` must return the engine-canonical schema
- Functional: Admin API `PUT /api/relay/config` must write YAML the engine can parse
- Non-functional: Hot-reload must work once watcher is bootstrapped

## Architecture

Same pattern as Phase 2. Rewrite `relay_api.rs` to use typed `RelayConfig` instead of generic `Value`.

Key structural differences between old and new schema:
- Old: `providers: {asn_classifier: {enabled, risk_weight}}` — per-provider toggle + weight
- New: `signals: {enabled: ["asn_classifier", "tor_exit"], risk_score_delta: {tor_exit: 30}}` — signal list + delta map
- Old: `intel: {asn_feed: {url}, tor_feed: {url}}` — feed URLs inline
- New: `asn: {provider, mmdb_path, refresh: {url, interval}}` + `tor: {list_path, refresh: {url, interval}}` — structured per-source config
- Old: `risk_weights: {tor: 30}` — flat weight map
- New: `signals.risk_score_delta: {tor_exit: 30}` — inside signals block

## Related Code Files

- Modify: `configs/relay.yaml` — rewrite to engine schema
- Modify: `crates/waf-api/src/relay_api.rs` — switch from `Value` to typed `RelayConfig`
- Read: `crates/waf-engine/src/relay/config.rs` — reference struct
- Read: `crates/waf-engine/src/relay/registry.rs:186+` — reference test YAML examples

## Implementation Steps

0. Add `#[derive(Serialize)]` to: `RelayDetectionDocument`, `RelayConfig`, `HeaderConfig`, `AsnConfig`, `TorConfig`, `RefreshConfig`, `SignalConfig` in `crates/waf-engine/src/relay/config.rs`. Add `#[serde(deny_unknown_fields)]` to `RelayDetectionDocument`. Note: `IpNet` and `PathBuf` fields serialize to strings, which is fine for JSON API responses. `Duration` fields use custom deserializer (`deser_duration_opt`) — need a matching serializer or use `#[serde(skip_serializing)]` and reconstruct on deserialize.

1. Rewrite `configs/relay.yaml`:
   ```yaml
   relay_detection:
     trusted_proxies: []
     max_chain_depth: 3
     headers:
       forwarded_for:
         - "X-Forwarded-For"
         - "X-Real-IP"
     asn:
       provider: null
       fail_close: false
     tor:
       list_path: null
     signals:
       enabled: []
       risk_score_delta:
         tor_exit: 30
         datacenter: 15
         bad_asn: 25
   ```
2. Verify: `RelayConfig::from_yaml_path("configs/relay.yaml")` succeeds
3. Rewrite `relay_api.rs`:
   - `get_relay_config`: read file → `RelayConfig::from_yaml_str()` → serialize to JSON
   - `put_relay_config`: deserialize JSON body → validate → write YAML
   - Remove old `yaml_to_fe()` / `default_relay_fe()` if they exist
4. Check admin panel frontend for relay config page and update form fields

## Success Criteria

- [ ] `configs/relay.yaml` parses through `RelayConfig::from_yaml_path()` without error
- [ ] `cargo test -p waf-engine -- relay` passes
- [ ] Admin API GET returns engine-schema JSON
- [ ] Admin API PUT writes engine-parseable YAML
- [ ] Hot-reload test: modify file → engine picks up new config

## Risk Assessment

- **FE breakage**: Admin panel relay config page likely shows `providers` with toggle switches. New schema uses `signals.enabled` list. Frontend needs updating.
- **`null` in YAML**: `asn.provider: null` and `tor.list_path: null` are valid YAML but may cause issues on round-trip through admin API. Test this explicitly.
- **Feed URLs dropped**: Old schema had `intel.tor_feed.url` inline. New schema uses `tor.refresh.url`. The Tor bulk exit list URL needs to be preserved somewhere (either in config or hardcoded as default).
