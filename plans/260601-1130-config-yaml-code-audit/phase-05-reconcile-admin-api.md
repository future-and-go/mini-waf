---
phase: 5
title: "Reconcile Admin API (DDoS + Relay only)"
status: pending
priority: P1
effort: "2h"
dependencies: [2, 3]
---

# Phase 5: Reconcile Admin API (DDoS + Relay only)

## Overview

Rewrite `ddos_api.rs` and `relay_api.rs` to use typed Rust structs for read/write instead of generic `serde_json::Value`. Scoped to only the 2 broken endpoints per validation decision. risk/device-fp/challenge APIs work today despite the same anti-pattern — they're out of scope.

## Scope Decision

- **In scope**: `ddos_api.rs`, `relay_api.rs`
- **Out of scope**: `risk_api.rs`, `device_fp_api.rs`, `challenge_api.rs`, `tier_policies_api.rs` (all work today)
- **Out of scope**: Frontend page updates (separate task)
- **Out of scope**: Extracting shared helpers (`resolve_path`/`read_yaml_opt`/`write_yaml`) — DRY win deferred until more endpoints are rewritten

## Architecture

Target pattern per endpoint:
```
GET: read file → from_yaml_str::<Document>() → serde_json::to_value() → Json
PUT: Json body → serde_json::from_value::<FileConfig>() → validate() → wrap in Document → serde_yaml::to_string() → write file
```

Prerequisite: Phase 2 adds `Serialize` to DDoS structs, Phase 3 adds `Serialize` to Relay structs.

## Related Code Files

- Modify: `crates/waf-api/src/ddos_api.rs`
- Modify: `crates/waf-api/src/relay_api.rs`
- Read: `crates/waf-engine/src/checks/ddos/config.rs` (DdosDocument, DdosFileConfig)
- Read: `crates/waf-engine/src/relay/config.rs` (RelayDetectionDocument, RelayConfig)

## Implementation Steps

1. **DDoS API rewrite** (`ddos_api.rs`):
   - `get_ddos_config`: `DdosFileConfig::from_yaml_str()` → `serde_json::to_value(&doc.ddos)` → `Json`
   - `put_ddos_config`: `serde_json::from_value::<DdosFileConfig>(body)` → `validate()` → `DdosDocument { ddos: cfg }` → `serde_yaml::to_string()` → write
   - Fallback: if file doesn't exist or parse fails, return `DdosFileConfig::default()` serialized
   - Remove: `yaml_to_fe()`, `default_ddos_fe()`, manual `json!()` construction

2. **Relay API rewrite** (`relay_api.rs`):
   - Same pattern using `RelayConfig` / `RelayDetectionDocument`
   - Note: `RelayConfig` contains `IpNet` (serializes as string) and `Option<Duration>` (custom deserializer `deser_duration_opt` — needs matching serialize or `#[serde(skip)]`)
   - Remove old helpers

3. **FE compatibility**: Since frontend is a separate task, the API may temporarily need to detect the old schema and translate. However, if the admin panel is updated in parallel, skip the compatibility layer.

4. **Verify round-trip**: write a test per endpoint:
   - Default config → GET → modify field → PUT → GET → assert change persists
   - PUT with invalid data → 400 error with validation message

## Success Criteria

- [ ] `ddos_api.rs` uses typed `DdosFileConfig` for read/write
- [ ] `relay_api.rs` uses typed `RelayConfig` for read/write
- [ ] PUT with invalid values returns 400 (not silent write that crashes engine)
- [ ] Round-trip test passes
- [ ] Dead helper functions removed from both files

## Risk Assessment

- **FE breakage**: Admin panel will break if updated API ships before FE update. Mitigate by coordinating deploy or adding temporary old-schema fallback in GET responses.
- **Duration serialization**: `RelayConfig` has `Option<Duration>` with custom deserializer. Adding a matching serializer (`"30m"` format) or using `#[serde(skip_serializing)]` needs care.
