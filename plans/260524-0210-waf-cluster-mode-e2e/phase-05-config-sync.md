---
phase: 5
title: "Config Sync"
status: completed
priority: P2
effort: "3h"
dependencies: [1]
---

# Phase 5: Config Sync

## Overview

`ConfigSyncer` is a minimal stub — it increments a version counter but doesn't serialize or broadcast actual configuration. This phase implements real config sync: when the main node's config changes (via API or hot-reload), the new config is serialized and pushed to all workers.

### Red-Team Fixes

- **JWT secret distribution**: Include `api.jwt_secret` in synced config so all nodes validate JWTs identically. This unblocks Phase 6 write forwarding auth.
- **Config validation**: Validate deserialized TOML before applying. If validation fails, log error and keep current config (no crash).
- **Term fencing**: Include `term` field in ConfigSync message. Workers reject ConfigSync from stale-term senders.

## Requirements

- Functional: Config changes on main propagate to workers within `config_interval_secs` (30s)
- Functional: Workers apply received config to their local `AppConfig` (non-cluster sections only)
- Functional: JWT signing secret (`api.jwt_secret`) synced so all nodes validate auth identically
- Functional: ConfigSync includes election `term` — workers reject messages from stale-term mains
- Non-functional: Config payload is TOML-serialized, typically <10KB
- Non-functional: Validation before apply — malformed config does not crash workers

## Architecture

```
Main:
  Config change (API or hot-reload)
    → increment config_version
    → serialize relevant config sections to TOML
    → broadcast ConfigSync { version, payload } to all peers

Worker:
  receives ConfigSync
    → deserialize TOML payload
    → apply to local config (proxy, rules, cache settings)
    → update config_version in NodeState
    → trigger affected subsystem reloads
```

## Related Code Files

- Modify: `crates/waf-cluster/src/sync/config.rs` — real `build_sync()` and `apply_sync()`
- Modify: `crates/waf-cluster/src/transport/server.rs` — real `handle_config_sync()`  
- Modify: `crates/waf-cluster/src/transport/client.rs` — real `handle_config_sync()`
- Modify: `crates/waf-cluster/src/lib.rs` — spawn periodic config sync on main
- Read: `crates/waf-common/src/config.rs` — AppConfig structure

## TDD: Tests First

1. **Unit test** (`crates/waf-cluster/tests/config_sync_test.rs`):
   - Create `ConfigSyncer` with a sample `AppConfig`
   - Call `build_sync()` → verify TOML payload contains expected sections
   - Call `apply_sync()` with the payload → verify config fields updated
   - Verify version incremented

2. **Version skip test**:
   - Worker at config_version 5, main sends version 5 → no-op (already current)
   - Worker at version 5, main sends version 7 → apply

3. **Partial config test**:
   - Verify cluster-specific config (seeds, role) is NOT overwritten by sync
   - Only proxy, rules, cache, api sections are synced

## Implementation Steps

1. **Define syncable config sections** (`sync/config.rs`):
   - Create `SyncableConfig` struct containing only the sections that should sync:
     - `proxy`, `rules`, `cache`, `api` settings
   - Exclude: `cluster`, `storage` (node-specific)

2. **Implement `build_sync()`**:
   - Serialize `SyncableConfig` to TOML string
   - Return `ConfigSync { version, payload: toml_string }`

3. **Implement `apply_sync()`**:
   - Deserialize TOML payload into `SyncableConfig`
   - Merge into local config (overwrite synced sections, keep local-only sections)
   - Update `node_state.config_version`

4. **Wire dispatch handlers**:
   - Server: main broadcasts `ConfigSync` to peers when config changes
   - Client: worker applies received `ConfigSync`

5. **Spawn periodic config broadcast on main** (`lib.rs`):
   - Every `config_interval_secs`, if config_version changed, broadcast to all peers

6. **Run tests** — all config sync tests pass

## Success Criteria

- [ ] Main serializes and broadcasts config changes
- [ ] Workers deserialize and apply config changes
- [ ] Cluster-specific config (seeds, role, crypto) never overwritten
- [ ] Version check prevents redundant applies
- [ ] `cargo test -p waf-cluster` passes
- [ ] `cargo check --workspace` passes

## Risk Assessment

- Low-medium risk: config is small and changes rarely
- Pitfall: overwriting worker's cluster config → mitigated by `SyncableConfig` subset
- Pitfall: TOML serialization of complex types → test with real `AppConfig`
