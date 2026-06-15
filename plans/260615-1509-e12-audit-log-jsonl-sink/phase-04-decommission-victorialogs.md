---
phase: 4
title: "Decommission VictoriaLogs"
status: completed
priority: P1
effort: "5h"
dependencies: [1]
---

# Phase 4: Decommission VictoriaLogs

## Overview

Remove every VictoriaLogs code path and config now that the file sink is the sole
audit destination (decision 0010). Purely subtractive on the transport/
observability surface — touches **no** decision logic. Closes US-1205.

## Requirements

- Functional: workspace builds and tests green with **no** VL dependency. The
  audit file path is the only audit configuration. `audit_sender` no longer
  references `BatchSender`. Console logging and the DB-backed `/ws/logs` stream
  stay working.
- Non-functional: no `victoria`/`vlogs`/`BatchSender` symbols remain in non-test
  Rust source.

## Architecture

Sequenced **after** Phase 1 (the file must already be the audit sink before the
network sink code is deleted). Removal map:

| Area | Delete / change |
| --- | --- |
| Audit transport | Delete `crates/waf-engine/src/logging/batch_buffer.rs`; drop `BatchSender`/`BatchConfig`/`spawn_batch_flusher` exports from `logging/mod.rs`. (`AuditSender` already off `BatchSender` after Phase 1.) |
| Tracing layer | Delete `crates/waf-engine/src/logging/vlogs_layer.rs`; remove `VictoriaLogsLayer`/`LayerSlot` exports; remove `.with(vlogs_layer)` registration + `vlogs_layer_slot` threading in `main.rs`. Keep the console `fmt` layer + `EnvFilter` + reload handle. |
| Sidecar/installer | Delete `crates/prx-waf/src/victoria_logs/*` (`mod.rs`, `sidecar.rs`, `installer.rs`); remove `mod victoria_logs;` and `ensure_binary`/`VictoriaLogsSidecar::spawn`/`vlogs_sidecar` wiring in `main.rs`. |
| Read API | Delete `crates/waf-api/src/logs.rs`; remove the 3 routes (`/api/v1/logs/query|stats|streams`) + `use crate::logs::...` in `server.rs`; remove `AppState::victoria_logs_base_url` and `logs_streams_cache` in `state.rs`. Keep `set_log_level` (`/api/admin/logs/level`) and `/ws/logs`. |
| Config | Remove `VictoriaLogsConfig` + helpers and `AppConfig.victoria_logs` (the `[victoria_logs]` block) in `waf-common/config.rs`. `[audit]` (Phase 1) is the only audit config. |
| Deps | Drop installer-only crate deps no longer used (`flate2`, `tar`, `sha2` for VL, VL `reqwest` use) from the affected `Cargo.toml`s **only if** not used elsewhere — grep before removing each. |
| Tests | Delete VL-only tests: `prx-waf/tests/victoria_logs_*`, `waf-api/tests/logs_handlers_proxy.rs`, `waf-engine/tests/logging_batch_lifecycle.rs`, `waf-engine/tests/logging_vlogs_layer.rs`; scrub VL refs from `waf-common/tests/config_*`, `waf-api/tests/common/mod.rs`, `waf-engine/tests/logging_audit_sender.rs`. |

`db_batch_writer.rs` and `/ws/logs` are independent of VL — **do not touch**.

## Open item (flagged, decision 0010 follow-up)

The admin-panel FE log-query/stats/streams views lose their backend. Decision
0010 says "confirm with the owner before deleting `logs.rs`" and remove/repoint
the FE. **Rust-workspace scope here removes the backend routes**; the React FE
surface (`web/admin-panel`) repoint/removal is a separate FE task — note it in the
trace and do not block the Rust build on it. Surface to user if FE breakage is a
blocker.

## Related Code Files

- Delete: `crates/waf-engine/src/logging/batch_buffer.rs`,
  `crates/waf-engine/src/logging/vlogs_layer.rs`,
  `crates/prx-waf/src/victoria_logs/{mod,sidecar,installer}.rs`,
  `crates/waf-api/src/logs.rs`
- Delete (tests): `crates/prx-waf/tests/victoria_logs_installer_disabled.rs`,
  `…installer_extract.rs`, `…sidecar_disabled.rs`,
  `crates/waf-api/tests/logs_handlers_proxy.rs`,
  `crates/waf-engine/tests/logging_batch_lifecycle.rs`,
  `crates/waf-engine/tests/logging_vlogs_layer.rs`
- Modify: `crates/waf-engine/src/logging/mod.rs`, `crates/prx-waf/src/main.rs`,
  `crates/waf-api/src/server.rs`, `crates/waf-api/src/state.rs`,
  `crates/waf-common/src/config.rs`, the affected `Cargo.toml`s,
  `crates/waf-common/tests/config_defaults.rs`, `…config_loader.rs`,
  `crates/waf-api/tests/common/mod.rs`,
  `crates/waf-engine/tests/logging_audit_sender.rs`

## Implementation Steps

1. `logging/mod.rs`: drop VL exports (`BatchSender`, `BatchConfig`,
   `spawn_batch_flusher`, `VictoriaLogsLayer`, `LayerSlot`); delete
   `batch_buffer.rs` + `vlogs_layer.rs`.
2. `main.rs`: remove `mod victoria_logs;`, the sidecar spawn + `vlogs_sidecar`
   leak, the tracing-layer registration + `vlogs_layer_slot` params through
   `run_server`/`init_async`, and the `config.victoria_logs.enabled` audit branch
   (audit now from `config.audit`, done in Phase 1). Keep console logging.
3. Delete `crates/prx-waf/src/victoria_logs/*`.
4. `waf-api`: delete `logs.rs`, its routes + imports in `server.rs`, and the
   `victoria_logs_base_url` + `logs_streams_cache` state fields/initialisers.
5. `waf-common/config.rs`: delete `VictoriaLogsConfig` (+ default helpers +
   validate) and `AppConfig.victoria_logs`.
6. Delete the VL-only test files; scrub VL refs from the shared test helpers/config
   tests.
7. `Cargo.toml` cleanup: grep each candidate dep (`flate2`, `tar`, `sha2`,
   VL-specific `reqwest`) repo-wide; remove only the unused ones.
8. `cargo build --workspace`; fix fallout. `grep -rn -i 'victoria\|vlogs\|BatchSender'
   crates --include='*.rs' | grep -v target` returns nothing in non-test source.
9. `cargo test --workspace` (targeted first: waf-engine, waf-api, prx-waf,
   waf-common).

## Success Criteria

- [ ] All listed files deleted; VL routes/state/config removed.
- [ ] No `victoria`/`vlogs`/`BatchSender` symbol in non-test Rust source.
- [ ] `config.audit` is the only audit configuration; `[victoria_logs]` block gone.
- [ ] Console logging + `set_log_level` + `/ws/logs` still wired.
- [ ] Unused VL-only deps dropped (grep-verified).
- [ ] `cargo build --workspace` and `cargo test --workspace` green.
- [ ] FE log-view repoint flagged as a follow-up (not silently dropped).

## Risk Assessment

- **Over-deletion** of a shared dep (`sha2`/`reqwest` used elsewhere, e.g.
  fingerprint hashers per waf-engine CLAUDE.md) — mitigated by per-dep repo-wide
  grep before removal; remove only VL-exclusive uses.
- **main.rs threading**: `vlogs_layer_slot` flows through several fn signatures —
  remove the param everywhere it's declared/passed, compiler-driven.
- **FE breakage** from removing backend routes — flagged as an explicit
  out-of-Rust-scope follow-up; surface to user before assuming FE is fine.
- **Sequence**: must run after Phase 1; deleting `BatchSender` before the file
  sink exists would leave the audit path with no sink.
