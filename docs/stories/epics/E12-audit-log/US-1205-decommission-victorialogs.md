# US-1205 Decommission VictoriaLogs

## Status

implemented

## Lane

high-risk

## Product Contract

Once the JSONL file is the sole audit sink (US-1201, decision 0009), VictoriaLogs no
longer earns its operational cost. Remove it entirely: the audit network sink, the
`tracing → VictoriaLogs` layer, the managed sidecar + installer, the read proxy API,
and `VictoriaLogsConfig`. No contract field changes — §6 audit output is unchanged;
this removes only transport/observability plumbing. Decision 0010 is the durable
record.

## Relevant Product Docs

- `docs/product/audit-log.md` (audit output unchanged)
- interop contract v2.3 §6 (audit shape stays satisfied by the file sink)
- decision `0010-decommission-victorialogs.md`

## Removal Inventory

Audit sink (depends on US-1201 landing the file sink first):

- `crates/waf-engine/src/logging/audit_sender.rs` — drop `BatchSender`; record built
  by the (renamed) §6 builder, no `_msg`/`_time`/`stream` VL-isms. (US-1201)
- `crates/waf-engine/src/logging/batch_buffer.rs` — delete (VL HTTP batch transport).

Tracing pipeline:

- `crates/waf-engine/src/logging/vlogs_layer.rs` — delete (`tracing → VL` layer).
- `crates/waf-engine/src/logging/mod.rs` — drop `vlogs_layer` / `batch_buffer`
  modules and re-exports (`VictoriaLogsLayer`, `LayerSlot`, `BatchConfig`,
  `BatchSender`, `spawn_batch_flusher`). `db_batch_writer` stays (DB-only, no VL dep).
- `crates/prx-waf/src/main.rs` — remove `mod victoria_logs;`, VL imports, the
  `VictoriaLogsLayer` registration, the sidecar spawn in `init_async`, the Phase 02
  pipeline wiring, the Phase 03 `victoria_logs_base_url` exposure, the shutdown leak,
  and the `vlogs_sidecar` return-tuple element.

Sidecar + installer:

- `crates/prx-waf/src/victoria_logs/{mod,installer,sidecar}.rs` — delete.
- `crates/prx-waf/tests/victoria_logs_installer_disabled.rs`,
  `victoria_logs_installer_extract.rs`, `victoria_logs_sidecar_disabled.rs` — delete.
- `crates/prx-waf/Cargo.toml` — drop installer-only deps (`flate2`, `tar`, `sha2`,
  and `reqwest` if VL was its only consumer).

Read API:

- `crates/waf-api/src/logs.rs` — delete (VL read proxy).
- `crates/waf-api/src/server.rs` — remove routes `/api/v1/logs/query|stats|streams`.
  `POST /api/admin/logs/level` (`set_log_level`) is independent — keep.
- `crates/waf-api/src/state.rs` — remove `victoria_logs_base_url` and the
  `/api/v1/logs/streams` memoised cache.
- `crates/waf-api/tests/logs_handlers_proxy.rs` and the VL helpers in
  `tests/common/mod.rs` — delete.
- `crates/waf-api/src/websocket.rs` (`/ws/logs`) is sourced from the DB broadcast
  channel, **not** VL — leave untouched.

Config:

- `crates/waf-common/src/config.rs` — remove `VictoriaLogsConfig`, the
  `victoria_logs` field, and its `validate()` call. Replace with the `[audit]`
  block (`AuditFileConfig`) from US-1201.
- `crates/waf-common/tests/config_defaults.rs`, `config_loader.rs` — drop VL cases.

## Acceptance Criteria

- No `grep -ri victoria crates/` hits remain (code, tests, comments, Cargo manifests).
- `AuditSender` carries no `BatchSender`; `vlogs_layer.rs`, `batch_buffer.rs`, and
  `crates/prx-waf/src/victoria_logs/*` are gone.
- `/api/v1/logs/query|stats|streams` no longer registered; `set_log_level` still works.
- `VictoriaLogsConfig` and the `[victoria_logs]` config block no longer exist; the
  only audit config is the `[audit]` block.
- `cargo build --workspace` and `cargo test --workspace` are green with the VL deps
  removed; no dead `BatchSender`/`reqwest`-for-VL code remains.
- Audit output to `./waf_audit.log` is byte-for-byte the §6 object (no VL-isms).

## Design Notes

- Order: land US-1201 (file sink) first, then this removal — the file must be the
  audit sink before the network sink is deleted.
- Decision logic in `engine.rs` is untouched; only the audit transport and the
  observability/read surface change.
- Cross-epic impact: the admin panel log-query / streams views lose their backend.
  Confirm with the owner before deleting `logs.rs` (see Stop Conditions in 0010).

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Config loads with no `[victoria_logs]` block; `[audit]` block parsed. |
| Integration | Server boots with VL removed; audit file still written; `set_log_level` 200. |
| E2E | Post-run parse of `./waf_audit.log` unaffected by removal. |
| Platform | `./waf run` boots with no sidecar download/spawn. |
| Release | `grep -ri victoria crates/` empty; `cargo test --workspace` green. |

## Harness Delta

Register under decision 0010-decommission-victorialogs; durable proof booleans set via
harness-cli after verification.

## Evidence

Planned — no implementation yet. Depends on US-1201 landing the file sink.
