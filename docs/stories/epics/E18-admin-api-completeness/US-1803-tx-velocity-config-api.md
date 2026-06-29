# US-1803 TX Velocity — config read/write API + hot-reload + editable form

## Status

implemented

## Lane

normal

Plan: `docs/review/admin-panel/plans/C2-tx-velocity-config-api.md`.
Gap spec §C2 (G.1 row 14). Req IDs: FR-012, FR-031.

## Product Contract

The TX Velocity page's "Config thresholds" card must be an editable form backed
by a real API that reads/writes `configs/tx-velocity.yaml`, and the engine must
hot-reload the change (no restart).

## Acceptance Criteria

- `GET /api/tx-velocity/config` returns the parsed `tx-velocity.yaml` inner
  object (documented defaults when the file is missing, not 500).
- `PUT /api/tx-velocity/config` parse-first-validates (schema_version, positive
  bounds, `endpoint_roles[].path` regex) and atomically writes the YAML;
  invalid input → 400 with a message, no half-written file.
- The engine hot-reloads the file (watcher wired in `main.rs` — see US-1802
  follow-up) so a PUT applies without restart.
- The FE card is an editable form bound to GET/PUT (Save persists + reloads).

## Design Notes

- API: `crates/waf-api/src/tx_velocity_api.rs` (mirrors `ddos_api`):
  `resolve_path`, `{ success, data: <inner> }`, atomic `.tmp`+rename, audit on
  PUT (`action="tx-velocity.config.update"`).
- Validation reuses the engine's own `TxVelocityFileConfig::from_yaml_str`
  (wrap inner → YAML → parse+validate) so the API and engine agree.
- Added `Serialize` to `TxVelocityDocument`/`TxVelocityFileConfig` + nested
  config structs (`RoleRule`, `ClassifierConfigs`, `SequenceCfg`, `VelocityCfg`)
  in `waf-engine` so GET can serialize them; `EndpointRole` already had it.
- Hot-reload watcher `start_tx_velocity_watcher` is wired at startup (done in
  US-1802's follow-up); endpoint_roles are preserved round-trip by the FE form.
- UI: `web/admin-panel/src/pages/tx-velocity/index.tsx` — read-only
  `Descriptions` card replaced with an editable `TxVelocityConfigCard`
  (enabled + classifier thresholds + timing knobs).

## Validation

| Layer | Expected proof |
| --- | --- |
| Unit | engine tx-velocity config already validated; API validation via from_yaml_str. |
| Integration | (manual/live) GET→PUT→GET round-trip; invalid → 400. |
| E2E | live Docker: edit a threshold + Save persists to YAML + survives reload; engine hot-reload log. |
| Release | `cargo clippy -D warnings` + `tsc --noEmit` + `vite build` clean. |

## Evidence

Verified 2026-06-29 (rebuilt `prx-waf` image; host cargo 1.95.0; FE `npm ci` +
`tsc --noEmit` clean; `vite build` passed in the Docker frontend stage).

- `cargo clippy -D warnings` clean (waf-engine/waf-api/prx-waf).
- Startup log: `tx_velocity: initial config loaded /app/configs/tx-velocity.yaml`
  + `hot-reload watching` (watcher wired).
- Live (`https://localhost:16827`): `GET /api/tx-velocity/config` → full inner
  config (classifiers + endpoint_roles). `PUT` (enabled=true, sequence
  min_human_ms=400) → 200; `GET` round-trips `enabled=true,
  sequence.min_human_ms=400`. `PUT` with `endpoint_roles[].path="((("` →
  `400 "compile role rules"` (validation, no half-write). Test config restored
  afterward.
