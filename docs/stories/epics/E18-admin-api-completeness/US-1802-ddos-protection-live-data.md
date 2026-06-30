# US-1802 DDoS Protection — live metrics, ban table, working unban

## Status

implemented

## Lane

normal

Plan: `docs/review/admin-panel/plans/B1-ddos-protection-live-data.md`.
Gap spec: `admin-panel-gap-remediation-spec.md` §B1 (G.1 rows 7, 8, 9).
Req IDs: FR-005 (DDoS protection), FR-004 (rate limiting).

## Product Contract

The DDoS Protection page (`/ui/#/ddos-protection`) must show **live** data, not
stubs: the 4 KPI cards reflect the running engine, the ban table lists currently
banned IPs with their level/rate/reason, and the per-row Unban button actually
removes the ban.

## Relevant Product Docs

- `docs/review/admin-panel/plans/B1-ddos-protection-live-data.md`
- Engine: `crates/waf-engine/src/checks/ddos/` (FR-005, merged PR #46/#39).

## Acceptance Criteria

- `GET /api/ddos/metrics` returns real counters: `active_bans` = live ban-table
  size (expired pruned), `bursts_1h`/`bans_issued_1h` = engine lifetime totals,
  `store_errors` = engine counter. (FE cards relabeled "(total)".)
- `GET /api/ddos/ban-table` enumerates non-expired bans as
  `{ ip, banned_until_ms, ban_level, last_rps, reason }` with a `total`.
- `DELETE /api/ddos/ban-table/{ip}` removes the IP (idempotent 200; 400 on a
  malformed IP) and the next list/metrics reflect the removal; the mutation is
  audited (`action="ddos.unban"`).
- Routes unchanged (already registered); no schema migration.

## Design Notes

- Commands: `delete_ban_entry` (unban) — owns the audit side effect.
- Queries: `get_ddos_metrics`, `list_ban_table`.
- API: `crates/waf-api/src/ddos_api.rs` — three handlers rewritten to take
  `State` and read/mutate `state.engine.ddos_ban_table()` +
  `state.engine.ddos_metrics()`.
- Engine: `DynamicBanTable` value type changed `i64` → `BanState { expires_ms,
  ban_level, last_rps, reason }`; added `remove()`, `snapshot()`, `insert_ban()`
  (kept the `insert(ip, expires_ms)` convenience). `DetectorVerdict::HardBurst`
  gained `rps: u32` (observed window count for `per_fp`/`per_tier`; threshold
  for `per_ip`, which is backed by the FR-004 rate-limit store that returns only
  a `Decision`). `BanAction::execute` records level/rps/reason.
- Domain rules: `active_bans` uses the live `len()` (avoids the known
  `bans_active` over-count drift); unban is idempotent.
- UI surfaces: KPI label relabel only (`bursts1h`/`bansIssued1h` → "(total)" in
  `i18n/locales/en.json`); no other FE change (contract already matched).

## Validation

| Layer | Expected proof |
| --- | --- |
| Unit | `DynamicBanTable` remove/snapshot/expiry; `BanAction` records level/rps/reason; detector verdicts carry `rps`. |
| Integration | engine: burst → ban appears in `snapshot` with metadata; `remove` unbans. |
| E2E | live Docker: metrics non-zero after a burst, ban table lists IP, unban removes it; no console 404. |
| Platform | Docker rebuild of `prx-waf`. |
| Release | `cargo clippy -D warnings` + `cargo test` on touched crates. |

## Harness Delta

- `harness-cli` binary still absent in this checkout → durable rows
  (`story add/update`) not recorded; this markdown story is the artifact. (Not
  fixable here — the binary does not ship in this checkout.)
- Follow-up fixes completed (originally flagged as separate items):
  - **`bans_active` drift fixed:** `dec_bans_active` is now wired into the
    expiry purge path (`get_ddos_metrics`) and the manual-unban path
    (`delete_ban_entry`), so the counter no longer climbs forever. The
    user-facing `active_bans` KPI still uses the authoritative live `len()`.
    (`reset_runtime_state` still clears the table without zeroing the lifetime
    counter — a minor remaining edge, left untouched as it is a separate
    control-plane path.)
  - **`start_tx_velocity_watcher` wired:** FR-012 transaction-velocity config
    (`configs/tx-velocity.yaml`) is now loaded at startup in `main.rs`
    `run_server` (same pattern as the DDoS/rate-limit watchers); previously the
    subsystem was inert.

## Evidence

Verified 2026-06-29 (host `cargo 1.95.0` + rebuilt `prx-waf` Docker image).

- Tests: `waf-engine checks::ddos` 102 unit + `ddos_integration` 22 +
  `ddos_proptest` 11 passed (incl. new `dynamic_ban_table_remove`,
  `dynamic_ban_table_snapshot_excludes_expired`,
  `ban_action_records_level_rps_reason`). `clippy -D warnings` clean on
  `waf-engine`/`waf-api`/`gateway`/`prx-waf`; `rustfmt --check` clean on changed files.
- Live (rebuilt container, `https://localhost:16827`):
  - Baseline: metrics all zero; ban-table `[]`; `DELETE` absent IP → `200`
    idempotent; `DELETE` malformed IP → `400`.
  - After a burst (threshold lowered via the working `PUT /api/ddos/config`):
    `metrics` → `{active_bans:1, bursts_1h:1, bans_issued_1h:1, store_errors:0}`;
    `ban-table` → `[{ip:"192.168.65.1", ban_level:1, last_rps:5, reason:"burst",
    banned_until_ms:…}]` (all real engine state, not the old stub zeros/`[]`).
  - `DELETE /api/ddos/ban-table/192.168.65.1` → `200`; ban-table empties;
    `active_bans` → 0 (lifetime `bans_issued_1h` stays 1, as designed).
  - `audit_log` row: `ddos.unban / ddos_ban / 192.168.65.1`.
- Bootstrap fix: `start_ddos_watcher` is now wired in `main.rs` `run_server`
  (mirrors `start_rate_limit_watcher`), so DDoS detection actually enforces and
  hot-reloads `configs/ddos.yaml`. Without it the engine `ddos_cfg` stayed empty
  and no ban could ever fire (pre-existing bug).
- Follow-up (2026-06-29, same session): `start_tx_velocity_watcher` is now wired
  too (FR-012), and the `bans_active` drift is fixed (decrement on expiry purge
  + manual unban). Verified live after rebuild: all three subsystem watchers log
  "initial config loaded" at startup (`rate_limit`, `ddos`, `tx_velocity`); the
  ddos endpoints still return correct shapes (metrics/ban-table/idempotent unban).
