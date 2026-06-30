# C2 — TX Velocity: config read/write API + hot-reload wiring

**G.1 row:** 14 · **Req IDs:** FR-012 (Transaction Velocity & Sequence),
FR-031 (hot config) · **Lane:** normal

> Companion: spec §C2. Follows [`ARCHITECTURE.md`](../../../ARCHITECTURE.md)
> (parse-first, command/query) and [`CONTEXT_RULES.md`](../../../CONTEXT_RULES.md).

---

## 1. Codebase audit (current state)

**Frontend** (`web/admin-panel/src/pages/tx-velocity/index.tsx`):
- KPIs + events table are **real** via `GET /api/security-events?rule_id_prefix=
  TX-SEQ-/TX-WITHDRAW-/TX-LIMIT-/TX-` (`rule_id_prefix` supported,
  `models.rs:323-336`).
- The "Config thresholds" card (lines 268-291) is a **hardcoded, read-only**
  `Descriptions` block; text from i18n (`en.json:622-625`); comment says "no REST
  API for FR-012 config". Thresholds live in `configs/tx-velocity.yaml`,
  hand-edited.

**Backend reality:**
- **No `tx_velocity_api.rs`**, no `/api/tx-velocity/*` route, not in `lib.rs`.
- Engine config types exist: `TxVelocityDocument` / `TxVelocityFileConfig`
  (`crates/waf-engine/src/checks/tx_velocity/config.rs`).
- `configs/tx-velocity.yaml` (root key `tx_velocity:`), fields:
  `schema_version, enabled, session_cookie, signal_cooldown_ms, session_ttl_secs,
  janitor_period_secs, endpoint_roles[]{role,path},
  classifiers{ sequence{min_human_ms}, withdrawal_velocity{max_count,window_ms},
  limit_change_velocity{max_count,window_ms} }`. Rust adds `dedupe_window_ms`
  (default 5000), not on disk.
- **Established pattern to mirror:** `/api/ddos/config`
  (`ddos_api.rs`): `resolve_path(state,"configs/ddos.yaml")`, typed struct,
  `{ success, data: <inner object> }`, PUT validates + atomic `.tmp`+rename.
  Challenge uses a FE-flattening variant; **DDoS is the closer fit** (typed,
  inner object).
- **Hot-reload gap:** `engine.start_tx_velocity_watcher(path)` exists but is
  **never called from `prx-waf/src/main.rs`** (only rate-limit is wired). So a
  PUT writes the file but the engine won't pick it up until the watcher is
  bootstrapped → FR-031 would not actually hold.

## 2. Gap

- No read/write API for the TX-velocity thresholds.
- Even with an API, hot-reload won't apply changes until the watcher is wired.

## 3. Assumptions (explicit)

- A-1: Mirror the **DDoS** pattern (typed `TxVelocityFileConfig`, response
  `{ success, data: <tx_velocity inner object> }`, `resolve_path`, atomic write).
- A-2: PUT accepts the inner object (no `tx_velocity:` wrapper), validates, wraps
  back under `tx_velocity:` on write — same as DDoS.
- A-3: `endpoint_roles[].role` is the fixed enum `login|otp|deposit|withdrawal|
  limit_change`; validate against it.
- A-4: Wiring the watcher in `main.rs` is required for the acceptance criterion
  "hot-reload picks it up without restart"; include it as a phase.
- A-5: The FE thresholds card becomes an editable form mapping 1:1 to the config.

## 4. Scope

**In scope:** new `tx_velocity_api.rs` with `GET`+`PUT /api/tx-velocity/config`;
register module + route; bootstrap `start_tx_velocity_watcher` in `main.rs`;
turn the FE card into an editable form.

**Out of scope:** changing TX-velocity detection logic; adding new classifiers;
per-host TX config; the parallel DDoS watcher gap (mention it, fix under B1/own
task); migrating other configs.

## 5. Phased plan (independently testable & reversible)

### Phase 1 — Read API (`GET /api/tx-velocity/config`)
- New `tx_velocity_api.rs` copying `ddos_api.rs`'s `resolve_path` + read flow;
  parse `TxVelocityDocument`; return `{ success, data: <inner> }`; missing file →
  documented defaults.
- Add `pub mod tx_velocity_api;` to `lib.rs`; route before `server.rs:313`.
- **Success:** GET returns the parsed `configs/tx-velocity.yaml` contents as
  JSON; integration test with a fixture file; missing file → defaults, not 500.
- **Reversible:** remove module + route line.

### Phase 2 — Write API (`PUT /api/tx-velocity/config`)
- Parse-first into `TxVelocityFileConfig`; validate (`role` enum; positive
  `*_ms`/`*_count`; `min_human_ms` sane); atomic `.tmp`+rename write.
- **Success:** PUT then GET round-trips; invalid role / negative window → 400
  with message; the on-disk YAML is valid and re-loadable; partial/garbage body
  rejected before any write (no half-written file).
- **Reversible:** revert handler; file writes are atomic so no corruption risk.

### Phase 3 — Bootstrap hot-reload watcher in `main.rs`
- Call `engine.start_tx_velocity_watcher(resolve("configs/tx-velocity.yaml"))`
  at startup (mirror the rate-limit watcher wiring).
- **Success:** with the watcher running, a PUT (or manual file edit) is reflected
  in engine behavior without restart — integration/E2E asserting a threshold
  change alters classification; bad file → engine retains previous snapshot
  (fail-soft) and logs a warn.
- **Reversible:** remove the one bootstrap call (engine falls back to load-once).

### Phase 4 — Editable FE form
- Replace the hardcoded `Descriptions` card with a form (mirror
  `ddos-protection` config form) bound to GET/PUT.
- **Success:** editing a threshold + Save persists to YAML and reloads on
  refresh; validation errors surface inline.
- **Reversible:** one-file revert to the static card.

## 6. Edge cases & failure modes

- Missing config file → GET returns defaults; PUT creates the file (mkdir).
- Concurrent PUT + manual edit → atomic write + watcher debounce (200ms) handles
  it; last-write-wins.
- Invalid regex in `endpoint_roles[].path` → reject at PUT (it's compiled by the
  engine).
- Schema drift (`dedupe_window_ms` absent on disk) → default applied; PUT should
  preserve/echo it.
- Watcher fail-soft: bad YAML keeps the prior snapshot, never crashes the proxy.

## 7. Security

- Behind `require_auth`. PUT mutates a security-control config → record an admin
  audit entry (`action="tx-velocity.config.update"`).
- `resolve_path` is server-derived from `main_config_file`; never accept a path
  from the client.
- Validate all numeric bounds at the boundary to prevent pathological configs
  (e.g. zero windows causing div-by-zero or unbounded memory).

## 8. Observability

- Canonical per-request JSON log on both handlers.
- On successful reload, the engine already logs; ensure PUT logs the new
  effective `schema_version`/key fields (without secrets).

## 9. Production-readiness gaps

- FR-031 (hot config) is **not actually wired** for tx-velocity (and ddos) today
  — Phase 3 is the real production fix; without it the API is "edit then restart".
- No config schema versioning/migration story beyond `schema_version: 1`.
- No RBAC granularity (any admin can edit thresholds).

## 10. Harness intake

- **Lane:** normal (config persistence + public contract; mirrors existing
  endpoints). Phase 3 touches startup/runtime behavior → stronger validation.
- **Story:** `docs/stories/epics/` under FR-012; from `docs/templates/story.md`.
- **Validation:** unit (validation), integration (round-trip + watcher reload),
  FE manual. Record with `harness-cli story update`.
