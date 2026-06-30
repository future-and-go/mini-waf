# A2 — Response Filtering: preview endpoint + per-host API

**G.1 rows:** 4, 5, 6 · **Req IDs:** FR-033 (response filtering), FR-034
(sensitive field redaction), FR-035 (header leak prevention) ·
**Lane:** high-risk

> Companion: spec §A2. High-risk per
> [`FEATURE_INTAKE.md`](../../../FEATURE_INTAKE.md) (data-model change +
> response hot path + existing behavior). Read
> [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) (parse-first, command/query) and
> `docs/templates/high-risk-story/*` before implementing.

---

## 1. Codebase audit (current state)

**Frontend** (`web/admin-panel/src/pages/response-filtering/index.tsx`):
- Global tab loads/saves `GET`/`PUT /api/panel-config`
  (`PanelConfig.response_filtering`: `categories{stack_trace,verbose_error,
  secrets,internal_ip}, json_redact_fields[], max_body_bytes`) — **works**.
- Preview widget `POST /api/response-filtering/preview` — request
  `{ body, content_type }`, reads `data.data.result` (lines 171-178) — **404**.
- Per-Host tab: `GET /api/hosts` then `GET`/`PUT /api/hosts/{id}/response-filter`
  with `HostResponseFilter` (lines 35-41): `body_scan_enabled,
  body_scan_max_body_bytes, internal_patterns[], header_blocklist[],
  strip_server_header` — **both 404**.

**Backend reality:**
- No `/api/response-filtering/*` routes/handlers; no `/api/hosts/{id}/
  response-filter` route (`server.rs` host routes stop at `/api/hosts/{id}`,
  lines 127-130). Confirmed absent.
- The **runtime engine exists** in `crates/gateway/src/filters/`:
  - `response_json_field_redactor.rs` — reusable: `CompiledRedactor::build(hc:
    &HostConfig)`, `redact_bytes(&self, &[u8]) -> Option<Vec<u8>>`,
    `is_json_content_type(ct)`.
  - `response_header_blocklist_filter.rs` (FR-035, reads
    `HostConfig.header_blocklist`), `response_server_policy_filter.rs`
    (`HostConfig.strip_server_header`), `response_via_strip_filter.rs`,
    `response_location_rewriter.rs`. Header chain built at
    `proxy.rs:390-396`; body filters (mask/scan/redact) run in
    `response_body_filter`.
  - Body scanner reads `HostConfig.body_scan_enabled,
    body_scan_max_body_bytes, internal_patterns, mask_token`.
- **Storage:** per-host config flows DB `Host.defense_json`
  (`models.rs:9-36`) → `DefenseConfig` (`waf-common/types.rs`) →
  `HostConfig` at boot (`prx-waf/src/main.rs:1637-1662`) and on API CRUD
  (`handlers.rs:64-90`, `127-135`) → `router.register()`.
- **Critical gap:** the DB→`HostConfig` mapping only fills `defense_config`. The
  response-filter fields the FE wants (`header_blocklist, strip_server_header,
  body_scan_enabled, body_scan_max_body_bytes, internal_patterns`) are
  **`HostConfig` fields that are currently only set from TOML / defaults**, not
  from `defense_json`. So even if we persist them, the proxy won't read per-host
  overrides until the mapping is wired.

## 2. Gap

1. No preview API. 2. No per-host GET/PUT API. 3. No persistence path for
per-host response-filter settings. 4. No DB→`HostConfig` wiring for those fields.

## 3. Assumptions (explicit)

- A-1: Per-host response-filter settings are stored inside the existing
  `Host.defense_json` JSONB under a `response_filter` key (no new column / no
  migration) — matches the "shape mirrors partial config, unknown keys ignored"
  contract (`models.rs:245-249`).
- A-2: Preview runs the **global** response-filter config (panel-config), since
  the FE preview sends only `{ body, content_type }` with no host id.
- A-3: Preview must not perform network I/O or touch a real upstream; it runs
  the redactor/scanner in-process over the supplied body.
- A-4: `redact_bytes` returning `None` means "no change"; preview then echoes the
  input unchanged.
- A-5: Reusing gateway filter code from `waf-api` is acceptable; if a dependency
  cycle results, extract the pure redaction core into a shared crate (decide in
  design.md). **Confirm before coding** (Karpathy "think before coding").

## 4. Scope

**In scope:** `POST /api/response-filtering/preview`; `GET`/`PUT
/api/hosts/{id}/response-filter`; persist under `defense_json.response_filter`;
wire DB→`HostConfig` for the five fields; integration test proving the proxy
applies a per-host override.

**Out of scope:** new redaction algorithms (reuse existing engine); a global
preview that also simulates header filters (preview is body-redaction only
unless product asks); per-route (sub-host) overrides; migrating `defense_json`
to typed columns.

## 5. Phased plan (independently testable & reversible)

### Phase 1 — Preview endpoint (read-only, no storage)
- New handler `preview_response_filter` (in `security.rs`, co-located with
  sensitive-patterns). Parse-first DTO `{ body: String, content_type: String }`.
- Build a transient `HostConfig`/`CompiledRedactor` from the **global**
  panel-config redaction settings; run `redact_bytes`; return
  `{ "data": { "result": String } }` (FE reads `data.data.result`).
- Route `.route("/api/response-filtering/preview",
  post(preview_response_filter))` before `server.rs:313`.
- If `waf-api`→`gateway` dep is undesirable, extract the redactor core first
  (see A-5).
- **Success:** POST a body containing a stack trace + a JSON `card_number` →
  response shows redacted text; non-JSON `content_type` with no internal
  patterns → unchanged echo; unit test on the handler with 3 fixtures.
- **Reversible:** delete handler + route line.

### Phase 2 — Per-host read API (GET)
- `get_host_response_filter` (in `handlers.rs`, next to `update_host`): read
  `Host.defense_json.response_filter`, default the five fields if unset, return
  the `HostResponseFilter` shape.
- Route `.route("/api/hosts/{id}/response-filter",
  get(get_host_response_filter))` after `server.rs:130`.
- **Success:** GET for a host with no stored filter returns documented defaults
  (200, not 404); GET for a seeded host returns stored values.
- **Reversible:** delete handler + route.

### Phase 3 — Per-host write API (PUT) + persistence
- `put_host_response_filter`: parse-first `HostResponseFilter`, validate
  (regex compile-check `internal_patterns`; `body_scan_max_body_bytes` bounds),
  merge into `defense_json.response_filter`, persist via `db.update_host`.
- Re-register `HostConfig` after write (mirror `update_host`).
- **Success:** PUT then GET returns the saved values; invalid regex → 400 with
  a clear message; values survive a process restart (DB-backed).
- **Reversible:** PUT only writes a sub-key; revert handler/route to disable.

### Phase 4 — Wire DB→`HostConfig` so the proxy honors overrides
- In the boot loader (`main.rs:1637-1662`) and API CRUD
  (`handlers.rs:64-90`, `127-135`), map
  `defense_json.response_filter.*` onto the corresponding `HostConfig` fields
  (`header_blocklist, strip_server_header, body_scan_enabled,
  body_scan_max_body_bytes, internal_patterns`).
- **Success:** gateway integration test — a host with `strip_server_header:true`
  + a `header_blocklist` entry + an `internal_patterns` match → the proxied
  response has the header stripped and the pattern masked; a host without
  overrides keeps defaults.
- **Reversible:** the mapping is additive; removing it reverts to default-only.

## 6. Edge cases & failure modes

- Invalid regex in `internal_patterns` → reject at PUT (do not poison the proxy).
- Huge `body` in preview → cap at `max_body_bytes`; reject oversize with 413.
- Non-UTF-8 body bytes → operate on bytes; preview returns lossy display string
  but never panics.
- `content_type` not JSON → skip JSON redactor, still run internal-pattern mask.
- Concurrent PUT + host update → last-write-wins on `defense_json`; document it.
- Redactor returning `None` (no match) → echo input (Phase 1).
- Host id not found → 404 (distinct from "no filter set" → defaults).

## 7. Security (hard gate)

- Response filtering is a **security control**: a broken per-host config must
  **fail safe** — on parse/compile error keep the previous effective config, do
  not silently disable filtering.
- Never leak secrets via preview echo logs: do **not** log request/response
  bodies of the preview endpoint.
- All inputs parsed at the boundary into typed DTOs (ARCHITECTURE parse-first).
- Endpoint behind `require_auth`; per-host PUT is a config mutation → audit it
  (admin-action audit log) with `resource_type=host_response_filter`,
  `resource_id=host_id`.

## 8. Observability

- Canonical JSON log line per request for all three endpoints
  (`request_id, user_id, action, duration_ms, status_code`).
- On PUT, emit an admin audit record (command side owns audit side effects —
  ARCHITECTURE command/query rule).
- Add a gateway debug counter for "per-host response-filter applied" to confirm
  Phase 4 wiring in staging.

## 9. Production-readiness gaps

- `defense_json` is untyped JSONB; persisting structured config there trades a
  migration for runtime parse risk — mitigated by strict parse-first + defaults.
- The redactor is regex/field based; document its limits (no semantic detection,
  no streaming-across-chunk guarantees beyond `apply_chunk`).
- Preview tests the global config only; per-host preview (with a host id) is a
  likely future ask — note it so users don't assume preview reflects per-host.

## 10. Harness intake

- **Lane:** high-risk (FR-033/034/035 touch the response hot path; data-model
  change in `defense_json`; existing behavior). Hard gates: audit/security,
  data model.
- **Story packet:** `docs/stories/epics/` — create under a response-filtering
  epic (or new `E18-admin-api-completeness`); fill `overview.md`, `design.md`
  (resolve A-5 dep decision), `execplan.md`, `validation.md`.
- **Decision:** record a `docs/decisions/NNNN-per-host-response-filter-storage.md`
  if `defense_json` becomes a durable contract surface.
- **Validation:** unit (preview), integration (per-host GET/PUT + proxy
  application), regression (global config still works).
