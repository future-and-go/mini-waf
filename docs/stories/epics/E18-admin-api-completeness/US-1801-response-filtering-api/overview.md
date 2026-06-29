# Overview

Plan: `docs/review/admin-panel/plans/A2-response-filtering-api.md`.
Gap spec: `admin-panel-gap-remediation-spec.md` §A2 (G.1 rows 4, 5, 6).
Req IDs: FR-033 (response filtering), FR-034 (sensitive field redaction),
FR-035 (header leak prevention).

## Current Behavior

- `POST /api/response-filtering/preview` → **404** (never built). The Global
  tab's Preview widget always errors.
- `GET`/`PUT /api/hosts/{id}/response-filter` → **404** (never built). The whole
  Per-Host tab fails to load and cannot save.
- The runtime engine exists and reads the five per-host fields off
  `waf_common::HostConfig` (AC-15/16/17 + FR-033/034 filters), but the
  DB→`HostConfig` mapping only fills `defense_config` — the response-filter
  fields come from `HostConfig::default()` / TOML, never from `defense_json`.
- `GET`/`PUT /api/panel-config` (Global tab config) works.

## Target Behavior

- `POST /api/response-filtering/preview` runs the **global** panel-config
  response-filter rules over a supplied `{ body, content_type }` and returns
  `{ data: { result } }` redacted/scanned text. Read-only, no network I/O.
- `GET /api/hosts/{id}/response-filter` returns the host's
  `HostResponseFilter` (documented defaults when unset; `200`, not `404`).
- `PUT /api/hosts/{id}/response-filter` validates + persists the filter under
  `defense_json.response_filter`, re-registers the host config, and audits the
  mutation.
- The proxy honors the persisted per-host overrides (boot loader + API CRUD map
  `defense_json.response_filter.*` onto `HostConfig`).

## Affected Users

- Admin / operator (admin panel Response Filtering page).

## Affected Product Docs

- `docs/review/admin-panel/plans/A2-response-filtering-api.md`
- `docs/decisions/0011-per-host-response-filter-storage.md`

## Non-Goals

- New redaction algorithms (reuse the existing engine).
- Per-route (sub-host) overrides.
- Migrating `defense_json` to typed columns.
- A per-host preview (preview is global-config only).
- Fixing the Global tab's `categories`/`max_body_bytes` panel-config schema
  mismatch (separate, pre-existing, out of A2 scope — noted, not changed).
