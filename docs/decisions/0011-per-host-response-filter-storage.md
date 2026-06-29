# 0011 Store per-host response-filter settings inside `Host.defense_json`

Date: 2026-06-29

## Status

Accepted

## Context

The admin panel's Response Filtering page (`/ui/#/response-filtering`,
`web/admin-panel/src/pages/response-filtering/index.tsx`) ships a **Per-Host**
tab that calls `GET`/`PUT /api/hosts/{id}/response-filter` with a
`HostResponseFilter` shape:

```jsonc
{ "body_scan_enabled": bool, "body_scan_max_body_bytes": number,
  "internal_patterns": string[], "header_blocklist": string[],
  "strip_server_header": bool }
```

Both routes currently 404 (gap spec A2b / G.1 rows 5–6). The runtime engine that
consumes these five fields already exists and reads them straight off
`waf_common::HostConfig` (`strip_server_header`, `header_blocklist`,
`internal_patterns`, `body_scan_enabled`, `body_scan_max_body_bytes`), wired by
the merged FR-033/034/035 PRs (#19/#18/#14) and the AC-15/AC-16/AC-17 filters in
`crates/gateway/src/filters/`. Only the admin **API surface** and the
**DB → `HostConfig`** mapping for these fields are missing.

The host row (`crates/waf-storage/src/models.rs:Host`) already carries an
untyped `defense_json: Option<serde_json::Value>` JSONB column that flows into
`HostConfig` at boot (`prx-waf/src/main.rs`) and on API CRUD
(`waf-api/src/handlers.rs`). The decision is **where** per-host response-filter
settings should live.

## Decision

Persist per-host response-filter settings as a `response_filter` sub-object of
the existing `Host.defense_json` JSONB column. No new column, no migration.

- `PUT /api/hosts/{id}/response-filter` parse-first-validates a typed
  `HostResponseFilter`, merges it under `defense_json.response_filter`, and
  persists via the existing `db.update_host` path. Invalid `internal_patterns`
  regexes are rejected at the boundary (400) so a bad config can never poison
  the proxy (fail-safe).
- `GET` reads `defense_json.response_filter`, returning documented defaults
  (mirroring `HostConfig::default()`) when unset — `200`, never `404`.
- The DB → `HostConfig` mapping (boot loader + API CRUD) applies
  `defense_json.response_filter.*` onto the five `HostConfig` fields **only when
  the sub-object is present**, so hosts that never set it keep the existing
  `HostConfig` defaults (no behavior change).

A shared typed `HostResponseFilter` DTO + `HostConfig::apply_response_filter`
helper live in `waf-common::types` so both `waf-api` and `prx-waf` map the same
way (single source of truth, parse-first).

## Alternatives Considered

1. **Dedicated typed column(s) on the hosts table** — rejected for v1: requires
   a migration and schema churn for five fields that the `defense_json`
   contract already accommodates ("shape mirrors partial config, unknown keys
   ignored"). Revisit if `defense_json` grows unwieldy.
2. **A new `host_response_filter` table** — rejected: 1:1 with host, no
   independent lifecycle, adds a join and a second write path for no benefit.
3. **Reuse the global `/api/panel-config` only (no per-host)** — rejected: the
   FE explicitly exposes per-host overrides and the engine reads per-host
   `HostConfig` fields; global-only would leave the Per-Host tab dead.

## Consequences

Positive:

- Closes gap spec A2b; the Per-Host tab loads, saves, and survives restart.
- No migration; backward compatible — absent `response_filter` ⇒ defaults.
- Proxy honors per-host overrides via the existing `router.register` reload.

Tradeoffs:

- `defense_json` is untyped JSONB; structured config there trades a migration
  for runtime parse risk — mitigated by strict parse-first + `#[serde(default)]`
  + fail-safe (keep previous effective config on parse error).
- Last-write-wins between a host update and a response-filter PUT on the same
  `defense_json` blob (documented).

## Follow-Up

- Preview (`POST /api/response-filtering/preview`) intentionally runs the
  **global** panel-config (`WafPanelConfig.response_filtering`), not a per-host
  config; a per-host preview is a likely future ask.
- `harness-cli` binary is absent in this checkout, so the durable decision row
  (`harness-cli decision add`) could not be recorded; register it once the CLI
  is present.
