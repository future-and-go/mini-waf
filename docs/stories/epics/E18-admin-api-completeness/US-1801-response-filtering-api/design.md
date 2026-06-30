# Design

## Domain Model

`HostResponseFilter` — the five per-host response-filter knobs the FE edits and
the engine consumes. Defined once in `waf_common::types` (leaf crate) so both
`waf-api` and `prx-waf` share the parse + mapping:

```rust
pub struct HostResponseFilter {
    pub body_scan_enabled: bool,            // FR-033
    pub body_scan_max_body_bytes: u64,      // FR-033
    pub internal_patterns: Vec<String>,     // AC-17 (regex)
    pub header_blocklist: Vec<String>,      // AC-15 / FR-035
    pub strip_server_header: bool,          // AC-16 / FR-035
}
```

Defaults mirror `HostConfig::default()` (so GET returns the real effective
defaults). `HostConfig::apply_response_filter(&HostResponseFilter)` copies the
five fields onto a `HostConfig`. `HostResponseFilter::from_defense_json(&Value)`
extracts the `response_filter` sub-object when present.

## Application Flow

- **Query** `GET /api/hosts/{id}/response-filter`: load host →
  `HostResponseFilter::from_defense_json(defense_json)` or
  `HostResponseFilter::default()` → return.
- **Command** `PUT /api/hosts/{id}/response-filter`: parse-first
  `HostResponseFilter` → validate (regex compile-check `internal_patterns`;
  `body_scan_max_body_bytes` bounds) → merge into `defense_json.response_filter`
  → `db.update_host` → rebuild + `router.register` `HostConfig` (now applying
  the response-filter fields) → write audit record (command owns the side
  effect).
- **Query** `POST /api/response-filtering/preview`: read global
  `WafPanelConfig.response_filtering` from the panel TOML → build a transient
  `HostConfig` (`body_scan_enabled = block_stack_traces`,
  `redact_extra_fields = json_redact_fields`) → run FR-033 scanner then FR-034
  redactor over the supplied body → return the result string.

## Interface Contract

| Route | Method | Request | Response |
| --- | --- | --- | --- |
| `/api/response-filtering/preview` | POST | `{ body: string, content_type: string }` | `{ success, data: { result: string } }` |
| `/api/hosts/{id}/response-filter` | GET | — | `{ success, data: HostResponseFilter }` |
| `/api/hosts/{id}/response-filter` | PUT | `HostResponseFilter` | `{ success, data: HostResponseFilter }` |

Errors: `404` host not found; `400` invalid regex / out-of-range bytes /
oversize preview body (`413` for body over cap). All behind `require_auth`.

The FE reads `data.data.result` for preview and `data` for the host filter
(matches `response-filtering/index.tsx`).

## Data Model

No schema change. Per-host settings persist as
`Host.defense_json.response_filter` (JSONB sub-object). See decision 0011.
Reuse `UpdateHost.defense_json` (`COALESCE($17, defense_json)` in `repo.rs`).

## UI / Platform Impact

None — the FE already calls these exact routes with the exact contract. No
frontend change required.

## Observability

- One canonical JSON log line per request (existing tower-http trace layer +
  per-handler `tracing`).
- PUT emits an admin audit record via `db.create_audit_log` with
  `action = "update_host_response_filter"`, `resource_type =
  "host_response_filter"`, `resource_id = host_id`, admin username + client IP.
- Preview must **not** log request/response bodies (may contain secrets).

## Alternatives Considered

1. **Reuse the gateway redactor/scanner directly vs extract a shared core**
   (plan A-5). Resolved: `waf-api` already depends on `gateway`
   (`Cargo.toml:12`), so it reuses `gateway::filters::{CompiledScanner,
   CompiledRedactor, apply_body_scan_chunk}` and `gateway::context::BodyScanState`
   directly. No dependency cycle, no new shared crate.
2. **Per-category preview** (map FE `categories` toggles) — not viable: FR-033
   uses a built-in all-or-nothing catalog (`body_scan_enabled`). Preview maps
   `block_stack_traces` → enable scanner; documented limitation.
