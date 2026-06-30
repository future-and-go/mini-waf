# 0011 Persist protection tier on security_events

Date: 2026-06-30

## Status

Accepted

## Context

The admin-panel "Security Logs" page was repointed from the decommissioned
VictoriaLogs API onto the Postgres-backed `/api/security-events` feed (US-1206,
decision 0010). That endpoint had no backing for the **tier** filter, so it was
removed. Restoring it requires the protection tier to be queryable.

The tier (`Critical | High | Medium | CatchAll`) is computed per request as
`ctx.tier` and was already written to the JSONL audit sink, but **not** to the
Postgres `security_events` row. A query API over the write-only `waf_audit.log`
JSONL (true FR-032) is an oversized, deferred high-risk effort.

## Decision

Persist `tier` as a nullable `TEXT` column on `security_events`, populated at
insert time from `format!("{:?}", ctx.tier)` — the same Debug expression the
JSONL audit sink uses — and extend `SecurityEventQuery` with a `tier` filter
(plus `created_at_from`/`created_at_to`). This keeps the existing indexed,
server-paginated query path.

The column is **forward-only**: rows written before migration `0019` keep
`tier = NULL`.

## Alternatives Considered

1. Build a query API over the `waf_audit.log` JSONL (true FR-032) — oversized,
   deferred high-risk; rejected for this scope.
2. Ship time-range only and defer tier — leaves out the field the user
   specifically asked to restore; rejected.

## Consequences

Positive:

- Tier filter served by the same indexed, paginated path as the other filters;
  no new read API or data source.
- Persisted tier matches the JSONL audit value exactly, so the two sinks agree.

Tradeoffs:

- **NULL-tier rows are excluded whenever a tier filter is active.** Pre-migration
  events have no tier and silently drop out of a tier-filtered view. This is a
  deliberate Existing-behavior change (intake flag), surfaced in the UI by an
  inline hint on the filter panel. A deferred option is an explicit
  "Unknown (pre-tier)" bucket (`tier IS NULL`) if users need it.
- **Tier string format is pinned to Debug PascalCase** (`CatchAll`, not
  `catch_all`). The `Tier` enum also derives serde `rename_all = "snake_case"`;
  switching the persisted value to serde serialization would silently break the
  frontend filter equality. Do **not** switch to serde serialization without
  updating both the FE filter strings and the pinning test
  (`waf-common/src/tier.rs::tier_debug_format_is_pascal_case`).
- Migration `0019` builds a non-concurrent index, taking a brief write-blocking
  lock at boot. Accepted at benchmark/dev scale; re-evaluate (build
  `CONCURRENTLY` via a maintenance task) before any large-table deploy.

## Follow-Up

- Re-evaluate the index build strategy and `COUNT(*)` cost before large-scale
  deploys (confirm `security_events` row count first).
- Deploy ordering: roll out the backend (binary + migration) fully before the FE
  bundle that exposes the tier/time filters — see US-1207.
