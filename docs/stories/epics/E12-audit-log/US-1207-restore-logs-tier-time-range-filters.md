# US-1207 Restore tier + time-range filters on the Security Logs page

## Status

in-progress

## Lane

normal (strong validation — Data-model + Existing-behavior flags)

## Product Contract

The A1 rewire (US-1206, decision 0010) repointed the "Security Logs" page onto
`/api/security-events` and dropped the time-range, tier, and free-text filters,
which that endpoint did not back. This story restores **time-range** and
**tier** by persisting tier to Postgres and extending the query. Free-text
search remains out of scope (dropped by user); true FR-032 (JSONL read API)
stays deferred.

## Relevant Product Docs

- `docs/product/audit-log.md`
- Decision: `docs/decisions/0011-persist-tier-on-security-events.md`
- Predecessor: `docs/stories/epics/E12-audit-log/US-1206-logs-page-rewire.md`
- Journal: `docs/journals/2026-06-27-a1-logs-page-security-events-rewire.md`

## Acceptance Criteria

- New security events persist a non-null `tier` **through the batch-writer path**
  (the production path); pre-migration rows are `tier = NULL`.
- `GET /api/security-events?created_at_from=…&created_at_to=…` narrows to the
  inclusive timestamp window; `tier=Critical,High` narrows to those tiers
  (NULL-tier rows excluded when the tier filter is active); empty `tier=` behaves
  as no filter.
- `total` and pagination stay correct with the new filters; `page_size` clamp
  (≤100) and `ORDER BY created_at DESC` unchanged.
- Frontend: range picker + 1h/6h/24h/7d presets and tier multi-select render, map
  to the new params, and the table reflects filtered results; tier column shown
  and toggleable in the columns picker.
- Default page load shows the **last 1 hour** (changed from all-time — record so
  QA does not misfile as a regression).
- FE inline hint shown when a tier filter is active (NULL-tier rows excluded).
- `cargo test` (touched crates) + `tsc --noEmit` + `vite build` green.

## Design Notes

- Commands: —
- Queries: `GET /api/security-events` (+ `created_at_from`, `created_at_to`,
  `tier`)
- API: backend change — migration `0019_security_events_tier.sql`; `tier` added
  to `SecurityEvent`/`CreateSecurityEvent`; both inserts (single + batch);
  `SecurityEventQuery` + the COUNT/SELECT builder (`repo.rs`).
- Tables: `security_events` gains `tier TEXT` (+ `idx_security_events_tier`).
- Domain rules: tier stored as Debug PascalCase (`Critical|High|Medium|CatchAll`)
  to match the JSONL audit value; FE sends exact PascalCase. Pinned by
  `waf-common/src/tier.rs::tier_debug_format_is_pascal_case`.
- Timestamp contract: FE sends `Z`-suffixed RFC3339 (`dayjs().toISOString()`); a
  `+00:00` offset would URL-decode its `+` to a space and 400 the request.
  Malformed timestamps are rejected at the axum `Query` extractor (400) before
  reaching storage — they never produce a 500.
- Error surface (finding 12): `ApiError::Storage` maps to 500 with the
  `StorageError` Display (Postgres driver message), not the parameterized SQL or
  user input; all filter values bind as parameters. Route stays behind
  `require_auth` + admin-IP + rate-limit (`server.rs:152`,`:313`).
- UI surfaces: `web/admin-panel/src/pages/logs/*`, `types/api.ts`.

## Deploy Ordering

Roll out the backend (binary + migration `0019`) **fully before** the FE bundle
that exposes the tier/time filters:

- FE-first → an old backend silently drops the unknown `tier` param (serde
  ignores unknown query keys) → the filter no-ops and looks broken.
- During a rolling backend deploy, old nodes write NULL tier until all nodes are
  new → recent events transiently vanish under a tier filter.

## Validation

`scripts/bin/harness-cli` is not present in this checkout — proof recorded here
+ in git rather than via `harness-cli story update`.

| Layer | Expected proof |
| --- | --- |
| Unit | `waf-common` tier Debug-format pinning test ✅ |
| Integration | `waf-storage` `repo_security_events_filters` (time-range inclusive, tier select + NULL exclusion, empty=no-filter, **batch-path tier persistence**, filter×pagination) ✅; `repo_security_events` (no regression) ✅; `waf-api` `middleware_jwt::security_events_route_no_token_401` ✅ |
| E2E | Manual: generate events at >1 tier through the batch writer, confirm new rows non-null tier, `created_at_from/to` + `tier=` narrow table & pager `total`, clearing tier un-filters, pagination works with a time filter — **PENDING** (requires running stack) |
| Platform | `cargo test` (waf-common/storage/engine/api touched suites) ✅ · `npm run type-check` ✅ · `npm run build` ✅ |
| Release | Migration `0019` applies on fresh DB (verified by `db_migrate_and_broadcast`) ✅ |

## Harness Delta

- `scripts/bin/harness-cli` still absent from this checkout (as in US-1206);
  proof recording fell back to story file + git.

## Evidence

- Plan: `plans/260630-0956-g1-logs-tier-timerange-filters/`
- Red-team review: 14 findings, all accepted (3 Critical / 4 High / 5 Medium /
  2 Low); findings 1–7 applied as full fixes, 8–14 folded into phase notes.
- Tests: see Validation table — all automated suites green.
