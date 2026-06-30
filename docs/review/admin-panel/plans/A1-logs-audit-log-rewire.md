# A1 — Logs page: rebuild on a live audit/event source

**G.1 rows:** 1, 2, 3 · **Req IDs:** FR-029 (live request feed), FR-032
(structured audit log) · **Epics:** E12-audit-log (US-1201..1205), decisions
[0009](../../../decisions/0009-audit-log-jsonl-file-sink.md),
[0010](../../../decisions/0010-decommission-victorialogs.md) ·
**Lane:** normal

> Companion: spec §A1. Follows
> [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) (parse-first boundary,
> query side) and [`CONTEXT_RULES.md`](../../../CONTEXT_RULES.md) (normal lane).

---

## 1. Codebase audit (current state)

**Frontend** (`web/admin-panel/src/pages/logs/`):
- `index.tsx` uses `useList({ resource: "logs", dataProviderName: "vlogs" })`.
- The `vlogs` provider is `src/providers/victoria-logs-data-provider.ts`,
  registered in `App.tsx:122-125`; it calls `GET /api/v1/logs/query`
  (`LOGS_QUERY_URL`, line 23), parsing NDJSON rows into `LogRow`
  (`LogsTable.tsx:25-44`: `_time, event_type, rule_name, rule_id, client_ip,
  host, method, path, tier, detail, req_id`).
- `index.tsx:42` calls `GET /api/v1/logs/stats` (the "Entries (24h)" card).
- `LogsFilters.tsx:88` calls `GET /api/v1/logs/streams` (filter dropdowns).

**Backend reality:**
- All three `/api/v1/logs/*` routes were removed with VictoriaLogs
  (decision 0010). They now 404 — confirmed in spec §A1.
- **Discrepancy with spec §A1 (must flag):** spec says re-point at
  `GET /api/audit-log`, claiming it returns request-feed fields
  (`request_id, ts_ms, risk_score, rule_id, action`). The audit shows this is
  **false**. `/api/audit-log` (`security.rs:267`, `list_audit_log`) reads the
  Postgres **admin-action** table `AuditLogEntry`
  (`waf-storage/src/models.rs:719-739`): `admin_username, action,
  resource_type, resource_id, detail, ip_addr, created_at`. It records *who
  changed what in the panel*, not the WAF request feed. It returns
  `{ entries, total }`.
- The **WAF request audit** (FR-032) is the JSONL sink `./waf_audit.log`
  (`waf-engine/src/logging/audit_sender.rs`, decision 0009): fields
  `request_id, ts_ms, ip, method, path, action, risk_score, mode` (+ `rule_id,
  rule_name, host, tier, detail, client_ip, query, event_type`). **There is no
  read API over this file.**
- The closest live, queryable request feed is **`/api/security-events`**
  (Postgres `SecurityEvent`, `models.rs:106-119`): `host_code, client_ip,
  method, path, rule_id, rule_name, action, detail, geo_info, waf_mode,
  created_at`, with a rich `SecurityEventQuery` (`models.rs:323-336`) including
  pagination and `rule_id_prefix`. This already powers the Dashboard live feed
  and TX-Velocity/Rule-Analytics tables.

## 2. Gap & interpretation

The spec's "re-point at `/api/audit-log`" is semantically wrong: it would show
admin actions, not the request/attack log the Logs page is for. Two correct
interpretations:

- **Option A (recommended): re-point Logs at `/api/security-events`.** It is
  live, paginated, already-used, and carries the fields the Logs table renders.
  Satisfies FR-029 (live request feed) for the admin GUI immediately, FE-mostly.
- **Option B: add a read API over the JSONL audit sink** (true FR-032 / SIEM
  view), e.g. `GET /api/audit-log/query` that tails/parses `waf_audit.log`.
  More faithful to FR-032 but introduces file-tailing on the API hot path and a
  new contract.

This plan does **A first** (closes the 404s with correct semantics, normal
lane) and scopes **B as an optional follow-up** behind a story under E12.

## 3. Assumptions (explicit)

- A-1: The Logs page's job is the **request/attack feed**, not admin actions.
  (If product wants admin-action history surfaced, that's a *separate* page.)
- A-2: `/api/security-events` returns `{ data: SecurityEvent[], total }` via the
  default data-provider envelope; pagination is `page`/`page_size`.
- A-3: `created_at` (RFC3339) is acceptable in place of `_time`/`ts_ms` for
  display; `client_ip`→`client_ip`, `rule_name/rule_id/method/path/host_code`
  map directly; `event_type` has no SecurityEvent equivalent (derive from
  `action` or drop the column).
- A-4: No new backend route is required for Option A.
- A-5: VictoriaLogs is permanently gone (dec-0010); deleting its FE provider is
  safe.

## 4. Scope

**In scope (Option A):** repoint Logs page + filters to `/api/security-events`;
remap columns; delete the `vlogs` provider and its registration; remove the
"VictoriaLogs disabled" alert; make "Entries (24h)" use a real count or remove
it; make filter dropdowns client-side or backed by existing query fields.

**Out of scope:** the JSONL read API (Option B, separate story); SIEM export;
LogsQL query language parity (security-events uses structured filters, not
LogsQL — the query bar becomes structured filters or is removed); changing the
audit storage model; surfacing the admin-action `/api/audit-log` in a GUI.

## 5. Phased plan (independently testable & reversible)

### Phase 1 — Repoint the table to `/api/security-events`
- Replace the `vlogs` `useList` in `logs/index.tsx` with the default
  data-provider `useList({ resource: "security-events", pagination, filters })`
  (mirror `tx-velocity/index.tsx` usage).
- Add a boundary mapper `SecurityEvent → LogRow` (parse-first: one typed mapper,
  no scattered `any`).
- **Success:** Logs table renders real rows; Network tab shows
  `GET /api/security-events?...` 200; **zero** requests to any `/api/v1/logs/*`
  (grep built bundle: `rg "/api/v1/logs" web/admin-panel/dist` → no hits).
- **Reversible:** revert the one page file; provider still registered.

### Phase 2 — Filters & "Entries (24h)" card
- Map Event Type / Tier / Rule filters to `SecurityEventQuery` fields
  (`action`, `rule_id_prefix`, `rule_name`); keep client-side filtering for any
  field the query doesn't support.
- "Entries (24h)": derive from `/api/stats/overview?hours=24` (already live) or
  remove the card. Do **not** fabricate a number.
- **Success:** selecting a filter changes the result set (verified against a
  seeded event); 24h card shows a value traceable to a real endpoint or is gone.
- **Reversible:** filter changes are isolated to `LogsFilters.tsx`.

### Phase 3 — Remove dead VictoriaLogs FE code
- Delete `victoria-logs-data-provider.ts`; remove its registration in
  `App.tsx:122-125`; remove the disabled-state alert in `index.tsx:193-204`;
  drop now-unused imports (clean only the orphans *this change* creates).
- **Success:** `rg "vlogs|victoria" web/admin-panel/src` → no hits; app builds
  (`pnpm build`); no console 404s on the Logs page.
- **Reversible:** restore the file + registration from git.

### Phase 4 (optional, separate story) — JSONL read API for true FR-032
- `GET /api/audit-log/query` reading `config.audit.log_path` (bounded tail,
  page/page_size, parse each line parse-first). Route in `server.rs` near 237.
- **Success:** returns last-N JSONL records with the 8 required FR-032 fields;
  integration test writes lines then reads them back.

## 6. Edge cases & failure modes

- Empty store → table shows empty state, not an error (today `/api/audit-log`
  live-returns `{entries:[],total:0}`; security-events returns `{data:[]}`).
- Backend 5xx → surface a retry-able error toast, not a blank page.
- Large `detail`/`query` strings → truncate in cell, full value in row detail.
- Pagination beyond `total` → clamp to last page.
- Mixed/missing fields (`rule_id` null) → mapper supplies safe defaults.
- Time-zone: render `created_at` in the browser locale; keep raw ISO in tooltip.

## 7. Security

- Page is already behind JWT (`require_auth`); `/api/security-events` is in
  `protected_routes`. No new surface in Option A.
- Option B reads a server file: confine to `config.audit.log_path`, never accept
  a path from the client; cap bytes read; treat each line as untrusted input and
  parse at the boundary (ARCHITECTURE parse-first rule).

## 8. Observability

- No new server logs needed for Option A.
- Option B handler emits the canonical one-line JSON per request
  (`request_id, action="audit-log.query", duration_ms, status_code`) per the
  ARCHITECTURE observability contract.

## 9. Production-readiness gaps

- FR-032's intent is a **SIEM-ingestible** stream; `/api/security-events`
  (Postgres) is the GUI view, not the SIEM feed. Production needs either the
  JSONL sink shipped to SIEM (out of band) or Option B as the documented read
  path. Record this in the E12 epic so the GUI fix isn't mistaken for FR-032
  completion.
- Retention/rotation of `waf_audit.log` is not addressed here.

## 10. Harness intake

- **Lane:** normal (touches a public-ish FE contract + a dead nav item; no
  auth/data-loss). Option B escalates to **high-risk** (reads audit/security
  data over a new API → audit/security hard-gate; needs a story packet +
  decision under E12).
- **Story:** create `docs/stories/epics/E12-audit-log/US-12xx-logs-page-rewire.md`
  from `docs/templates/story.md`; link `docs/product/audit-log.md`.
- **Validation:** FE build + manual Network-tab proof (Phases 1–3); integration
  test for Phase 4. Record proof with `harness-cli story update`.
