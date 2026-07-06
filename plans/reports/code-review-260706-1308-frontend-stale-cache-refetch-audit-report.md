# Code Review: frontend-wide audit of save→stale-cache / hydration gaps

**Date:** 2026-07-06 13:08
**Scope:** all 35 pages in `web/admin-panel/src/pages`, following
`debug-260706-1107-ddos-save-stale-cache-on-remount-report.md`.
**Bug family:** Refine `useCustomMutation` never invalidates queries; with global
`staleTime: 30_000` any save must manually refetch the query that hydrates its
form, and hydrate effects must survive react-query structural sharing (identical
payload after refetch → same object reference → payload-dep effect does NOT re-run).

## Verified fixed (from debug report)

All 3 fix sites present and correct:
- `ddos-protection/index.tsx:328` `configQuery.refetch()`
- `risk-scoring/index.tsx:177` `configQuery.query.refetch()`
- `response-filtering/index.tsx:358` `hostFilterQuery.query.refetch()`

Hydrate-effect deps sweep: all config pages depend on stable payload
(`*.result?.data`), none on the rebuilt result wrapper. Matches
fix-260706 report claim ("zero remaining").

## Findings

### F1 — HIGH (data-loss capable): response-filtering PerHostTab — reset effect clobbers hydration on cached host re-select

`response-filtering/index.tsx:331-341`. Effect order in source:

1. hydrate: `form.setFieldsValue(data)` deps `[hostFilterQuery.result?.data]` (line 331)
2. reset: `form.resetFields()` deps `[selectedHostId]` (line 339)

Re-select a previously viewed host while its GET is cached (staleTime 10s, and
beyond — gcTime 5min + structural sharing): both deps change in the same render;
effects run in declaration order → hydrate(saved values) then reset(wipes to
`initialValues` defaults). Nothing re-hydrates afterwards: within staleTime no
refetch fires; after staleTime the background refetch returns an identical
payload → structural sharing keeps the same object reference → hydrate dep
unchanged → effect never re-runs.

**Failure scenario:** select host A → view/save filter → select host B → select
host A again → form silently shows DEFAULTS while UI implies it shows A's config
→ user presses Save → A's real per-host filter is overwritten with defaults.

**Fix direction:** make host switch + hydration one coherent flow — e.g. reset
inside the hydrate path keyed by `selectedHostId`, or move the reset effect
BEFORE the hydrate effect and add `selectedHostId` to the hydrate deps (dep on
`dataUpdatedAt` or `[selectedHostId, data]` so cached data re-hydrates after
reset).

### F2 — MEDIUM: cc-protection hotlink form is write-only — never hydrated from server

`cc-protection/index.tsx:48-86`. Backend exposes
`GET /api/hotlink-config?host_code=…` (`waf-api/src/server.rs:195`,
`handlers.rs:591`) but the page never calls it — no `useCustom` for hotlink at
all. The form always renders empty/defaults.

**Failure scenario:** admin configures hotlink protection for a host → navigates
away → returns (even hard refresh) → form is blank; admin cannot see current
state and can unknowingly overwrite existing per-host settings by saving. Same
user-visible symptom class as the DDoS report, but worse: no refetch can fix it
because there is no query.

**Fix direction:** fetch `/api/hotlink-config?host_code=<selected>` (form is
keyed by `host_code` field — needs a host selector or fetch-on-host_code-blur)
and hydrate; refetch on save success. Mind F1's ordering pitfall when doing so.

### F3 — LOW/MEDIUM: settings "Refresh feeds" gives no visible result — no refetch, and endpoint semantics doubtful

`settings/index.tsx:239-245`. Button under the threat-intel feeds table posts
`/api/rules/reload` and `onSuccess` only toasts. `feedsQuery`
(`/api/threat-intel/feeds`, staleTime 60s, no interval) and `reputationQuery`
(staleTime 120s) are never refetched → entry counts / "Last refresh" stay stale
regardless of what the reload did.

Secondary (PLAUSIBLE, verify intent): `/api/rules/reload` →
`reload_rule_registry` (`rules_api.rs:344`) reloads the RULE registry; no POST
endpoint exists for threat-intel feed refresh (only GET status/feeds). If
`engine.reload_rules()` does not refresh relay.yaml threat-intel feeds, the
button is wired to the wrong action for the table it sits under.

**Fix direction:** at minimum add `feedsQuery.query.refetch()` (+ reputation)
to `onSuccess`; confirm whether a dedicated feed-refresh backend action is
needed.

## Cleared (checked, no issue)

- Enforcement console: all mutations call parent-provided `onRefetch` →
  shared capabilities query refetch. Flush intentionally doesn't (no caps change).
- custom-rules drawer: `onSaved` → `tableQuery.refetch()` + Refine
  useCreate/useUpdate auto-invalidation.
- Standard-resource pages (hosts, certificates, ip-rules, url-rules,
  notifications, sensitive-patterns, tunnels, plugins, bot-management,
  rule-sources, rules-management, geo-restriction, access-lists,
  crowdsec-*): every mutation refetches its backing query.
- cache page: purge actions refetch via `refineCustomRefetch` helper.
- cluster/tokens: token gen doesn't affect any cached query.
- notifications testNotif, relay-intel test, challenge preview: no server
  state change, no refetch needed.
- CreateRuleFromEventModal timers: `previewQuery.query` is the raw TanStack v5
  result (render-stable while query state unchanged) — auto-refresh interval
  wiring is sound.
- settings panel form: only page with proper dirty-guard (revision tracking +
  `suppressDirtyRef`); reference implementation for the systemic note below.

## Systemic note (not a per-page defect)

Except settings' panel form, no hydrate effect guards against clobbering a
dirty form: clicking a Refresh button (or any refetch that returns CHANGED
data) mid-edit silently discards user edits. Config queries have no
refetchInterval so exposure is user-triggered only. If this bites, port the
settings dirty-guard pattern.

## Unresolved Questions

1. F3: is `/api/rules/reload` supposed to refresh threat-intel feeds
   (relay.yaml), or does the feeds table need its own backend refresh action?
2. F2: is hotlink config intentionally write-only (fire-and-forget upsert), or
   was the GET wiring simply never built? Backend GET exists, suggesting the
   latter.
