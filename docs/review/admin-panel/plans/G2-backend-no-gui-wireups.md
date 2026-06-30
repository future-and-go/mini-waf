# G2 — Wire up backend endpoints that have no GUI

**G.2 rows** · **Req IDs:** FR-010/011 (device fingerprint conflicts), FR-009
(smart caching) · **Lane:** tiny → normal (all FE-only wire-ups of existing,
verified endpoints)

> Companion: spec §G.2 / §E. The hotlink-config GET wire-up (also in G.2) is
> covered by [C1](C1-cc-protection-relabel-hotlink.md). Follows
> [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) and
> [`CONTEXT_RULES.md`](../../../CONTEXT_RULES.md).

---

## 1. Codebase audit (current state)

All endpoints below exist, are registered, and are verified — they simply have
no GUI consumer:

- **`GET /api/device-fp/conflicts`** — `list_fp_conflicts`, route
  `server.rs:291`. The Device-Fingerprinting page
  (`device-fingerprinting/index.tsx`) has tabs `capture` + `behavior` and calls
  `/api/device-fp/config` + `/api/device-fp/recent`, but **never** calls
  `/conflicts` (confirmed: no usage anywhere in `src/`). `fp_conflict` appears
  only as a config provider key (line 259).
- **Cache endpoints** (`server.rs:226-235`):
  - `DELETE /api/cache/host/{host}` — `cache_flush_host`
  - `DELETE /api/cache/key` — `cache_flush_key`
  - `GET /api/cache/tags` — `cache_list_tags`
  The Cache page (`cache/index.tsx`) uses `stats`, `backend`, `stats/timeseries`,
  `routes/top`, `purge/tag`, `purge/route`, and `DELETE /api/cache` (flush all)
  — but **not** the three above.

## 2. Gap

Working, security/observability-relevant capabilities (conflict detection,
targeted cache purge, tag browsing) are invisible to operators.

## 3. Assumptions (explicit)

- A-1: The endpoints' response shapes are already correct; this is pure FE
  consumption (no backend change). Verify each shape against its handler before
  building the UI.
- A-2: Device-FP conflicts is additive (a new tab); cache additions are new
  controls on the existing page.
- A-3: `DELETE /api/cache/key` takes the key in the body/query as the handler
  expects — confirm the exact contract before wiring the input.

## 4. Scope

**In scope:** a "Conflicts" tab on Device Fingerprinting; per-host purge button,
per-key purge input, and a tag browser on the Cache page.

**Out of scope:** changing any backend endpoint; new endpoints; the hotlink GET
wire-up (see C1); cache eviction policy changes.

## 5. Phased plan (each independently testable & reversible)

### Phase 1 — Device-FP "Conflicts" tab (FE-only)
- Add a tab using `useCustom("/api/device-fp/conflicts")`; render
  fingerprint↔IP conflicts in a table (columns from the handler's response).
- **Success:** the tab loads real conflict rows (or an empty state); Network tab
  shows `GET /api/device-fp/conflicts` 200; no regression on existing tabs.
- **Reversible:** one-file revert (remove the tab).

### Phase 2 — Cache per-host purge (FE-only)
- Add a "Purge host" control calling `DELETE /api/cache/host/{host}`.
- **Success:** purging a host returns success and subsequent stats reflect the
  purge; confirm against a seeded cached host.
- **Reversible:** remove the control.

### Phase 3 — Cache per-key purge (FE-only)
- Add a key input calling `DELETE /api/cache/key` (per the handler's contract).
- **Success:** purging a known key removes it; invalid/missing key handled
  gracefully (handler's error surfaced).
- **Reversible:** remove the control.

### Phase 4 — Cache tag browser (FE-only)
- Add a tag list via `GET /api/cache/tags`; allow selecting a tag → reuse the
  existing `POST /api/cache/purge/tag`.
- **Success:** tags list loads; selecting + purging a tag works end-to-end.
- **Reversible:** remove the browser section.

## 6. Edge cases & failure modes

- Empty conflicts / empty tags → empty states, not errors.
- Purge of a non-existent host/key/tag → surface the handler's response
  (idempotent success or 404) clearly; never imply a purge that didn't happen.
- Large conflict/tag lists → paginate or cap with a "show more".
- Destructive purge actions → confirm dialog before firing DELETE.

## 7. Security

- All behind `require_auth`. Cache purges are state mutations → confirmation +
  the handlers' existing audit/logging apply; do not add new unauthenticated
  paths.
- Treat user-entered cache keys/hosts as untrusted; the handlers own validation,
  but the FE must URI-encode path/segment values.

## 8. Observability

- No new server logs (endpoints already log). Surface action results (success/
  error counts purged) to the operator in the UI.

## 9. Production-readiness gaps

- Conflict data is only useful if FR-010/011 detection is active; confirm it
  produces conflicts in the running system before claiming the tab "complete".
- Bulk purge ergonomics (purge many keys) are not covered — flag if operators
  need it.

## 10. Harness intake

- **Lane:** tiny per item (FE wire-ups of existing endpoints); the cache purge
  controls touch destructive operations → normal-leaning validation
  (confirmation + proof).
- **Validation:** FE manual proof per phase (Network tab + observed effect);
  `pnpm build`. Record intake rows.
