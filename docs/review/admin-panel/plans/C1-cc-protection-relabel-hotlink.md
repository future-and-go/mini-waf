# C1 — CC Protection: relabel page + hotlink GET wire-up

**G.1 rows:** 12, 13 · **Req IDs:** FR-004 (rate limiting), FR-005 (DDoS),
FR-007/FR-035 (anti-hotlink / referer) · **Lane:** tiny (hotlink GET, relabel)
→ normal + decision (if adding real CC controls)

> Companion: spec §C1. Follows [`ARCHITECTURE.md`](../../../ARCHITECTURE.md)
> and [`CONTEXT_RULES.md`](../../../CONTEXT_RULES.md).

---

## 1. Codebase audit (current state)

**Frontend** (`web/admin-panel/src/pages/cc-protection/index.tsx`):
- The page makes **zero** rate-limit / CC / DDoS / challenge calls. It does:
  - LB backends CRUD: `useList`/`useCreate`/`useDelete` on `lb-backends` →
    `/api/lb-backends` (`LbBackend = { id, host_code, backend_host,
    backend_port, is_healthy }`).
  - Anti-hotlink: `POST /api/hotlink-config` via `useCustomMutation`
    (`HotlinkForm = { host_code, enabled, allow_empty_referer, redirect_url? }`,
    lines 29-34). It **never GETs** existing config; the form only has
    `initialValues: { enabled:true, allow_empty_referer:true }` (line 159).
- Labels: `nav.ccProtection` = "CC Protection" (`i18n/locales/en.json:11`);
  `ccProtection.title` = "CC Protection & Rate Limiting"
  (`en.json:420-421`). Route/resource `cc-protection` (`App.tsx:83,162`,
  `nav-items.ts:103`).

**Backend reality:**
- `GET /api/hotlink-config?host_code=<code>` exists (`handlers.rs:590-616`,
  `get_hotlink_config`, route `server.rs:183-186`). Requires `host_code` or
  returns 400; live returns `{ "data": null }` when unset.
- `upsert_hotlink_config` body is `UpsertHotlinkConfig` (`models.rs:424-430`):
  `{ host_code, enabled?, allow_empty_referer?, allowed_domains?, redirect_url? }`
  — note `allowed_domains` exists in the backend but not in the FE form.
- Real "CC" (HTTP-flood) controls live in `Host.defense_json`
  (`cc, cc_rps, cc_burst, cc_ban_threshold`, `waf-common/types.rs:873-887`) and
  in `/api/ddos/*` + `/api/challenge/*`.
- **Important:** the `defense_json` CC fields are **schema-only** — no engine
  check currently reads `cc_rps/cc_burst/cc_ban_threshold` in production (only
  test assertions). So adding a "CC editor" bound to them would be **write-only**
  until engine enforcement is implemented.

## 2. Gap

- The page name implies CC/rate-limit but the page only does LB + hotlink →
  misleading (FR-004 appears wired but isn't).
- The hotlink form is write-only (no load of saved state).

## 3. Assumptions (explicit)

- A-1: The minimal, honest fix is **(a) relabel** the page to match its real
  function + **(b) load hotlink config on host-select**. This is what spec §C1
  recommends as tiny work.
- A-2: Adding real per-host CC controls is **deferred**: it requires engine
  enforcement of `cc_*` fields first, else it's a write-only form that misleads
  users — explicitly out of scope here, recorded as a decision/story.
- A-3: Renaming is i18n + nav label only; the route/resource key
  `cc-protection` stays (renaming the URL would break bookmarks; out of scope).

## 4. Scope

**In scope:** rename page title + nav label across `en/vi/zh` i18n; add a
`useCustom` GET of `/api/hotlink-config?host_code=` on host-select to populate
the form.

**Out of scope:** new CC/rate-limit endpoints; binding a form to `defense_json`
`cc_*`; engine enforcement of `cc_*`; changing the route key; surfacing
`allowed_domains` (note it but don't add unless asked).

## 5. Phased plan (independently testable & reversible)

### Phase 1 — Hotlink GET wire-up (FE-only, tiny)
- On host selection, `useCustom({ url: "/api/hotlink-config", query: {
  host_code } })`; when `data.data` is non-null, set the form fields; when null,
  fall back to current defaults.
- Guard the call so it isn't fired without `host_code` (backend 400s otherwise).
- **Success:** opening the form for a host that has saved hotlink config shows
  its stored `enabled/allow_empty_referer/redirect_url`; a host with no config
  shows defaults; no 400 in the Network tab.
- **Reversible:** one-file revert.

### Phase 2 — Relabel page (i18n, tiny)
- Update `nav.ccProtection` and `ccProtection.title` in `en.json` / `vi.json` /
  `zh.json` to reflect actual function (e.g. "Load Balancer & Anti-Hotlink").
- **Success:** sidebar + page header read the new name in all three locales;
  `rg` confirms no stale "CC Protection & Rate Limiting" title remains.
- **Reversible:** i18n-only revert.

### Phase 3 (deferred, decision-gated) — real CC controls
- Only after engine enforcement of `defense_json.cc_*` exists: add a per-host
  rate-limit editor bound to those fields + `/api/ddos/config`.
- **Success criteria (future):** editing `cc_rps` changes enforced behavior in a
  gateway integration test.

## 6. Edge cases & failure modes

- Host with no `host_code` selected → don't call GET; keep form disabled/empty.
- GET returns `{ data: null }` → treat as "no config", use defaults (not error).
- Switching hosts rapidly → cancel/ignore stale responses (Refine query keying).
- Backend 400 (missing host_code) → should never happen if guarded; surface as a
  dev warning, not a user error.

## 7. Security

- Both calls behind `require_auth`. No new mutation in Phases 1–2.
- Hotlink `redirect_url` is reflected to clients at runtime — validation belongs
  to the existing POST handler; this change doesn't alter it.

## 8. Observability

- No new server logs (GET already logs canonically). No audit change (read-only).

## 9. Production-readiness gaps

- FR-004 (rate limiting) is **not** truly enforced via the GUI today; relabeling
  prevents a false impression but doesn't deliver CC controls. Production-ready
  CC requires the deferred Phase 3 (engine + API + GUI).
- `allowed_domains` is a backend field with no GUI — note for completeness (see
  also G2 wire-ups).

## 10. Harness intake

- **Lane:** tiny for Phases 1–2 (copy/names + read-only wire-up). Phase 3 is
  normal + a `docs/decisions/` entry (scope change to CC enforcement).
- **Story:** tiny work records an intake row; Phase 3 needs a story under FR-004.
- **Validation:** FE manual proof (form loads saved state; labels updated);
  `pnpm build`.
