# A1 Logs — UI Verification (populated rows) + Filter-Restore Scoping

**Date:** 2026-06-29
**Severity:** Low (verification + scoping session; no production code changed)
**Component:** admin-panel (frontend), waf-api, waf-storage, gateway
**Status:** A1 rewire UI-verified end-to-end. Next task (restore 3 filters) scoped, not started.

## What This Session Did

1. **Doc fix (uncommitted):** `crates/waf-api/CLAUDE.md` — "embeds **Vue** admin panel"
   → "embeds **React** admin panel (Refine + AntD)". Verified against
   `web/admin-panel/package.json` (react 18.3, @refinedev/core 5, antd 5) and
   `static_files.rs:1`. One-line edit, **not committed**.

2. **Confirmed `/ui` = the admin-panel FE.** `static_files.rs:11` embeds
   `web/admin-panel/dist/` via `rust-embed`; `server.rs:331-336` serves it as an
   SPA at `/ui/*`. Source you edit → `dist/` (vite build) → re-embedded at
   `cargo` compile. So the A1 rewire isn't live in `/ui` until FE rebuild + waf
   recompile.

3. **A1 logs rewire — UI verification (journal Phase 4 from 2026-06-27, now DONE):**
   - Headless probes: old `/api/v1/logs/query` → **404**; `/api/security-events`
     + `/api/stats/overview?hours=24` → **401** (exist). Running binary's embedded
     bundle: **0** `/api/v1/logs`, **0** `vlogs/victoria`, **31** `security-events`.
   - Browser (agent-browser, `--ignore-https-errors`, login admin/admin123):
     Logs page fires `GET /api/security-events?page=1&page_size=100` +
     `GET /api/stats/overview?hours=24`, **no** v1/logs calls. Filters = Action,
     Rule Name, Client IP, Host Code, Path(contains). Removed filters confirmed
     absent.
   - **Populated rows proof:** generated real traffic (see below) → 5 rows render
     with mapped cols (action→Event, rule_name→Rule, client_ip, host_code→Host),
     footer "Total: 5", page-size 100. Screenshots/HAR in scratchpad (ephemeral).

## How Rows Were Generated (and the 2 gotchas)

To get real `security_events`: created a temp guarded host `test.local`
(code `b9e4f4452fc94353`, port 18080 → upstream 127.0.0.1:9527), sent SQLi/XSS/
RCE/path-traversal attacks → WAF **403** → engine wrote 5 rows (`engine.rs:1015`).

Two pre-existing gateway behaviors discovered (NOT bugs introduced here):
- **`create_host` does not hot-register into the gateway router.** Handler
  (`handlers.rs:61`) only writes DB; `HostRouter` is populated once at startup
  (`main.rs:1631`). New/edited hosts need a **proxy restart** to route.
- **Router registers bare hostname only for ports 80/443** (`router.rs:30`). On
  `:18080` the route key is `test.local:18080`, so the request `Host` header must
  include the port (`Host: test.local:18080`) or it fails closed → 503 +
  `circuit_breaker`/`fail-closed: missing request context` audit line. Requests
  with bare `Host: test.local` never reach the engine, so they land in the JSONL
  audit log only, NOT `security_events`.

## Current Stack State (IMPORTANT for pickup)

- **All processes I started are STOPPED.** waf proxy killed; ports 9527/18080/
  18443 down.
- **Postgres `prx-waf-postgres` (:15432) still UP** — left intentionally.
- **User will restart the server themselves** with their OWN `JWT_SECRET`. (I had
  to restart the proxy with a throwaway secret because the original was exported
  inline in the user's shell and lost on kill. That invalidated old tokens.)
- **Temp host `test.local` DELETED** (host count back to 0).
- **5 synthetic `security_events` rows REMAIN** in DB (demo data from the attacks).
  May want to clear before real use.
- A1 rewire itself is committed (`bd8c84c`). Only the CLAUDE.md Vue→React edit is
  uncommitted.

## NEXT TASK (interrupted /ck-plan — pick up here)

User wants to **re-implement the 3 removed filters: tier, free-text search,
time-range** ("keep the old filters"). Started `/ck:plan`, interrupted for this
journal. **Key reframing from source inspection — this is NOT FE-only:**

`SecurityEventQuery` (`models.rs:323-336`) + `list_security_events` WHERE clause
(`repo.rs:~1858`) currently filter: host_code, client_ip, rule_name, action,
iso_code, country, rule_id, rule_id_prefix, path. The `SecurityEvent` row
(`models.rs:106-119`) has: id, host_code, client_ip, method, path, rule_id,
rule_name, action, detail, geo_info(jsonb), waf_mode, **created_at**. NO tier,
NO search-text column.

Restore feasibility per filter:
- **Time-range — feasible, moderate.** `created_at` exists. Add `from`/`to`
  (DateTime) to `SecurityEventQuery` + `WHERE created_at >= from AND <= to`,
  re-add FE RangePicker + presets. Backend-light. **No hard-gate.**
- **Free-text search — moderate/large.** No text-search column. Either ILIKE
  across path/rule_name/detail (cheap, limited) or tsvector/FTS index (more work).
  Decide scope of "search" (which fields) with user.
- **Tier — BLOCKED without schema change → HIGH-RISK.** `security_events` has no
  `tier` column. Restoring requires: (a) migration adding `tier`, (b) populate it
  at write time (engine `create_security_event`/`db_batch_writer` paths must
  source the tier), (c) query param + FE control. Hits FEATURE_INTAKE hard-gates
  (data model + existing write-path behavior) → **high-risk story + decision**.
  Confirm with user whether tier is worth a migration, or drop it.

Suggested plan shape: split into FE+backend phases; **time-range first** (cleanest
win), **search second**, **tier last** (gated on user decision re: migration).
Relates to deferred **FR-032** (JSONL/SIEM read API) — time-range there too.

## Open Questions

- Clear the 5 synthetic `security_events` demo rows, or keep?
- Tier filter: worth a `security_events` schema migration + engine write-path
  change (high-risk), or drop tier and restore only time-range + search?
- Free-text "search": which columns should it cover (path, rule_name, detail)?
  ILIKE vs full-text index?
- Should time-range be added to `SecurityEventQuery` independently of FR-032, or
  folded into that story?
