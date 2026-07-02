---
title: "US-1806 Clearable upstream IP pin"
description: ""
status: pending
priority: P2
branch: "main-harness"
tags: []
blockedBy: []
blocks: []
created: "2026-07-02T07:10:16.964Z"
createdBy: "ck:plan"
source: skill
---

# US-1806 Clearable upstream IP pin

## Overview

Fix GH #171: editing a host's Upstream has no effect when a `remote_ip` pin is
set. Root cause is FE-only — the `Host` TS type and Add/Edit Host dialog have no
`remote_ip` field, so operators can neither see nor clear a pin.

**Backend needs no code change.** Verified against `main`:

- `Host` (`models.rs:9`) derives `Serialize` with `pub remote_ip:
  Option<String>` and `list_hosts` returns rows via `SELECT *` → `GET
  /api/hosts` **already returns `remote_ip`**.
- `UpdateHost.remote_ip` (`models.rs:283`) is already `Option<String>` and bound
  in `update_host` (`repo.rs:104`, `$8`).
- Proxy already prefers the pin only when non-empty:
  `remote_ip.as_deref().filter(|s| !s.is_empty()).unwrap_or(&remote_host)`
  (`proxy.rs:470-474`). An **empty-string** pin → falls back to `remote_host`.
- `remote_ip = COALESCE($8, remote_ip)` means `null` keeps the old value, but
  `""` sets the column to `''` (COALESCE only guards NULL). So **empty-string
  clear works end-to-end today** without dropping COALESCE.

Therefore the fix = wire `remote_ip` into the FE form so clear sends `""`. The
COALESCE drop is explicitly **out of scope** (empty-clear chosen over NULL-clear
per story Design Notes).

## Scope

- **In:** FE `Host` type + Add/Edit dialog field + edit population + i18n;
  backend repo test proving empty-string clears the effective pin.
- **Out:** DB migration (none), route changes (none), dropping COALESCE, proxy
  code changes. Effective-upstream table column is an optional stretch (AC says
  field value alone is sufficient).

## Lane

Normal. Risk flags: Public contracts (adds `remote_ip` to a client-visible
response shape — additive, non-breaking), Existing behavior (fixes it). No auth,
authz, data-loss, or migration. 1-2 flags → normal.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Frontend pin field](./phase-01-frontend-pin-field.md) | Pending |
| 2 | [Backend proof](./phase-02-backend-proof.md) | Pending |
| 3 | [Verify](./phase-03-verify.md) | Pending |

## Acceptance Criteria (from US-1806)

- [ ] Add/Edit Host dialog exposes optional "Upstream IP (pin)" field showing
  current `remote_ip`; can set or clear it (clear sends `""`).
- [ ] `Host` type + form payload include `remote_ip`; `GET /api/hosts` returns it
  (already true — assert in verify).
- [ ] After clearing pin + save, proxy routes to `remote_host` on next request
  (no restart, no SQL).
- [ ] After setting/changing pin + save, proxy dials the new IP.
- [ ] Active pin is visible in the UI (pre-populated field value is sufficient).
- [ ] No schema migration; routes unchanged.

## Dependencies

None. Standalone bug fix; no cross-plan blocking relationships found in the
`plans/` scan.
