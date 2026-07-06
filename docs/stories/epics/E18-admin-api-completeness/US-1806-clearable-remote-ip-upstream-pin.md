# US-1806 Clearable upstream IP pin — editing Upstream takes effect

## Status

planned

## Lane

normal

Source: GitHub issue [#171](https://github.com/future-and-go/mini-waf/issues/171)
(bug: editing host Upstream has no effect when `remote_ip` is set).

## Product Contract

Editing a host's Upstream in the admin UI must change where traffic is routed.
When a host has a pinned upstream IP (`remote_ip`), the operator must be able to
view it, change it, and clear it from the Edit/Add Host dialog — with no manual
SQL. A pin that is currently shadowing the hostname must be visible in the UI.

## Relevant Product Docs

- Proxy upstream selection: `crates/gateway/src/proxy.rs:466-474`.
- Host update repo: `crates/waf-storage/src/repo.rs:103` (`update_host`).
- Host model: `crates/waf-storage/src/models.rs` (`UpdateHost.remote_ip`).
- Admin API handlers: `crates/waf-api/src/handlers.rs`.
- FE host page + type: `web/admin-panel/src/pages/hosts/index.tsx`,
  `web/admin-panel/src/types/api.ts`.

## Root Cause (verified against `main`)

1. Proxy prefers `remote_ip` over `remote_host`:
   `remote_ip.filter(!empty).unwrap_or(&remote_host)` — a stale pin silently
   shadows the visible Upstream. SNI still uses `remote_host`, so TLS looks
   correct and masks the bug.
2. `remote_ip = COALESCE($8, remote_ip)` — sending `null` keeps the old value.
3. The `Host` TS interface and Edit/Add Host dialog have no `remote_ip` field,
   so the FE never reads or writes it.

Key nuance: the proxy already does `.filter(|s| !s.is_empty())`, so an
**empty-string** `remote_ip` clears the pin under current logic
(`COALESCE('', remote_ip)` → `''` → proxy falls back to `remote_host`). The FE
change is the necessary fix; dropping `COALESCE` is optional.

## Acceptance Criteria

- Add/Edit Host dialog exposes an optional "Upstream IP (pin)" field that shows
  the current `remote_ip`, and can set or clear it (clear sends `""`).
- `Host` type + form payload include `remote_ip`; `GET /api/hosts` returns it.
- After clearing the pin and saving, the proxy routes to `remote_host` on the
  next request (no restart, no manual SQL).
- After setting/changing the pin and saving, the proxy dials the new IP.
- UI makes an active pin visible when it shadows the hostname (field value is
  sufficient; a banner or effective-upstream display is a plus).
- No schema migration; routes unchanged.

## Design Notes

- Commands: edit/add host from admin panel.
- Queries: `GET /api/hosts` includes `remote_ip` in the response.
- API: `UpdateHost.remote_ip` already `Option<String>`; empty string clears via
  existing proxy filter. Only drop `COALESCE($8, remote_ip)` if NULL-clear is
  preferred over empty-clear (not required).
- Tables: `hosts.remote_ip` (TEXT since migration 0014); no change.
- Domain rules: `remote_ip` bypasses container DNS; empty/NULL means "use
  remote_host".
- UI surfaces: Hosts page → Add/Edit Host dialog; optional effective-upstream
  column.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id US-1806 --unit 1 --integration 1 --e2e 0 --platform 0`
(harness-cli not built in this checkout — record proof status when available).

| Layer | Expected proof |
| --- | --- |
| Unit | `update_host` with `remote_ip: Some("")` clears the effective pin; proxy `upstream_connect_host` falls back to `remote_host` when `remote_ip` empty. |
| Integration | Edit host to clear pin → `GET /api/hosts` shows empty `remote_ip` → next proxied request reaches `remote_host`. |
| E2E | Admin panel: edit Upstream on a host with an active pin, clear the pin, confirm traffic moves. |
| Platform | n/a |
| Release | n/a |

## Harness Delta

None. `harness-cli` binary absent in this checkout; story registered as a file
only.

## Evidence

- Issue review comment: https://github.com/future-and-go/mini-waf/issues/171#issuecomment-4863040704
