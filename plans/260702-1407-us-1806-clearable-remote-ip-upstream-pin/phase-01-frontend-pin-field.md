---
phase: 1
title: "Frontend pin field"
status: pending
effort: "S"
---

# Phase 1: Frontend pin field

## Overview

Add an optional "Upstream IP (pin)" field to the shared Add/Edit Host dialog so
operators can view, set, and clear `remote_ip`. This is the actual fix for GH
#171.

## Related Code Files

- Modify: `web/admin-panel/src/types/api.ts` (`Host` interface, ~line 45-63)
- Modify: `web/admin-panel/src/pages/hosts/index.tsx`
  - `HostFormShape` (line 27-42)
  - `DEFAULT_FORM` (line 61-76)
  - `onOpenEdit` `setFieldsValue` (line 121-136)
  - shared `renderForm` upstream `Space.Compact` (line 250-257)
- Modify: `web/admin-panel/src/i18n/locales/{en,vi,zh}.json` (`hosts.*` keys)

## Why the payload plumbing works

`onSubmit`/`onEditSubmit` send `{ ...DEFAULT_FORM, ...values }`. Today
`remote_ip` is in neither `DEFAULT_FORM` nor the form, so it is **omitted** from
the JSON body → backend `COALESCE($8, remote_ip)` keeps the old pin (the bug).
Once `remote_ip` is a registered `Form.Item` with a `DEFAULT_FORM` default of
`""`, `validateFields()` always returns a string:

- untouched empty field → `""` → `COALESCE('', remote_ip)` = `''` → proxy filter
  (`proxy.rs:473`) treats empty as no-pin → routes to `remote_host`.
- typed IP → `"1.2.3.4"` → stored → proxy dials it.
- edit with existing pin → `onOpenEdit` pre-fills the value → visible + re-sent.

No backend change needed.

## Implementation Steps

1. **TS type** — in `api.ts`, add to `Host`:
   ```ts
   /** Upstream IP pin. When non-empty, the proxy dials this IP instead of
    *  resolving remote_host (bypasses container DNS). Empty = use remote_host. */
   remote_ip?: string;
   ```

2. **Form shape + default** — in `index.tsx`:
   - Add `remote_ip: string;` to `HostFormShape`.
   - Add `remote_ip: "",` to `DEFAULT_FORM` (guarantees a string is always sent,
     so clear works and create defaults to no-pin).

3. **Edit population** — in `onOpenEdit` `setFieldsValue`, add
   `remote_ip: host.remote_ip ?? "",` so an active pin is visible on open
   (satisfies the "make active pin visible" AC).

4. **Form field** — in `renderForm`, add a `Form.Item name="remote_ip"` after the
   `remote_host`/`remote_port` `Space.Compact` (line 257). Optional field (no
   `required` rule); use a `Tooltip` matching the `preserve_host`/`http_redirect`
   pattern. Placeholder e.g. `203.0.113.10`. Help text: clearing the field routes
   to the hostname.
   ```tsx
   <Form.Item
     name="remote_ip"
     label={
       <span>
         {t("hosts.remoteIpPin")}&nbsp;
         <Tooltip title={t("hosts.remoteIpPinTooltip")}>
           <InfoCircleOutlined style={{ color: "#8c8c8c" }} />
         </Tooltip>
       </span>
     }
   >
     <Input placeholder="203.0.113.10" allowClear />
   </Form.Item>
   ```

5. **i18n** — add `hosts.remoteIpPin` and `hosts.remoteIpPinTooltip` to all three
   locale files (`en`, `vi`, `zh`). Tooltip explains: pins the upstream IP,
   bypassing DNS; leave empty to route to the hostname; a set pin overrides the
   Upstream field. Keep the existing per-file style (English is fine as a
   placeholder for vi/zh if no translator, but add the keys to all three so the
   UI does not show raw key strings).

## Success Criteria

- [ ] `Host.remote_ip?: string` present in `api.ts`.
- [ ] Add Host dialog shows an empty "Upstream IP (pin)" field; creating with it
  empty stores no pin.
- [ ] Edit Host dialog on a pinned host pre-fills the field with the current pin.
- [ ] Clearing the field and saving sends `remote_ip: ""` in the request body
  (verify via network tab / integration in phase 3).
- [ ] `remoteIpPin` + `remoteIpPinTooltip` keys exist in en/vi/zh; no raw i18n
  keys render in the dialog.
- [ ] `npm run build` / `tsc` passes (phase 3).

## Risk Assessment

- **Undefined vs empty string:** AntD `Input` with `initialValues`+`DEFAULT_FORM`
  default of `""` yields `""` (not `undefined`) when cleared. Confirm in phase 3
  — if a cleared field ever yields `undefined`, the body omits `remote_ip` and
  the pin is not cleared. Mitigation is the `DEFAULT_FORM` default plus the
  `{ ...DEFAULT_FORM, ...values }` spread already in the submit handlers.
- **Create path:** `CreateHost.remote_ip` is `Option<String>`; sending `""`
  inserts an empty pin (harmless, filtered by proxy). Acceptable.
