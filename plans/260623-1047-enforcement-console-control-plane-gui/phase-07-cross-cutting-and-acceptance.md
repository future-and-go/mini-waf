---
phase: 7
title: "Cross-cutting and Acceptance"
status: pending
priority: P2
dependencies: [4, 5, 6]
effort: "M"
---

# Phase 7: Cross-cutting and Acceptance

## Overview

Apply the cross-cutting states/i18n/theme/a11y requirements across all surfaces
and verify the full spec §10 acceptance checklist. This is the gate before the
feature is considered done.

## Requirements

### States (all console surfaces)
- **Loading:** `Skeleton`/`Spin` on first capabilities load; keep last good data on
  refetch (React-Query `keepPreviousData` / `placeholderData`).
- **Error:** capabilities fetch fail → page-level `Alert type="error"` + retry.
- **Interop disabled:** if the backend signals disabled (per Phase 1 decision —
  e.g. 404), show `Result status="info"` "Control plane is disabled in config
  (`interop.enabled = false`)." — never crash.
- **Empty unsupported:** never render the warning when `unsupported` is empty.

### i18n / theme / a11y
- All strings via `t()`; keys under `nav.control`, `enforcement.*` present in
  `en/vi/zh` with real translations.
- Colors via `theme.useToken()` tokens; action convention enforce = success green,
  log_only = warning amber; no hardcoded hex outside `ModeTag`.
- Keyboard-operable selects, visible focus, confirm modals trap focus (antd
  defaults); mode pill has `aria-label`.

## Architecture

No new modules — this phase hardens existing ones. Centralize the loading/error/
disabled handling in `enforcement/index.tsx` so child sections render only when
`caps` resolves. The disabled-state detection must match the Phase 1 backend
behavior (confirm the exact status/shape before wiring the `Result`).

## Related Code Files

- Modify: `web/admin-panel/src/pages/enforcement/index.tsx` — loading/error/
  disabled gating wrapping catalog + plane map + runtime ops.
- Modify (as needed): catalog, plane-map, mode-pill, runtime-ops for focus/aria/
  token-color compliance.
- Modify: `web/admin-panel/src/i18n/locales/{en,vi,zh}.json` — fill any missing
  keys; ensure parity across locales.
- Verification only (no code): production build for the secret grep.

## Implementation Steps

1. Add loading/error/disabled gating in `index.tsx`; confirm disabled shape with
   Phase 1.
2. Sweep all new components for hardcoded hex (move to tokens/`ModeTag`), missing
   `t()` calls, and a11y (focus/aria).
3. Reconcile i18n keys across `en/vi/zh` (no missing keys; no English placeholders
   in vi/zh).
4. Run the full acceptance checklist below and record results.

## Success Criteria (spec §10 acceptance)

- [ ] No `X-Benchmark-Secret` in the built FE bundle:
      `cd web/admin-panel && npm run build && grep -ri "benchmark-secret\|X-Benchmark-Secret" dist/` → no matches.
- [ ] Catalog renders all 17 features + policies; effective mode = policy>feature>default.
- [ ] Feature/policy toggles call correctly-scoped `set-profile`; siblings unaffected.
- [ ] `unsupported[]` surfaced after every apply; never swallowed; clears on clean apply.
- [ ] `ddos_protection.per_tier` shown with known-gap warning; not hidden.
- [ ] Default-mode change confirmed; clears overrides (`scope:"all"`).
- [ ] Reset shows `audit_log_preserved: true`; flush handles not-supported gracefully.
- [ ] Mode pill reflects live default mode + override count; links to console.
- [ ] X-WAF-Mode visible in event detail + live feed (backed by Phase 2 data).
- [ ] Governance plane map renders; footer note present; deep-links work.
- [ ] interop-disabled backend → informative `Result`, no crash.
- [ ] All strings i18n (en/vi/zh); theme tokens only; `tsc --noEmit` clean.
- [ ] Backend: `cargo test` green for the routes (Phase 1) and waf_mode (Phase 2).

## Risk Assessment

- **Hidden secret in source maps / env.** Mitigated by grepping `dist/` after a
  real build, not just `src/`.
- **Locale gaps shipping as raw keys.** Mitigated by the parity reconcile + a
  key-diff check across the three locale files.
- **Disabled-state shape mismatch** with Phase 1. Mitigated by confirming the
  exact status/body before wiring the `Result`.

Rollback: this phase is hardening; reverting individual gates degrades gracefully
to the per-surface behavior from Phases 4–6.
