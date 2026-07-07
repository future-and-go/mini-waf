# Phase 2 — Frontend: engine-shape tier-policies form + end-to-end verification

## Context

- `web/admin-panel/src/pages/tier-policies/index.tsx` (697 lines) — rewrite to engine schema
- Engine shapes (phase 1 / `waf_common`): `TierConfig { default_tier, classifier_rules, policies }`; `CachePolicy` tagged `{ mode, ttl_seconds? }`; rules `{ priority, tier, host? {kind,value}, path? {kind,value}, method? (UPPERCASE[]), headers? [{name,value}] }`
- `web/admin-panel/src/pages/dashboard/index.tsx:81,190,538-549` — `RiskBandPreview` reads only `policies.<tier>.risk_thresholds` → survives unchanged (verify, don't edit)
- `web/admin-panel/src/pages/settings/index.tsx:513` — comment reference only

## Steps

1. Replace FE types with the engine schema (mirror serde exactly; JSON casing: tiers/kinds/modes snake_case, methods UPPERCASE).
2. Rework the form:
   - Per-tier policy cards: `fail_mode` radio, `ddos_threshold_rps` number, `cache_policy` mode select + conditional `ttl_seconds` input, thresholds sliders with `allow < challenge < block` client check.
   - `default_tier` selector.
   - Classifier-rule editor (shrunk scope per user): editable fields are priority, tier, path kind+value, methods multi-select ONLY. `host`/`headers` are NOT editable this round — but must round-trip: keep full rule objects in state, render existing host/headers as read-only badges, and never strip them on save (PUT sends the complete `TierConfig`).
   - Defaults aligned with shipped `tier-protection.toml` values (not the old 20/60/85).
3. Dry-run widget: send `{ method, path, host? }`; render `matched_tier` + policy summary (drop `matched_rule_id`).
4. GET/PUT keep `/api/tier-policies` endpoints; payload is the `TierConfig` JSON.
5. Match existing page conventions (Refine + AntD patterns used by risk/ddos pages); keep single-page module unless sibling pages already split.

## Verification (workflow gates)

1. `npm run build` (or repo's tsc+lint scripts) in `web/admin-panel` — clean.
2. `cargo test -p waf-api` + touched-crate clippy — green (phase 1 re-check after any contract tweak).
3. Walk touchpoints: dashboard `RiskBandPreview`, nav/App routes, settings comment — no regression.
4. **code-reviewer subagent (mandatory)**: acceptance criteria from `plan.md`, blast radius (`server.rs` routes, `AppState` ctor sites, config profiles), contract-change callouts, pattern conformance.
5. **tester subagent (mandatory)**: full `cargo test -p waf-api`, FE build, shipped-config regression suites.

## Risk / rollback

FE-only shape change riding on phase 1's API; revert commit restores previous page. No other consumer of the endpoints (grep-verified).
