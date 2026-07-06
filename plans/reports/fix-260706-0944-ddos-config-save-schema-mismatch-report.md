# Fix: DDoS config save 400 — FE schema mismatch

## Summary

- Symptom: PUT /api/ddos/config → 400 `invalid ddos config: unknown field ban_durations_secs, expected one of schema_version, enabled, hot_reload, tiers, gc_interval_s, max_keys, redis` on every Save click.
- Root cause (confirmed, matches `debug-260705-2331-ddos-config-schema-mismatch-risk-save-report.md`): admin-panel DDoS page built against a draft schema never implemented backend-side. FE sent `{per_ip, per_fingerprint, ban_durations_secs, store}`; backend `DdosFileConfig` (`deny_unknown_fields`, `crates/waf-engine/src/checks/ddos/config.rs:34`) accepts `{schema_version, enabled, hot_reload, tiers, gc_interval_s, max_keys, redis}`. Save could never succeed.
- Fix: FE-only rewrite of the config form to mirror `DdosFileConfig` exactly. Backend contract untouched.

## Changes

1. `web/admin-panel/src/pages/ddos-protection/index.tsx`
   - `DdosConfig` model = backend schema: `schema_version`, `enabled`, `hot_reload`, `tiers{critical|high|medium|catch_all}`, `gc_interval_s`, `max_keys`, `redis?`.
   - Tier cards ×4 with per-tier enable switch; disabled tier → `null` in payload (= not DDoS-protected, engine semantics).
   - Optional redis card (url / key_prefix / op_timeout_ms); off → `redis: null` (memory-only).
   - Dropped ban-escalation-ladder card: ban durations are hardcoded backend-side (`BanSchedule` 60s/5m/1h), the card edited nothing real.
   - GET side fixed too: previously only `enabled` matched, all other fields silently showed hardcoded defaults; now full config hydrates form + toggles.
2. `web/admin-panel/src/i18n/locales/en.json` — `ddos` block realigned to page keys (was already drifted); zh/vi never had the block, untouched.
3. `crates/waf-api/src/ddos_api.rs` — 2 contract tests locking the exact FE payload shape (tiers with nulls, redis null/present): deserialize + `validate()` + YAML round-trip through engine parser. Backend schema drift now breaks CI instead of prod saves.

## Verification

- `cargo test -p waf-api --lib ddos_api` → 2/2 pass; full `--lib` suite 124/124 pass.
- `npx tsc --noEmit` clean; `npm run build` succeeds.
- Only DDoS page consumes `ddos.*` i18n keys (grep-verified); no other blast radius. Backend untouched except added tests.
- Note: fix is in the FE bundle — the `prx-waf` container must be rebuilt (admin panel embedded via rust-embed) before Save works in the running deployment.

## Deliberate scope cuts

- Ban ladder NOT made operator-configurable (open product question in debug report); card removed instead — YAGNI, backend hardcodes it.
- Collaterals 3/4 from the debug report (challenge.yaml corruption, device-fp.yaml unknown field, write-without-validation pattern in challenge/device-fp APIs) NOT fixed here — separate work items.

## Unresolved Questions

- Should `BanSchedule` (60s/5m/1h) become configurable in `ddos.yaml`? If yes, backend schema + FE card come back together.
- Working-tree `configs/{challenge,device-fp,risk,tier-policies}.yaml` still carry last night's panel-save mutations (challenge.yaml is engine-rejected) — restore/repair pending separate fix.
