# Debug: DDoS config save 400 + risk config save failure

## Executive Summary

Two reported issues, two different root causes:

1. **DDoS save 400 (`unknown field ban_durations_secs`)** — REAL, still broken. The
   admin-panel DDoS page was built against a draft schema that was never implemented
   backend-side. FE sends `{per_ip, per_fingerprint, ban_durations_secs, store}`;
   backend `DdosFileConfig` (`deny_unknown_fields`) only accepts
   `{schema_version, enabled, hot_reload, tiers, gc_interval_s, max_keys, redis}`.
   Save can NEVER succeed with current code.
2. **Risk config save** — ALREADY FIXED and verified working live. Failure was the
   known null-`paths` bug (fixed in #234/#235, merged tonight 22:51/23:10). The
   `prx-waf` container was rebuilt 23:35:43 and restarted 23:35:50; logs show 3
   successful saves + `risk: hot-reload OK` at 23:36:26/:32/:38. `configs/risk.yaml`
   now round-trips (all 6 `waf-api` risk tests + engine regression test pass).

Collateral damage found during investigation (not user-reported, empirically proven):

3. **`configs/challenge.yaml` corrupted by challenge save** — engine parser now
   rejects it (`token.cookie_max_age: invalid type: unit value, expected u32`).
4. **`configs/device-fp.yaml` rejected by engine parser**
   (`providers[0]: unknown field enabled`).

## Root Cause 1 — DDoS page schema mismatch

Chain (verified):

1. `web/admin-panel/src/pages/ddos-protection/index.tsx:36-67` — FE `DdosConfig` model:
   `enabled, per_ip{threshold_rps,window_secs}, per_fingerprint{...}, ban_durations_secs[3], store{backend,redis_url}`.
   Page dates to PR #114 ("Admin Panel add gap requirement") — written before backend FR-005 landed.
2. Backend contract `crates/waf-engine/src/checks/ddos/config.rs:32-55` — `DdosFileConfig`
   with `#[serde(deny_unknown_fields)]`: `schema_version, enabled, hot_reload,
   tiers{critical|high|medium|catch_all → per_fp_threshold/per_fp_window_s/per_tier_threshold/per_tier_window_s},
   gc_interval_s, max_keys, redis{url,key_prefix,op_timeout_ms}`.
3. `crates/waf-api/src/ddos_api.rs:52-54` (`put_ddos_config`) — `serde_json::from_value::<DdosFileConfig>`
   → 400 `invalid ddos config: unknown field ban_durations_secs, expected one of ...`
   (exact user error; serde reports first unknown field).
4. GET side half-broken too: backend returns tier shape; FE only matches on `enabled`
   (`index.tsx:163`), every other form field silently falls back to hardcoded `DEFAULT_CONFIG`.
   Admin is editing values that do not reflect the live config.

Ban durations are NOT config at all backend-side: escalation ladder is hardcoded in
`BanSchedule` (`crates/waf-engine/src/checks/ddos/action/ban.rs` — 60s / 5m / 1h).

**Fix direction:** rewrite the DDoS page form to mirror `DdosFileConfig`
(tiers × 4 thresholds, gc_interval_s, max_keys, optional redis). Ban-escalation ladder:
either drop the UI card or extend backend schema — product decision (see questions).

## Root Cause 2 — Risk save (resolved, evidence)

- Prior state: `configs/risk.yaml` had `canary.paths:` = explicit YAML null →
  `serde_json::from_value::<RiskConfig>` 500 on GET, and PUT died in the same
  `current_risk_node` merge (documented in
  `plans/reports/debug-260705-1620-risk-config-endpoint-500-null-canary-paths-report.md`).
- Fixes merged tonight: b48af7d (#235) + 64a2268 (#234) `strip_null_entries` in read
  path; a02e7a1 (#236) FE credit magnitudes.
- User's complaint (23:31) predates the container rebuild (image built 23:35:43,
  container up 23:35:50, includes HEAD 41697a0).
- Live verification: `docker logs prx-waf` → `risk: hot-reload OK` ×3 at
  23:36:26/:32/:38 (+0700); `configs/risk.yaml` rewritten (`enabled: true`, `paths: []`).
- Test verification: `cargo test -p waf-api --lib risk_api` → 6/6 pass incl.
  `shipped_risk_yaml_round_trips_through_api_path` against the current working-tree file;
  `risk_yaml_loads_through_engine_parser` passes.

If save still errors in the browser: hard-refresh the panel (stale cached bundle), else
capture the exact toast text — no failing path remains reproducible in current code.

## Collateral 3 — challenge.yaml corrupted by its own save path

`cargo test -p waf-engine --test config_yaml_regression` FAILS:
`challenge.token.cookie_max_age: invalid type: unit value, expected u32` (line 10).

Cause: `crates/waf-api/src/challenge_api.rs:51-67` `fe_to_yaml` writes
`body["cookie_max_age"]` verbatim — FE payload lacks the key → `Value::Null` → literal
`cookie_max_age: null` written to YAML, but engine field is non-optional `u32`
(`crates/waf-engine/src/challenge/config.rs:79-80`). Additionally `fe_to_yaml` rebuilds
the whole document (no deep-merge like risk API) → the entire `difficulty:` tier section
was silently WIPED from `configs/challenge.yaml` (see `git diff configs/challenge.yaml`).
File was written 23:36:53 by an admin-panel save; engine will reject it on next
startup/reload.

Fix direction: challenge PUT should deep-merge over current node + validate through
`ChallengeConfig` before write (the exact pattern risk_api uses), and omit absent keys
instead of writing null.

## Collateral 4 — device-fp.yaml unknown field

Same regression suite FAILS: `device_fp.providers[0]: unknown field enabled` —
`configs/device-fp.yaml` (written 23:32:54, presumably device-fp page save) contains
`enabled:` per provider which `DeviceFpConfig` provider schema rejects. Same
write-without-engine-validation class. Not chased further.

## Blast Radius

- DDoS page: save permanently 400s; displayed config is fake defaults (silent drift).
- challenge.yaml + device-fp.yaml: on next container restart those subsystems will fail
  config parse (behavior then depends on their fallback: default snapshot vs disabled).
- Pattern risk: every config PUT endpoint that does NOT round-trip through the engine
  struct before writing can corrupt operator YAML. risk_api (post-#234) is the good
  pattern; challenge/device-fp/ddos predate it.

## Recommended Fixes (not applied — debug-only session)

1. **DDoS FE rewrite** (`ddos-protection/index.tsx`): model = `DdosFileConfig` exactly;
   tier cards for critical/high/medium/catch_all; drop or gate the ban-ladder card.
2. **challenge_api PUT**: read-merge-validate-write via `ChallengeConfig` (mirror
   risk_api); restore lost `difficulty:` section in `configs/challenge.yaml` from git
   (`git checkout main -- configs/challenge.yaml` equivalent + re-apply intended edits).
3. **device-fp write path**: validate merged node through `DeviceFpConfig` before write;
   repair `configs/device-fp.yaml`.
4. **Systemic guard**: extend `config_yaml_regression.rs` pattern to run in CI on every
   shipped config (it already caught 3 and 4); add PUT-side round-trip validation to all
   config APIs.

## Unresolved Questions

- Should the ban-escalation ladder (60s/5m/1h `BanSchedule`) become operator-configurable
  in `ddos.yaml`, or should the FE card be removed? Product decision needed before the
  DDoS page rewrite.
- `configs/challenge.yaml` `difficulty:` section is lost in working tree — was
  `enabled: false` + defaults the user's intent, or restore the pre-save file?
- device-fp save path not fully traced (which handler wrote `providers[].enabled`).
