# PM Report — GeoIP & Risk Engine P0 Test Gaps (Completed)

Plan: `plans/260706-2038-geoip-risk-p0-test-gaps/` | Branch: `main-harness` | Issue: gh-250 | Date: 2026-07-06

## Status

| Phase | Result |
|-------|--------|
| 1 Config cleanup + loader test | Done — configs reverted to committed values; id-4 IR row `challenge` → `block` (enforcement unchanged); `unsupported_action_row_falls_back_to_block` added, 12/12 geo_config tests green |
| 2 Reload-preserve service test | Done — `reload_failure_keeps_serving_previous_searcher` in `tests/geoip_lookup.rs`; no committed fixture (handcrafted `searchable_xdb_bytes()` helper, baseline lookup returns real region data); regression-sensitivity proven via temporary swap-to-None (reverted) |
| 3 Risk canary tests | Closed at validation — coverage pre-existed in `src/risk/tests/canary.rs` |
| 4 Verification gate | Done — geoip_lookup 14/14, geoip_updater_schedule 18/18, geo 22/22, clippy + fmt clean; code-reviewer subagent: DONE, all 6 criteria pass |

## Diff

`configs/geo-rules.yaml` (1 line), `geo_config.rs` (+test), `tests/geoip_lookup.rs` (+helper/test). `risk.yaml`, `geoip.rs`: no diff.

## Known pre-existing failures (not caused by this diff)

- 9 `engine::tests::*` need Docker (postgres testcontainers); docker socket permission denied for this user machine-wide.
- `device_fp::config::tests::shipped_yaml_matches_behavior_defaults`: committed `configs/device-fp.yaml` carries unknown field `enabled` (predates this work, last touched in 28585bc).

## Docs

No `./docs` update warranted — test-only + config-hygiene change; no user-facing behavior, contract, or architecture change.

## Unresolved questions

- Pre-existing `device-fp.yaml`/config-schema mismatch fails a shipped-defaults test on this branch — separate fix candidate (not in this plan's scope).
