---
title: "Migrate configs/ YAML to TOML"
description: "Hard-cutover migration of 8 YAML config files in configs/ to TOML, including loaders, hot-reload, admin API, docs, and Docker."
status: pending
priority: P2
branch: "main"
tags: ["config", "refactor", "tdd"]
blockedBy: []
blocks: []
created: "2026-05-30T16:01:31.712Z"
createdBy: "ck:plan"
source: skill
---

# Migrate configs/ YAML to TOML

## Overview

Convert all 8 YAML config files under `configs/` to TOML in a single hard-cutover release. Drop `serde_yaml` from `waf-engine`'s config path entirely. The user-authored rule format under `rules/` (and `rules_api.rs`, `migrate-yaml-rules` bin, OWASP CRS, `configs/seed/`) is **explicitly OUT of scope** — those remain YAML and `serde_yaml` is kept where they live.

Strategy decided up-front (see ck:plan questionnaire):
- **Hard cutover** — one release ships a one-shot `waf migrate-configs` CLI; YAML loaders are deleted in the same release.
- **Admin UI** — already form-driven (not raw editor), only the API server-side codec swaps.
- **Comments hand-preserved** — each new `.toml` written manually mirroring the YAML headers.

TDD per `--tdd`: every loader phase rewrites the test suite (with TOML literal fixtures) **before** swapping the production parser, so a red→green cycle proves equivalence.

## In-scope file inventory

| YAML → TOML | Rust loader (config + reload) | Admin API | UI tag/i18n |
|-------------|-------------------------------|-----------|-------------|
| `configs/challenge.yaml` → `.toml` | `waf-engine/src/challenge/{config,reload}.rs` | `waf-api/src/challenge_api.rs` | none |
| `configs/ddos.yaml` → `.toml` | `waf-engine/src/checks/ddos/{config,reload}.rs` | `waf-api/src/ddos_api.rs` | none |
| `configs/device-fp.yaml` → `.toml` | `waf-engine/src/device_fp/{config,reload}.rs` + `behavior/config.rs` | `waf-api/src/device_fp_api.rs` | `docs/device-fingerprinting.md` |
| `configs/rate-limit.yaml` → `.toml` | `waf-engine/src/checks/rate_limit/{config,reload}.rs` + `waf-common/src/config.rs` doc | none | none |
| `configs/relay.yaml` → `.toml` | `waf-engine/src/relay/{config,reload}.rs` | `waf-api/src/relay_api.rs` | none |
| `configs/risk.yaml` → `.toml` | `waf-engine/src/risk/{config,reload}.rs` | `waf-api/src/risk_api.rs` | none |
| `configs/tier-policies.yaml` → `.toml` | (no engine loader — only API) | `waf-api/src/tier_policies_api.rs` | none |
| `configs/tx-velocity.yaml` → `.toml` | `waf-engine/src/checks/tx_velocity/{config,reload}.rs` | none | `web/admin-panel/src/pages/tx-velocity/index.tsx`, en+vi locales |

Plus `configs/default.toml:105` (`rate_limit.config_path`) and any docs strings referencing the old paths.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Foundation & deps](./phase-01-foundation-deps.md) | Pending |
| 2 | [One-shot migration tool](./phase-02-one-shot-migration-tool.md) | Pending |
| 3 | [risk module](./phase-03-risk-module.md) | Pending |
| 4 | [device-fp module](./phase-04-device-fp-module.md) | Pending |
| 5 | [challenge module](./phase-05-challenge-module.md) | Pending |
| 6 | [relay module](./phase-06-relay-module.md) | Pending |
| 7 | [rate-limit / tx-velocity / ddos](./phase-07-rate-limit-tx-velocity-ddos.md) | Pending |
| 8 | [tier-policies & admin API switchover](./phase-08-tier-policies-admin-api-switchover.md) | Pending |
| 9 | [Paths / Docker / i18n / docs](./phase-09-paths-docker-i18n-docs.md) | Pending |
| 10 | [Cleanup & e2e regression sweep](./phase-10-cleanup-e2e-regression-sweep.md) | Pending |

## Dependencies

No cross-plan dependency. Related historical context (informational only): `plans/260518-1031-yaml-format-consolidation/` consolidated **rule** YAML schemas — separate concern, no overlap with this `configs/` migration.

## Key design decisions

1. **Hard cutover, single release**. Old `.yaml` files in `configs/` are deleted in the same commit that adds the new `.toml`. CHANGELOG entry calls out the one-shot `waf migrate-configs` step for operators.
2. **Admin API JSON↔TOML codec**. The six FE-facing endpoints (`risk_api`, `device_fp_api`, `challenge_api`, `relay_api`, `ddos_api`, `tier_policies_api`) currently use `serde_yaml::from_str::<serde_json::Value>`. TOML cannot represent `null` and requires tables-after-scalars ordering. A shared helper module (`waf-api/src/config_codec.rs`) converts between `serde_json::Value` and `toml::Value`, dropping nulls and ordering keys deterministically. Helper lives in `waf-api` because that's the only crate doing JSON↔TOML round-tripping; engine loaders deserialise directly into typed structs.
3. **`serde_yaml` removal scope**: only `waf-engine` config loaders + the six `waf-api` endpoints above. `serde_yaml` stays in:
   - `waf-engine/src/rules/formats/{yaml.rs,custom_rule_yaml.rs}` (user-authored rule format)
   - `waf-engine/src/checks/owasp.rs` (bundled CRS)
   - `waf-engine/src/bin/migrate-yaml-rules.rs` (legacy rules tool)
   - `waf-api/src/rules_api.rs` (rule CRUD)
   - `waf-api/src/{access_lists_api,geo_api}.rs` (these touch files OUTSIDE `configs/` — out of scope, verified)
4. **`tier-policies.yaml` has no engine loader** — it's consumed only by `tier_policies_api.rs` as a generic `Value`. Migration is purely a file rename + codec swap on the API side.
5. **`device-fp.yaml` `providers:` sequence** uses `Vec<ProviderConfig>` with optional fields per provider name. In TOML this is `[[device_fp.providers]]` repeated tables. Verified the existing struct (`crates/waf-engine/src/device_fp/config.rs:172`) is field-discriminated (not enum-tagged), so the TOML representation is direct.
6. **`tier-policies.yaml`** is the only file without a `# header` comment block; safest to migrate first as a smoke test (Phase 8).
7. **TDD ordering per phase**: (a) rewrite unit tests with TOML literal fixtures and confirm they go RED; (b) swap the parser; (c) tests go GREEN; (d) write the new `configs/<name>.toml` on disk; (e) delete `configs/<name>.yaml`.

## Risks

- **TOML doesn't allow `null`**. The current admin-API helpers liberally use `Value::Null` to denote "missing optional block". TOML codec must convert nulls → "key absent". Risk-managed via Phase 8's codec round-trip property test (1k random JSON ≈ TOML ≈ JSON).
- **TOML table-ordering rule** (tables must come after scalar keys of their parent table) means hand-written files need correct ordering. Risk-managed via a Phase 1 `cargo test` that loads every shipped `configs/*.toml` and asserts equality with the live default-config struct.
- **Hot-reload watchers** match by file name. Each phase updates the watcher target path; integration tests touch the new `.toml` and assert ArcSwap pointer change.
- **Docker layer cache** keys on `COPY configs/ /app/configs/`. Rebuild verifies after Phase 9. No path inside containers changes (still `configs/<name>.<ext>` — just the ext flips).
- **`configs/default.toml:105`** references `configs/rate-limit.yaml`. Phase 9 updates this; if a user has a customised `default.toml` they must also update this line — called out in CHANGELOG.

## Out of scope (confirmed)

- `rules/` directory (user-authored rule YAMLs)
- `configs/seed/` (CSV/TXT example data — not config format)
- OWASP CRS bundled rules
- `waf-api/src/rules_api.rs` (rule CRUD)
- `waf-api/src/{access_lists_api,geo_api}.rs` (touch files outside `configs/`)
- `waf-engine/src/bin/migrate-yaml-rules.rs` (legacy rule migration tool, unrelated)

## Unresolved questions

None at plan time. If Phase 8 codec discovers a TOML representation the FE cannot round-trip (e.g. fields that must remain JSON-null), escalate before merging that phase.
