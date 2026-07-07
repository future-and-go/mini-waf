# C1 Fix — Tier-Policy Single Source of Truth (`tier-protection.toml`)

**Status:** completed 2026-07-07 · **Created:** 2026-07-07 11:11 · **Branch:** main-harness
**Gates:** code-review + test reports in `reports/` (both DONE_WITH_CONCERNS → criticals fixed: fmt, clippy `indexing_slicing` in test). Post-review decision: tier TOML is panel-owned/dedicated — documented in profile comments + module doc instead of merging co-located tables (user choice). Deferred minors recorded in reports: PUT-handler E2E test, write-error tests, FE default-config fallback UX, deprecated antd `onAfterChange`.
**Origin:** C1 in `plans/reports/code-review-260707-1001-risk-score-engine-cross-layer-unknown-unknowns-report.md`
**User decisions:** engine shape in UI, but shrunk rule editor (path+method editable; host/headers read-only, round-tripped untouched) · wire `config_path` in default.toml + local-dev.toml · dry-run on real gateway classifier · delete orphan `configs/tier-policies.yaml`

## Problem

Admin API/UI read+write `configs/tier-policies.yaml`; enforcement reads `configs/tier-protection.toml` via `[tiered_protection] config_path` → `gateway::tiered` watcher. Panel edits never reach enforcement; formats are incompatible (`cache_policy` string vs tagged enum). `default.toml`/`local-dev.toml` omit `config_path` → engine hardcoded CatchAll 30/70/90.

## Approach

Repoint the API at the TOML the engine watches, round-tripping through `waf_common::tier::TierConfig` + `validate()` + rule compile (`TierSnapshot::try_from_config`) before write. Rewrite the UI form to the engine schema. Delete the YAML. Wire `config_path` in both remaining profiles so hot-reload makes panel edits live everywhere.

## Phases

| # | Phase | File | Verify |
|---|---|---|---|
| 1 | Backend: API + state plumbing + configs | `phase-01-backend-api-toml-source.md` | `cargo test -p waf-api`, new unit tests pass |
| 2 | Frontend: engine-shape form + verification | `phase-02-frontend-engine-shape-and-verify.md` | FE build + tsc clean, dashboard preview intact, code-reviewer pass |

## Acceptance criteria

1. PUT `/api/tier-policies` with engine-shaped JSON writes `[tiered_protection]` TOML to the exact path the engine watcher loads; invalid config (thresholds order, missing tier, bad regex) → 400, file untouched.
2. GET returns the parsed engine config (JSON of `TierConfig`); dashboard `RiskBandPreview` shows the enforced thresholds.
3. Dry-run classifies via `gateway::tiered::TierClassifier` (regex/host/method rules honored).
4. `configs/tier-policies.yaml` deleted; no code references remain.
5. `default.toml` + `local-dev.toml` set `config_path = "configs/tier-protection.toml"`.
6. No regression: existing waf-api tests pass; public routes unchanged (`/api/tier-policies`, `/api/tier-policies/dry-run`).

## Out of scope

- Dead `thresholds.challenge` in `decide()` (report M-finding, separate).
- Other working-tree config diffs (`risk.yaml`, `ddos.yaml`) — untouched.
- DDoS page schema mismatch (separate report).

## Risks

- **Contract break:** response/request shape changes (`cache_policy` object, no `matched_rule_id` in dry-run). FE updated in same change; no other consumers (grep-verified: dashboard reads only `policies.<tier>.risk_thresholds`, unchanged).
- **Path divergence:** engine resolves `config_path` relative to CWD; API `resolve_path` resolves relative to config root. Plumb the engine-resolved path into `AppState` (follow `panel_config_path` precedent) so both provably use one file.
- **Hot-reload feedback:** watcher rejects a file the API accepted → prevented by compiling snapshot (same code path as watcher) before write.
- **Rollback:** revert commit; YAML restorable from git history.
