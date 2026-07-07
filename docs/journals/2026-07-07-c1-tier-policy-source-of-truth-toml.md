# C1 Tier-Policy Admin Surface — Point at tier-protection.toml

**Date:** 2026-07-07 11:14  
**Commit:** a1e5e5e  
**Branch:** main-harness  
**Plan:** `plans/260707-1111-tier-policy-source-of-truth-toml/`

## The Problem

The admin API and UI read/wrote `configs/tier-policies.yaml` — but the engine's tier watcher only loads `configs/tier-protection.toml` via `config.tiered_protection.config_path`. Operator edits in the panel succeeded with a success toast and immediately vanished at enforcement time. The YAML was a cosmetic orphan; formats were incompatible (flat `cache_policy: "no_cache"` string vs tagged enum `{ mode = "..." }`, `tier.rs:36-44`). Default profiles omitted `config_path` entirely, forcing all requests into hardcoded fallback 30/70/90 thresholds.

The RiskBandPreview dashboard claimed "must show what the engine enforces" while rendering the disconnected YAML numbers — a lie operators believed.

**Impact:** Tier policies were unmaintainable. Any attempt to tune enforcement was cargo-cult ritual.

## What Shipped

**API repoint** (`crates/waf-api/src/tier_policies_api.rs`, +353 lines gross / −198 net).  
GET/PUT/dry-run now read and write the same TOML file the watcher loads. Payloads round-trip through `waf_common::tier::TierConfig` + `TierSnapshot::try_from_config` — the watcher's own validation path — before an atomic `write_toml_str`. Dry-run classifies via the live `gateway::tiered::TierClassifier`. Both API and watcher derive `config_path` from a single `AppState` field, so they provably share one file.

**Config profiles** (`configs/default.toml`, `configs/local-dev.toml`).  
Added `[tiered_protection] config_path = "configs/tier-protection.toml"` to point both API and watcher at a dedicated file. Tier TOML is panel-owned: full-file rewrites, so co-location with other tables risks silent deletion (documented in profile comments).

**Admin page rewrite** (`web/admin-panel/src/pages/tier-policies/index.tsx`).  
FE adopts the engine schema in full: tagged `cache_policy`, `method` field, `default_tier`. Host/header matchers render read-only with a "managed by gateway" tooltip but are round-tripped untouched on save. Rule editor this round edits only priority/tier/path/methods; future rounds can unlock matchers. Added i18n keys; wired dry-run output to real TierClassifier response shape.

**Dead YAML deleted** (`configs/tier-policies.yaml`).  
Zero references remain in code; grep confirmed.

## Key Decisions

1. **UI schema = engine schema.** Panel users see the real, enforced shape. Asymmetry breeds confusion.
2. **Host/header matchers are read-only this round.** They're gateway state, not panel state; editing them needs gateway synchronization (out of scope). Passing them through untouched preserves them on save, so future work is unblocked.
3. **tier-protection.toml is panel-owned.** The panel PUT rewrites the entire file, so it must be dedicated. Shared-table scenarios (e.g., `config_path` pointing at the main `default.toml`) would silently delete everything else. The watcher's `TomlEnvelope` *invites* shared-file setups (`tier_config_watcher.rs:41-47`), so this is a real sharp edge documented in the profile.

## Verification

**Tests:** 131/131 waf-api lib (7 new tier_policies_api tests); 9/9 config_loader (profiles parse); gateway tier watcher/classifier 28+ tests unchanged. Dry-run test uses real `gateway::tiered::try_reload` against actual `serialize_toml` output — not mocked. Watcher-equivalence proven.

**Lint gates:** `cargo fmt --all --check` (9 diffs fixed), `cargo clippy --workspace --all-targets` (indexing_slicing in test mod fixed with `#[allow]` precedent from risk_api). All green after fixes.

**FE:** `tsc --noEmit` clean, `npm run build` clean (553.73 kB → 152.20 kB gzip).

## Known Edges (Documented, Not Blocking)

- **H-1 (Medium):** PUT destroys co-located TOML tables and comments. Documented in profile; acceptable for dedicated panel-managed files. Could round-trip through `toml::Value` as future work.
- **M-1 (Low):** FE falls back to `DEFAULT_CONFIG` if loaded file is missing required keys — no warning. Watcher would reject the file anyway; low likelihood.
- **M-2 (Low):** When `config_path` is unset, API uses fallback but no watcher runs; edits silently do nothing until restart. Deliberate per plan; no indication in UI.

## What Hurt

The orphan-file trap. It existed *because* nobody cross-checked enforcement's real data source — the code-review round (C1 finding) that caught it was the hardest-won inspection of the stack. Lesson: **name the file the engine actually reads before any admin-surface change**. A prompt saying "user can edit tier policies" doesn't tell you which file. The watcher's existence (in a different crate, different startup thread) makes this discovery-hostile.

## Next Steps

1. **Merge:** All gates pass, deferred non-blockers (H-1, M-1, M-2) documented in commit + plan reports.
2. **Follow-up (out of scope):** M-1 loading-skipped warning; M-2 inert-subsystem indicator; H-1 either preserve-unknown-tables or strengthen the "dedicated file" constraint.

---

**Status:** DONE  
**Summary:** Tier-policy admin surface now points at tier-protection.toml (the watcher's real data source); format/schema unified end-to-end; all CI gates green after formatting+lint fixes.  
**Concerns:** None—deferred non-blocking edges documented in code-review report.
