# Code Review — C1 Tier-Policy Source of Truth (TOML)

Reviewer: code-reviewer subagent · 2026-07-07 · scope: uncommitted working tree vs HEAD, branch `main-harness`
Excluded per instruction: `configs/risk.yaml`, `configs/ddos.yaml` (pre-existing diffs).

## Scope

- `crates/waf-api/src/tier_policies_api.rs` (rewrite, +7 tests), `config_files.rs` (+`write_toml_str`), `state.rs` (+`tier_config_path`), `Cargo.toml` (+toml)
- `crates/prx-waf/src/main.rs` (init_async plumbing)
- `configs/default.toml`, `configs/local-dev.toml` (+`[tiered_protection] config_path`), `configs/tier-policies.yaml` (deleted)
- `web/admin-panel/src/pages/tier-policies/index.tsx` (rewrite), `en.json`/`vi.json`
- ~550 insertions / ~200 deletions incl. Cargo.lock

## Overall Assessment

The design is sound and does what the plan claims: PUT round-trips through `serde_json → TierConfig → TierSnapshot::try_from_config` (byte-identical to the watcher's validation path), the watcher-equivalence test drives the real `gateway::tiered::try_reload` against a file written from `serialize_toml` output (not mocked), and API/watcher provably share one path because both derive it from the same `config.tiered_protection.config_path` string. FE serde fidelity is exact. **However, two CI hard gates fail on this working tree** — `cargo fmt --check` and workspace clippy — so the change is not landable as-is, and the phase-01 "clippy no new warnings" verify claim was not actually met.

## Critical Issues (CI-blocking)

### C-1. `cargo fmt --all -- --check` fails — 9 diffs, both new Rust files

CI step "Format check" (`.github/workflows/ci.yml:33`) will fail. Diffs at:
- `crates/prx-waf/src/main.rs:1847` (the new `tier_config_path` assignment line is over-width; rustfmt wants it broken across 5 lines)
- `crates/waf-api/src/tier_policies_api.rs:79, 124, 140, 148, 159, 204, 215, 250`

Fix: `cargo fmt --all`.

### C-2. `cargo clippy --workspace --all-targets` fails — `indexing_slicing` deny in new test module

```
error: indexing may panic
  --> crates/waf-api/src/tier_policies_api.rs:218
218 |         bad_regex.classifier_rules[0].path = Some(PathMatch::Regex { value: "(".into() });
```

`indexing_slicing = "deny"` is workspace-wide (`Cargo.toml:141`) and, unlike unwrap/expect/panic, has **no** `allow-*-in-tests` exemption in `clippy.toml`. Sibling modules carry the allow on the test mod for exactly this reason (`risk_api.rs:169 #[allow(clippy::indexing_slicing)] mod tests`); the new `#[cfg(test)] mod tests` at `tier_policies_api.rs:130` omits it. Non-test targets are clean (verified: `clippy -p waf-api --lib` and `clippy -p prx-waf --all-targets` both pass).

Fix: add `#[allow(clippy::indexing_slicing)]` on the test mod (matches precedent), or use `get_mut(0)`.

## High Priority

### H-1. PUT silently destroys co-located TOML tables and all comments

`put_tier_policies` serializes only `TierProtectionFile { tiered_protection }` and renames it over the target. But the watcher's `TomlEnvelope` (`tier_config_watcher.rs:41-47`) is *explicitly designed* to tolerate other tables in the same file ("editing other tables in the same file does NOT false-fail the tier reload"), so pointing `config_path` at a shared TOML — including the main config itself — is a configuration the engine invites. In that setup:
- GET succeeds (serde ignores unknown top-level tables — verified: `TierProtectionFile` has no `deny_unknown_fields`),
- one panel save silently deletes every other table. If `config_path = "configs/default.toml"`, a save destroys the entire main config.

Shipped profiles use a dedicated file and the endpoint is admin-authenticated, so this is not Critical, but it is a real data-loss edge with no guard.

Suggested fix (either): (a) round-trip through `toml::Value` — parse existing file, replace only the `tiered_protection` key, reserialize; or (b) reject PUT with 409/400 when the on-disk file contains tables other than `tiered_protection`; or minimally (c) document in both profile comments that `config_path` must reference a dedicated, panel-managed file (comments are lost on first save regardless — acceptable for managed files, worth one line in the shipped `tier-protection.toml` header saying the panel rewrites it).

## Medium Priority

- **M-1. FE silently shows defaults over an unrecognized-but-parseable config.** The load-effect guard (`index.tsx:421-426`) requires `critical`/`high` keys; a hand-edited file missing them GETs fine (GET does not validate — `TierConfig.policies` is a plain HashMap), the page keeps `DEFAULT_CONFIG` (including its 3 sample classifier rules) with Save enabled, and a save overwrites the operator's file with UI defaults without any warning. Low likelihood (the watcher would have been rejecting that file anyway), but a "loaded config was ignored" warning state would be safer than silently rendering defaults.
- **M-2. Inert-subsystem edits look live.** When a profile omits `config_path`, the API falls back to `resolve_path(state, "configs/tier-protection.toml")` and GET/PUT succeed — but no watcher is running, so edits do nothing until a restart with a wired profile. Plan accepted the fallback deliberately; noting that the UI gives no indication. Fine to leave, worth a follow-up.
- **M-3. Test hygiene:** `put_serialization_loads_through_watcher_reload` uses `std::env::temp_dir() + process::id()` with `remove_dir_all().ok()` — leaks the dir on assertion failure and collides if the same PID reruns. `gateway` tests use `tempfile::tempdir()`; waf-api doesn't currently dev-depend on `tempfile`, which is presumably why. Acceptable, but `tempfile` is the cleaner pattern if it's ever added.

## Low Priority

- PUT accepts unknown JSON fields silently (no `deny_unknown_fields` on `TierConfig` — upstream type, consistent with watcher behavior). Typo'd field names are dropped without error.
- antd `Slider.onAfterChange` is deprecated since antd 5.10 (repo is on ^5.22; renamed `onChangeComplete`). Pre-existing pattern on this exact page, correctly preserved per plan — flagging only as future migration debt.
- Concurrent PUTs share one tmp path (`<stem>.toml.tmp`); interleaved writes could corrupt the tmp before rename. Mirrors the accepted `write_yaml_str` pattern; blast radius is bounded (watcher rejects and keeps the previous snapshot; GET 500s until re-saved).
- 500 bodies include the filesystem path (`load_tier_config` error). Pre-existing `ApiError::Internal` convention, authenticated admin surface — documented non-issue.
- `serialize_toml` returning `(String, TierConfig)` to thread ownership back out is slightly convoluted; harmless.
- Table `rowKey` is the array index with row deletion — standard AntD caveat, harmless at this scale.

## Acceptance Criteria Verification

| # | Criterion | Result |
|---|---|---|
| 1 | PUT engine-shaped JSON → TOML at watcher path; invalid → 400, file untouched | **PASS.** `parse_and_validate` (serde + `TierSnapshot::try_from_config`) runs before any write; tests cover thresholds order, missing tier, bad regex → `ApiError::BadRequest` |
| 2 | GET returns `TierConfig` JSON; dashboard RiskBandPreview intact | **PASS.** data-provider `custom()` unwraps `{success,data}` (data-provider.ts:153-165); dashboard reads `result.data.policies.<tier>.risk_thresholds` (dashboard/index.tsx:78-83, 198, 538-549) — shape unchanged for that path |
| 3 | Dry-run via `gateway::tiered::TierClassifier`; `{matched_tier, policy}` | **PASS.** Compiles production classifier per request; `matched_rule_id` dropped, FE updated, grep confirms no other consumer |
| 4 | `configs/tier-policies.yaml` deleted, zero code references | **PASS.** `git status` shows `D`; grep across code/config finds references only in plans/docs history |
| 5 | Both profiles set `config_path`; config_loader still passes | **PASS.** Both diffs present; `cargo test -p waf-common --test config_loader` 9/9 incl. `load_repo_default_toml` |
| 6 | No regression: waf-api lib tests, routes unchanged | **PASS (tests).** 131/131 `cargo test -p waf-api --lib` (7 new tier tests all run); `server.rs` untouched, routes at :286-287 inside the `require_auth` layer. **But CI gates fmt+clippy FAIL (C-1/C-2)** |

## Specific Checks

- **(a) Serde fidelity: PASS.** FE `method?: string[]` (not `methods`) matches `TierClassifierRule.method`; `CachePolicy {mode, ttl_seconds}` matches `#[serde(tag="mode", rename_all="snake_case")]`; `PathMatch/HostMatch {kind, value}` match `#[serde(tag="kind")]`; `TIER_KEYS` incl. `catch_all` match `rename_all="snake_case"`; `HTTP_METHODS` lists all 9 UPPERCASE variants of `HttpMethod`.
- **(b) Round-trip: PASS.** Full rule objects live in `config.classifier_rules`; add appends, delete filters by index, nothing else mutates rules; host/headers render read-only with tooltip; PUT sends complete `TierConfig`. Editor can only *create* path/method rules, as scoped.
- **(c) Path divergence: PASS.** Watcher: `PathBuf::from(p)` from `config.tiered_protection.config_path` (main.rs:1442); API: identical expression at main.rs:1850. `resolve_path` fallback only activates when `config_path` is unset, i.e. when no watcher exists (see M-2).
- **(d) Clippy/type/build:** FE `tsc --noEmit` exit 0 (re-verified independently). Rust: **clippy --all-targets FAILS (C-2), fmt FAILS (C-1)**; lib/bin targets clean.
- **(e) Watcher-equivalence: PASS, test is real.** PUT validates via `TierSnapshot::try_from_config` — the same call `try_reload` makes (tier_config_watcher.rs:138). `put_serialization_loads_through_watcher_reload` writes actual `serialize_toml` output to a real temp file and asserts `gateway::tiered::try_reload` loads it with `rule_count()==2`, including `None` option fields (the toml-crate None hazard). No mocks.
- **(f) Pattern conformance: PASS with the C-1/C-2 caveat.** `write_toml_str` is a verbatim twin of `write_yaml_str`; `tier_config_path` mirrors `panel_config_path` (state.rs + init_async); `run_seed_admin`'s AppState (main.rs:1031) correctly left alone — verified it only seeds the admin row and never serves routes; FE preserves the local-slider-state commit-on-`onAfterChange` pattern and the `loadQuery.dataUpdatedAt` effect guard with its infinite-loop rationale comment.

## Edge Cases Scouted

- Co-located TOML tables wiped by PUT (H-1) — the watcher tolerates them, the API destroys them.
- Parseable-but-invalid on-disk config: GET serves it unvalidated (correct — operator sees reality); FE guard fallout in M-1.
- Missing file: GET serves `TierPolicy::default()` ×4 (fail-open, `ddos_threshold_rps = u32::MAX` renders as 4294967295 above the FE input's max — cosmetic only).
- Dry-run classifies the *saved* file, not unsaved form edits — same as the previous implementation, unchanged contract.
- tmp-file rename: watcher filters events by final file name; notify rename events carry the destination path, so hot-reload fires. Debounce 200ms.
- Empty `host` in dry-run: `HostMatch` rules simply don't match — consistent with classifier semantics.

## Recommended Actions

1. **(blocking)** `cargo fmt --all` — clears C-1.
2. **(blocking)** Add `#[allow(clippy::indexing_slicing)]` to the `tier_policies_api` test mod (risk_api.rs precedent) — clears C-2. Re-run `cargo clippy --workspace --all-targets --all-features` to match CI exactly.
3. **(recommended before merge)** Decide on H-1: preserve-unknown-tables via `toml::Value` merge, or a one-line "this file is panel-managed and fully rewritten on save" comment in shipped `tier-protection.toml` + profile comments, accepting the constraint.
4. (follow-up) M-1 warning state; M-2 inert-subsystem indicator.

## Metrics

- `cargo test -p waf-api --lib`: 131/131 pass (7 new tier tests)
- `cargo test -p waf-common --test config_loader`: 9/9 pass
- `tsc --noEmit` (web/admin-panel): clean
- `cargo clippy --workspace --all-targets` equivalent: **1 error** (C-2)
- `cargo fmt --all --check`: **9 diffs, 2 files** (C-1)
- i18n: all 48 `tierPolicies.*` keys used by the page exist in both `en.json` and `vi.json` (script-verified)

## Unresolved Questions

1. H-1 disposition: is "config_path must be a dedicated panel-managed file" an accepted product constraint (document it), or should PUT preserve unknown tables? Needs a controller/user decision — the watcher's shared-file affordance and the API's whole-file rewrite currently contradict each other.
