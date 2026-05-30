# Red-Team — Assumption Destroyer Review

Plan: `plans/260530-2325-fr012-fp-plumbing-and-ok-enrichment/`
Reviewer mode: hostile / scope auditor

---

## Finding 1: Phase-01 hoist plan ignores `FpKey`'s real dependency surface

- **Severity:** Critical
- **Location:** Phase 1, "Architecture" + "Step 1.2 — move the types"
- **Flaw:** Plan claims `FpKey` and `FingerprintValue` can be hoisted "near `GeoIpInfo`" with no dependency changes, listing only `serde` (already present). But `crates/waf-engine/src/device_fp/types.rs` is a single file whose module-level imports (`use crate::device_fp::capture::ConnCtx; use crate::device_fp::signal::Signal;` at lines 13–14) are tangled with `DeviceCtx`, `Observation`, `IdentityRecord`, `DeviceIdentity`. After cutting only `FingerprintValue` + `FpKey`, the remaining file still needs those imports — but the plan also says "`DeviceCtx`, `Observation`, `IdentityRecord`, `DeviceIdentity` stay in `waf-engine`", which is correct, but the cut-and-paste sequence in Step 1.2 doesn't ensure `pub use waf_common::{FpKey, FingerprintValue};` actually re-exports usable types. The bigger gap: `Observation` (still in `waf-engine::device_fp::types`) holds an `Option<FpKey>` field (verified at `crates/waf-engine/src/device_fp/types.rs` — `IdentityRecord { pub key: FpKey, … }` line 125-131, `DeviceIdentity { pub key: Arc<FpKey>, … }` line 136-139). After the move, those structs depend on the re-exported type. That works in Rust but the plan never says "`DeviceIdentity.key` is `Arc<FpKey>` where `FpKey` now resolves via the shim". The Step 1.4 grep gate `pub struct FpKey\|pub struct FingerprintValue` returns one site only — but doesn't catch broken `Observation`/`IdentityRecord`/`DeviceIdentity` uses through the shim.
- **Failure scenario:** Phase-01 lands; phase-02's gateway change `Arc::clone(&d.key)` in `proxy.rs:551` compiles because `DeviceIdentity.key: Arc<FpKey>` and `FpKey` is the same nominal type via re-export. But if anyone in the gateway has `use waf_engine::device_fp::FpKey` *and* `use waf_common::FpKey` simultaneously, rustc treats them as the same type (re-export, fine). Lower risk than feared, but the plan never confirms with a grep that no test fixture has `FpKey { /* missing field */ }` literals across crates. There are sites that construct `FpKey { ja3: …, ja4: None, h2_akamai: None }` in fixtures (verified at `crates/waf-engine/src/checks/tx_velocity/session_key.rs:90-94`, `crates/waf-engine/src/checks/tx_velocity/recorder.rs:506-509`). Those compile through the re-export, but Phase-01's "no test rewrites required" claim is brittle if any non-test consumer ever destructures `FpKey` from the *old* path with new field assumptions.
- **Evidence:**
  - `crates/waf-engine/src/device_fp/types.rs:13-14` — `use crate::device_fp::{capture::ConnCtx, signal::Signal}` (engine-internal)
  - `crates/waf-engine/src/device_fp/types.rs:125-139` — `IdentityRecord.key: FpKey`, `DeviceIdentity.key: Arc<FpKey>` stay in engine
  - `crates/waf-engine/src/device_fp/mod.rs:43` — `pub use types::{… FingerprintValue, FpKey, …}` — re-export chain has multiple hops; plan's "no mass-rewrite" relies on this
- **Suggested fix:** Add an explicit Step 1.2.1 that does the `cargo check -p waf-engine` after only deleting the two struct defs but before pasting the shim, to confirm the engine-internal `Observation/IdentityRecord/DeviceIdentity` block compiles against the shim. Also list `crates/waf-engine/src/device_fp/identity/` (memory/redis stores) as "Read for context" — they wrap `IdentityRecord` and may have type-alias surprises.

---

## Finding 2: Phase-02 grep estimate "~30-50 fixtures" undercounts; actual is 164 hits across 72 files

- **Severity:** Critical
- **Location:** Phase 2, "Step 2.6 — sweep test fixtures" + "Risk Assessment" first row
- **Flaw:** Plan says `RequestCtx { … }` struct-literal sweep will yield "~30-50 fixtures across `waf-engine`, `gateway`, `waf-common`, `waf-api`". The actual count is **164 hits across 72 files** (verified by `grep -rn "RequestCtx {" crates/ --include="*.rs" | wc -l`). The 3.3× undercount drives the "1-2h" Phase-01 / "2-3h" Phase-02 effort estimates. Critically, the plan does NOT enumerate `crates/waf-engine/benches/` files (`risk_anomaly.rs`, `rule_eval.rs`, `sql_injection.rs`) — benches are also workspace members and `cargo check --workspace` does catch them, but the "Related Code Files" list omits them. Same for `crates/gateway/tests/fr018_brute_force_dispatch.rs`, `crates/gateway/tests/proxy_waf_response_writer.rs`, `crates/gateway/tests/waf_observability_headers.rs` — none mentioned.
- **Failure scenario:** Engineer follows the plan, fixes the ~50 sites grep finds in `src/`, runs `cargo test -p waf-engine`, sees green, commits. CI then runs `cargo check --workspace --all-targets` and explodes on bench files + gateway integration tests. Worse, the bench files use sufficiently old fixture macros that grep misses some of them (e.g. nested struct-literal in macro-rules). The "~30-50" estimate masks effort by ~3×.
- **Evidence:**
  - `grep -rn "RequestCtx {" crates/ --include="*.rs" | grep -v target | wc -l` → 164
  - `grep -rln "RequestCtx {" crates/ --include="*.rs" | grep -v target | sort -u | wc -l` → 72 distinct files
  - Files not in plan's mention list: `crates/waf-engine/benches/risk_anomaly.rs`, `crates/waf-engine/benches/rule_eval.rs`, `crates/waf-engine/benches/sql_injection.rs`, `crates/gateway/tests/fr018_brute_force_dispatch.rs`, `crates/gateway/tests/proxy_waf_response_writer.rs`, `crates/gateway/tests/waf_observability_headers.rs`, `crates/waf-engine/tests/common/mod.rs`, `crates/waf-engine/tests/ddos_scenarios/mod.rs`, `crates/waf-engine/tests/support/owasp_helpers.rs`
- **Suggested fix:** Re-run the grep before phase kickoff; revise effort estimate to "4-6h"; replace "~30-50" with a non-misleading sentence: "164 struct-literal sites in 72 files". Also recommend adding `#[derive(Default)]` (or a manual `Default` impl) on `RequestCtx` and using `..RequestCtx::default()` syntax for new test fixtures going forward — saves the next field addition from this churn. Plan's Risk Assessment row "no `Default::default()` for `RequestCtx`" is true today but doesn't propose fixing the underlying maintenance burden.

---

## Finding 3: Phase-03 changes `record()` signature; 27+ callers across tests, benches, and the check itself — plan only lists pipeline tests

- **Severity:** Critical
- **Location:** Phase 3, "Step 3.5 — port existing pipeline tests" + "Step 3.3 — implement set_outcome + strip record()"
- **Flaw:** Plan says `record(&self, key: &SessionKey, role: EndpointRole, ok: bool)` → `record(&self, key: &SessionKey, role: EndpointRole)` (drop `ok`). Plan lists only the 4 pipeline tests in `recorder.rs:419-524` and the one call in `check.rs:61`. Actual count of `store.record(&key, …, true)` call sites that break: **27** across `tests/tx_velocity_integration.rs` (12 sites), `benches/tx_velocity_bench.rs` (5 sites), `src/checks/tx_velocity/recorder.rs` inline tests (10 sites including `record_skips_role_none`, `record_appends_for_known_role`, `ring_caps_at_window_and_drops_oldest`, `mark_signal_updates_cooldown_marker`, `purge_expired_*`, `concurrent_inserts_no_panic`, `pipeline_*` × 4). Plan's success criterion `grep -n "store.record(.*true)" crates/` returns empty is a gate, not a discovery method.
- **Failure scenario:** Engineer rewrites the 4 pipeline tests per Step 3.5 then runs `cargo test -p waf-engine tx_velocity` — sees 22 unrelated test/bench compile errors all caused by the signature change. Spends an hour mechanically fixing them; only then notices `benches/tx_velocity_bench.rs` is in the workspace. The whole-plan `cargo test --workspace` gate in Step 3.6 catches it, but the plan presents the change as if it touches 5 sites when it touches 27.
- **Evidence:**
  - `crates/waf-engine/tests/tx_velocity_integration.rs:116,123,158,188,215,220,246,275,299,305,329,376` — all `store.record(&key, …, true)` (12 hits)
  - `crates/waf-engine/benches/tx_velocity_bench.rs:61,81,101,137,158,191` — `store.record(…, true)` (6 hits, one comment)
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:306,315,326,336,347,357,373,431,459,464,491,515` — inline test calls (12 hits)
  - `crates/waf-engine/src/checks/tx_velocity/check.rs:61` — production call (1 hit)
- **Suggested fix:** Replace Step 3.5 with "rewrite every `store.record(&k, role, ok)` → `store.record(&k, role); store.set_outcome(&k, role, ok);` (or drop the `set_outcome` if the test didn't care about outcome). Enumerate the 27 sites in the phase's `## Related Code Files` so the engineer plans the rewrite up front." Note that for tests that only verified `record_appends_for_known_role` (no classifier eval expected), the rewrite is simpler — `set_outcome` is optional. Acknowledge bench rewrites — and consider whether `tx_velocity_bench.rs` measurements are still comparable across the signature change.

---

## Finding 4: Phase-04 misses exhaustive `Signal::WithdrawalVelocity` / `Signal::LimitChangeBurst` constructions in risk-scorer test fixtures — `..` rest-pattern claim is a destructure-only check

- **Severity:** High
- **Location:** Phase 4, "Step 4.5 — grep-sweep downstream consumers" + Risk Assessment row 1 ("Mitigated by grep-sweep…; all current matchers use `Signal::WithdrawalVelocity { count, .. }` which keeps compiling")
- **Flaw:** The Risk Assessment row claims all current matchers use `{ count, .. }` rest pattern. **TRUE for `match` arms** but **FALSE for construction sites**. `crates/waf-engine/src/risk/ingest/signal_to_contributor.rs:193-200` contains *exhaustive struct literal* constructions inside a test:
  ```
  Signal::WithdrawalVelocity { count: 5, window_sec: 60 },
  Signal::LimitChangeBurst   { count: 3, window_sec: 60 },
  ```
  Once the variant gains `ok_count: u32`, these literals fail with "missing field `ok_count`". Plan only labels `crates/waf-engine/src/risk/` as **"Read"** in the Related Code Files block, not Modify — implying the engineer might skip it. The classifier test files (`withdrawal_velocity.rs:95,116`, `limit_change_burst.rs:69`) have the same exhaustive-construction problem and **are** correctly called out in Step 4.4.
- **Failure scenario:** Engineer extends the Signal enum, updates classifier production code, runs `cargo test -p waf-engine --lib tx_velocity` → green. Runs `cargo test -p waf-engine` (broader) → compile failure in `risk::ingest::signal_to_contributor::tests::all_signal_variants_mapped`. Same in any future risk-scorer fixture that constructs the variant.
- **Evidence:**
  - `crates/waf-engine/src/risk/ingest/signal_to_contributor.rs:193-200` — exhaustive struct literal of both variants in test array
  - `crates/waf-engine/tests/tx_velocity_integration.rs:167,197,255` — uses `..` rest, will keep compiling
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:439` — uses `..` rest, will keep compiling
- **Suggested fix:** Promote `crates/waf-engine/src/risk/ingest/signal_to_contributor.rs` to **Modify** in Phase 4 Related Code Files. Add explicit grep variants: `grep -rn "Signal::WithdrawalVelocity {[^.]" crates/` and `grep -rn "Signal::LimitChangeBurst {[^.]" crates/` to find construction-style literals separately from `..`-rest match arms. Update Risk Assessment row 1 to "all current `match` arms use `..` rest; construction-style literals (including the test fixture in `risk/ingest/signal_to_contributor.rs:193`) must be updated separately."

---

## Finding 5: Phase-05 integration test `fingerprint_fallback_when_no_cookie` will fail — `fp_key_for_submission()` collapses non-fingerprint identities, but the test never exercises that path; meanwhile the cookie-path tests succeed for the wrong reason

- **Severity:** High
- **Location:** Phase 5, Step 5.1 — `tx_velocity_on_response_e2e.rs` test `fingerprint_fallback_when_no_cookie`
- **Flaw:** Test asserts `snap.iter().any(|s| s.key == *fp)`. The submission key is set via `fp_key_for_submission(key: &SessionKey) -> FpKey` (verified at `crates/waf-engine/src/checks/tx_velocity/recorder.rs:32-37`), which returns `fp.clone()` for `SessionIdent::Fingerprint(fp)` — so the assertion CAN pass for the FP-identity case. **However**, the test relies on the velocity classifier actually firing (max_count: 2, 3 records breach) AND the cooldown signaling once. With phase-3 changes, the classifier now runs on `set_outcome`, not `record`. The plan correctly moves the eval, but `set_outcome` runs the classifier only if it finds a matching slot to flip. In the e2e test, every `check.check(&ctx)` records `ok=false`, then `check.on_response(&ctx, 200)` finds the most-recent Withdrawal slot and flips it. After 3 iterations, the ring has 3 events, all `ok=true`. Classifier sees `count=3, ok_count=3` → fires. So the test passes, but for **subtle reasons** the plan doesn't explain: the slot-flip must walk newest-first AND the cooldown gate must be reset_state-aware. Independent issue: the test for cookie path uses `count: 3` exact match, but the classifier was configured with `max_count: 2`. After 3 records, classifier fires. After 4+ records, classifier fires again (cooldown 0). The test asserts `count: 3` exactly, ignoring possible `count: 4, 5, …` firings — fragile but defensible. The plan never enumerates this.
- **Failure scenario:** Engineer runs the new e2e test. If `set_outcome`'s "first match wins" loop has an off-by-one in the modular arithmetic `(entry.head + WINDOW - 1) % WINDOW`, the flip might miss the freshest slot, leaving all events at `ok=false`. Classifier still fires (count > max_count), but `ok_count=0` — test fails with "expected ok_count=3, got ok_count=0". Plan doesn't include a unit test that verifies the specific newest-first walk semantics under `record()` head-advancing semantics — Step 3.1's `set_outcome_flips_ok_on_most_recent_matching_event` partially covers it but only across 3 events in one role, not after head wraps.
- **Evidence:**
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:32-37` — `fp_key_for_submission` collapses cookie ident to `FpKey::default()`
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:66-75` — `ActorTx::record` advances `head = (head+1) % WINDOW`; freshest slot is at `(head + WINDOW - 1) % WINDOW`, which matches plan but isn't bench-tested under wrap
  - Phase-05 test config: `max_count: 2`, 3 records, cooldown 0 — fires repeatedly; first fired submission may have `count: 3` or higher depending on `set_outcome` timing
- **Suggested fix:** Add a regression test in Phase 3 that records 18+ events (head wraps past WINDOW=16) and verifies `set_outcome` still flips the newest matching slot. In Phase 5, relax the `count: 3` exact match to `count >= 3` to absorb cooldown-zero re-fires. Document explicitly that `fp_key_for_submission` returns `FpKey::default()` for cookie-identity submissions, so the cookie-path e2e tests CANNOT assert on the submission `key` field (they don't, but the next engineer to extend the test might).

---

## Finding 6: Phase-05 `build_request_ctx` test helper imports `waf_common::HostConfig` + `waf_common::tier::{Tier, TierPolicy}` — verify those re-exports

- **Severity:** Medium
- **Location:** Phase 5, Step 5.1 — `build_request_ctx` helper at the bottom of the e2e test file
- **Flaw:** Helper uses `use waf_common::{HostConfig, RequestCtx}; use waf_common::tier::{Tier, TierPolicy};`. `crates/waf-common/src/lib.rs` does `pub use types::*;` — `RequestCtx`, `HostConfig`, `GeoIpInfo` will be reachable as `waf_common::HostConfig` and `waf_common::RequestCtx` via the glob. `tier` is a module (`pub mod tier;` line 4 of lib.rs) AND also glob-re-exported via `pub use tier::*;` (line 11). So both `waf_common::tier::Tier` AND `waf_common::Tier` are valid. The plan's import works. **However**, the helper also imports `FingerprintValue, FpKey` from `waf_common` (Step 5.1, "fingerprint_fallback_when_no_cookie" test) — these only become reachable after Phase 1 lands AND `waf-common/lib.rs` re-exports them. Plan-01 Step 1.2 sub-step 4 says "Re-export from `waf-common` lib root if `types::*` is not already glob-exported — check `crates/waf-common/src/lib.rs` first". It already IS `pub use types::*;` — so as long as `types.rs` exports `pub struct FpKey`, the `waf_common::FpKey` path works. Good. But the plan never confirms this by name.
- **Failure scenario:** If Phase 1 implementer doesn't add the new types to `types.rs` with `pub` visibility, or paths them inside an inner module, the e2e test imports break. Low risk because the mechanical move preserves `pub struct`, but if someone adds a private helper alongside, this breaks.
- **Evidence:**
  - `crates/waf-common/src/lib.rs:11` — `pub use types::*;` (glob)
  - `crates/waf-common/src/types.rs` — `pub struct GeoIpInfo`, `pub struct RequestCtx` confirmed
  - Plan Phase 1 Step 1.2 step 4 says "if other types are re-exported there (mirror existing pattern)" — accurate but lukewarm
- **Suggested fix:** Phase 1 success criterion already includes "`FpKey` reachable via `waf_common::FpKey`" — but make it an explicit `cargo check -p waf-engine --test tx_velocity_on_response_e2e` rehearsal step (e.g., before declaring Phase 1 done, the engineer runs a one-line `use waf_common::FpKey;` compile check). Currently the success criterion is "`grep -rn "pub struct FpKey…" crates/` returns one site" — a structural check, not a usability check.

---

## Finding 7: Phase-03 `set_outcome` cooldown-and-spawn block silently inherits a runtime requirement: `tokio::spawn` requires an active Tokio runtime. `engine.on_response` is called from a sync `response_filter` context — verify

- **Severity:** High
- **Location:** Phase 3, "Step 3.3 — implement set_outcome + strip record()" sub-step 2
- **Flaw:** Plan says: "After dropping the entry guard, run the cooldown + snapshot + classifier loop that previously lived in `record()`. … Use the existing `fp_key_for_submission` helper and `tokio::spawn` for the aggregator submit." The current `record()` was *also* called from `check()` which runs inside Pingora's async runtime, so `tokio::spawn` works. But Pingora's `response_filter` (`crates/gateway/src/proxy.rs:851-869`) is `async fn`, called from inside Tokio, so `tokio::spawn` continues to work there too — for the **gateway path**. For the **engine-level test** (`engine_late_pipeline.rs`, `engine_late_log_only_geo.rs`, `tests/common/mod.rs`), some currently call `engine.evaluate()` synchronously from `#[test]` (not `#[tokio::test]`). If any of them now also call `engine.on_response()` (and the plan suggests in Phase 5 to "pair every call site of `engine.evaluate` with `engine.on_response` in production paths"), `tokio::spawn` panics with "there is no reactor running".
- **Failure scenario:** Engineer dutifully pairs every `engine.evaluate` test call with `engine.on_response` per phase-03 Risk Assessment row "Engine `on_response` not called from `prx-waf` integration tests that bypass the gateway: All call sites of `engine.evaluate` should pair…". If those tests are not `#[tokio::test]`, the new `set_outcome`'s `tokio::spawn` panics inside the synchronous test, hiding the real assertion failure under a runtime panic.
- **Evidence:**
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:213-215` — current `tokio::spawn(async move { aggregator.submit(…).await })` requires runtime
  - Phase 3 plan does not enumerate which engine tests need `#[tokio::test]` annotation if they start calling `on_response`
  - Pingora's `ProxyHttp::response_filter` is `async` — gateway path safe
- **Suggested fix:** In Phase 3 Risk Assessment, add a row: "`set_outcome` calls `tokio::spawn`; tests calling it without `#[tokio::test]` will panic. Use the existing `#[tokio::test]` annotation pattern (recorder.rs pipeline tests already use it). Engineer-tier integration tests in `tests/engine_*.rs` use synchronous `#[test]`; if they call `on_response`, switch them to `#[tokio::test]`." Also acknowledge the Phase 5 Risk Assessment line "E2E test brittle to `flush()` timing" — same `tokio::time::sleep(10ms)` is required at every `on_response` test, and the plan's helper `flush()` only appears in the new e2e file, not in the ported pipeline tests.

---

## Finding 8: Phase-04 `evaluate_velocity` signature change is `(u32, u32) → (u32, u32, u32)` but the `count.try_into().unwrap_or(u32::MAX)` pattern in existing code is replaced with `saturating_add` — semantic shift not flagged

- **Severity:** Medium
- **Location:** Phase 4, "Step 4.3 — extend evaluate_velocity"
- **Flaw:** Current code (`crates/waf-engine/src/checks/tx_velocity/classifiers/withdrawal_velocity.rs:40-46`) uses `.filter(…).count().try_into().unwrap_or(u32::MAX)` — a usize→u32 saturating-via-try_into. Plan's new body uses `count.saturating_add(1)` in a manual loop — a u32 → u32 saturating-add. Semantically equivalent, but the new code introduces a `for ev in in_window` loop where the old code was a single iterator chain. Functionally fine, but the plan does not flag that `count.saturating_add(1)` differs from the original implementation pattern and may produce different perf characteristics (likely faster since one pass instead of two — but unverified). More importantly, the plan claims `ok_count <= count` is "encoded by the loop construction" — true *within a single classifier call*, but if `ok_count` is incremented before `count` (it is not, per the plan), the invariant would break. Iron Rule #1 also says no `.unwrap_or(…)` outside `#[cfg(test)]`? Actually Iron Rule bans `.unwrap()`/`.expect()`, not `.unwrap_or_default()`/`.unwrap_or(val)` — so the existing `.unwrap_or(u32::MAX)` is compliant. Plan replaces it with a manual loop — no Iron Rule issue, but a stylistic divergence the plan doesn't justify.
- **Failure scenario:** Reviewer asks "why did you stop using the iterator chain?" — author has no answer; PR thread bikesheds. Or worse, a future contributor reverts to the iterator chain and loses the dual-counter semantics. The plan doesn't say "we MUST switch to manual loop because we need two counters" — let the reader figure it out.
- **Evidence:**
  - `crates/waf-engine/src/checks/tx_velocity/classifiers/withdrawal_velocity.rs:40-46` — original chain
  - Phase 4 Step 4.3 — manual `for ev in in_window` loop
- **Suggested fix:** Add a one-line comment in the new `evaluate_velocity` body: "Manual loop replaces filter-and-count chain because we need both `count` and `ok_count` from one pass." Also consider keeping the iterator style: `let (count, ok_count) = in_window.fold((0u32, 0u32), |(c, ok), ev| (c.saturating_add(1), ok.saturating_add(u32::from(ev.ok))));` — one pass, no manual loop, preserves stylistic continuity.

---

## Finding 9: Phase-02's `with_device_fp` builder method bypasses one path — `request_ctx_builder` is also constructed by tests that don't go through the gateway; "Default-impl-not-needed" claim is shaky

- **Severity:** Medium
- **Location:** Phase 2, Step 2.3 (builder change) + Risk Assessment row "Test fixtures default-construct `RequestCtx` somewhere (no struct literal)"
- **Flaw:** Plan says "Currently no `Default` impl exists; this is fine." Confirmed — `grep -n "impl Default for RequestCtx\|RequestCtx::default" crates/` does not return any production impl. But `grep -rn "RequestCtxBuilder" crates/` would reveal whether the builder is used in tests *without* `.with_device_fp(…)`. Plan's new field default in the builder is `device_fp: Option<Arc<FpKey>> = None` — fine. But for tests that construct `RequestCtx` via struct literal (the 164 sites in Finding 2), they all need an explicit `device_fp: None,`. Plan acknowledges this in Step 2.6 but understates the count. **The subtler issue:** Phase 2 says the field goes "after the `cookies` field". The struct currently ends with `pub cookies: HashMap<String, String>,` at line ~52 of `crates/waf-common/src/types.rs`. Test fixtures that use trailing-field positional reasoning ("the field at the end") via `..base_ctx` syntax — none verified to exist, but worth scanning.
- **Failure scenario:** A test uses `RequestCtx { device_fp: Some(fp), ..base_ctx }` where `base_ctx` was built before phase-02. After upgrade, `base_ctx` has `device_fp: None` and the override works. No regression. But if someone copy-pastes the old fixture and the field order in the struct changes (unlikely but possible), grep won't help.
- **Evidence:**
  - `crates/waf-common/src/types.rs:21-55` — `RequestCtx` definition
  - `grep -n "..base_ctx\|..ctx_with" crates/waf-engine/src/checks/tx_velocity/check.rs:167-170` — uses spread syntax already in `missing_session_skips_recording`
- **Suggested fix:** Phase 2 should add explicit recommendation: "After adding `device_fp`, also derive `Default` on `RequestCtx` so future field additions don't require touching 164 fixtures. Failing that, document the convention that all fixtures use `..base_ctx_for_test()` builders." This is a YAGNI vs maintenance trade-off the plan dodges.

---

## Finding 10: Phase-05's docs trail is incomplete — `docs/codebase-summary.md` claim is conditional, gateway CLAUDE.md isn't mentioned, FR-012 parent plan's status (already `complete`) is contradicted

- **Severity:** Medium
- **Location:** Phase 5, Step 5.3 — docs updates + plan.md "Cross-Plan Scan"
- **Flaw:** Phase 5 says "Modify `docs/codebase-summary.md` (if it documents FR-012)" — conditional, no grep verification. Also says "Modify `crates/waf-engine/CLAUDE.md` if it describes tx_velocity classifier signal payload". Both conditionals depend on the engineer remembering to check. More importantly: plan.md Cross-Plan Scan says "parent plan, status=`complete`" but Phase 5 step 5.3 instructs adding a `## Follow-ups (post-completion)` block to the parent plan — completing a plan and then editing it is a workflow pattern this codebase may or may not follow. The plan does NOT explicitly check `plans/260504-1632-fr-012-transaction-velocity/plan.md` for an existing `## Follow-ups` section (just appends one). Verify the parent plan structure first or risk creating duplicate sections. Also missing: `crates/gateway/CLAUDE.md` lists features but doesn't mention `engine.on_response` dispatch — phase-05 step 5.2 modifies the `proxy.rs:861` comment but doesn't update the gateway crate's CLAUDE.md to mention FR-012 on the response path.
- **Failure scenario:** Plan ships, but a future operator reading `crates/gateway/CLAUDE.md` doesn't find FR-012 in the Features section (it's listed under waf-engine's CLAUDE.md only). Confusion: "is tx_velocity active in the gateway or only engine-internal?"
- **Evidence:**
  - `crates/gateway/CLAUDE.md` — Features section lists "Per-request context", "Filter chain", "Access phase" — no FR-012 / tx_velocity mention
  - `crates/waf-engine/CLAUDE.md` — Features list contains "Device fingerprinting (FR-010)", "CrowdSec integration", etc. but tx_velocity is not on the bullet list (verified — section ends at "Block page: rendered response for denied requests")
  - Plan's Step 5.3 explicitly mentions only `crates/waf-engine/CLAUDE.md`
- **Suggested fix:** Replace conditional doc updates with explicit ones: (a) confirm via grep that `docs/codebase-summary.md` mentions FR-012 (run the grep IN the phase plan, not as a TODO); (b) add `crates/gateway/CLAUDE.md` to the Modify list and append "FR-012 tx_velocity on_response dispatch hitches on the same `engine.on_response` call as FR-018"; (c) before editing the parent plan, verify it doesn't already have a `## Follow-ups` section.

---

## Unresolved Questions

- Plan claims `tokio::spawn` inside `set_outcome` works in test contexts — should phase-03 spell out `#[tokio::test]` requirement, or change to a blocking submit for testability?
- Should `RequestCtx` gain a `Default` impl as part of this plan to absorb the 164-fixture churn debt going forward? (Plan dodges — answers via "no derive needed" but doesn't say "we should add one for next time").
- Phase-05 says `cargo bench -p waf-engine --bench tx_velocity_eval 2>/dev/null || true` — does this bench actually exist? Found `tx_velocity_bench.rs`, not `tx_velocity_eval`. Verify the bench name before claiming "p99 < 5% regression".

**Status:** DONE_WITH_CONCERNS
**Summary:** 10 findings; plan understates scope (164 RequestCtx sites vs. claimed ~30-50), misses 27 `store.record(..., true)` callers including benches+tests+integration, fails to flag the exhaustive `Signal::WithdrawalVelocity { count: 5, window_sec: 60 }` literal in `risk/ingest/signal_to_contributor.rs:193`, and dodges the `tokio::spawn`-without-runtime hazard in non-async tests. Most findings are scope/process gaps rather than design errors; the design itself is sound.
**Concerns:** Engineering effort is likely 1.5-2× the stated estimates; bench files outside the listed Modify set will block CI on the `cargo check --workspace` gate.
