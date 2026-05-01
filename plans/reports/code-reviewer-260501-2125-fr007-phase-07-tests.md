# Code Review — FR-007 phase-07 Test Suite + Bench

**Reviewer:** code-reviewer
**Date:** 2026-05-01
**Scope:** 11 files (10 tests + 1 bench) + Cargo.toml dev-deps
**Plan spec:** plans/260501-2003-fr007-relay-proxy-detection/phase-07-tests-bench-coverage.md

## Overall Assessment

Strong, well-structured test suite. All 12 adversarial matrix rows present with correct expected assertions, no widening of production API surface, deterministic execution (no real network, all wiremock-bound to ephemeral ports). Bench compiles and exercises all 4 providers. Minor concerns around proptest seed pinning, one bench fidelity nit, and a couple of cosmetic items.

**Score: 8.5 / 10**

## Focus-Area Findings

### 1. Adversarial Test Matrix coverage — PASS

All 12 rows from phase-07 §Adversarial Test Matrix are present in `relay_adversarial.rs` and assertions match the table verbatim:

| # | Row | Test | Status |
|---|---|---|---|
| 1 | Trusted-tail spoof, no signal | `trusted_proxy_spoof_tail_real_ip_is_attacker_no_spoof_signal` | OK |
| 2 | Trusted-tail spoof + private mid → `XffSpoofPrivate` | `trusted_proxy_spoof_tail_with_private_mid_emits_spoof_private` | OK |
| 3 | Double XFF folded | `double_xff_header_folded_concatenated_correctly` | OK |
| 4 | RFC1918 mid-chain → `XffSpoofPrivate` | `rfc1918_mid_chain_after_public_emits_spoof_private` | OK |
| 5 | Chain >32 → `XffTooLong` | `chain_over_32_entries_yields_xff_too_long_no_panic` | OK |
| 6 | Header >8KB → `XffTooLong` | `header_over_8kb_rejected_at_byte_cap_xff_too_long` | OK |
| 7 | IPv6 zone-id stripped | `ipv6_zone_id_parsed_zone_stripped_no_error` | OK |
| 8 | Bracketed IPv6 + port | `bracketed_ipv6_with_port_parsed_correctly` | OK |
| 9 | Unicode → `XffMalformed` | `unicode_bytes_in_header_yield_xff_malformed` | OK |
| 10 | Empty XFF + X-Real-IP | `empty_xff_only_x_real_ip_uses_x_real_ip` | OK |
| 11 | All trusted → real_ip = peer | `all_chain_entries_trusted_real_ip_is_peer_no_signals` | OK |
| 12 | Compromised feed + operator allow | `compromised_feed_operator_allow_override_classified_residential` | OK |

### 2. Public-API fidelity — PASS

Tests consume only items already `pub` in `crates/waf-engine/src/relay/**` (`RelayDetector`, `ProviderRegistry`, `RelayConfig`, `Signal`, `ClientIdentity`, `XffValidator::new`, `ProxyChainAnalyzer::new`, `AsnClassifier::new`, `TorSet`, `TorExitMatcher::from_set`, `parse_xff_chain`, `MAX_HEADER_BYTES`, `MAX_CHAIN_ENTRIES`, `EmptyAsnDb`, `AsnRecord`, `DatacenterSet`, `RefreshOutcome`, `IntelProvider`). `git diff HEAD -- crates/waf-engine/src/lib.rs` shows only `pub mod relay;` added. No new `pub` introduced for tests.

### 3. Determinism — MOSTLY PASS, one nit

- **No real network:** all HTTP via wiremock on `127.0.0.1:0`. OK.
- **Tempfiles:** `TempDir` used everywhere, cleaned on drop. OK.
- **Hot-reload races:** `poll_until` with 1s deadline + 20ms interval, 50ms debounce. Bounded.
- **Proptest seed pinning — partial:** `relay_xff_proptest.rs` sets `failure_persistence: None` but does NOT pin a seed. proptest defaults to a fresh seed per run (env `PROPTEST_SEED` if set). The plan spec calls for "seed proptest" for determinism. Recommendation: either set `PROPTEST_SEED` in CI env or use `prop_assert!` with a fixed seed via `proptest_state_machine` / explicit `TestRng`. Current 256-case run is fast (<1s) and the invariants are total (never-panic + set-membership), so flake risk is minimal — listing as **Medium** not Critical.

### 4. Test quality — PASS, with one observation

Tests assert outputs (real_ip values, signal variants, file existence, ArcSwap snapshot equality), not just code paths. Each test pins concrete expected state. Two minor observations:

- `relay_asn_classifier.rs:41` uses `Box::leak(Box::new(HeaderMap::new()))` per `eval()` call. In a test binary this is benign (process exits), but this is a code smell. Cleaner: have the helper take a `&HeaderMap` and let the caller own. Not a blocker.
- `relay_pipeline_handover.rs:35` calls `det.evaluate(...)` then immediately discards the result via `let _identity = ...` and constructs `identity_with_xff` manually. The `evaluate` call is exercised but not asserted on — the test's load-bearing assertion is on the manually-constructed `ClientIdentity`. This is honest (the file documents that full Pingora harness is deferred), but the dead `evaluate` call could be removed. Cosmetic.
- `relay_e2e.rs:236` `xff_malformed_real_ip_falls_back_to_peer`: the test header `"not-an-ip"` is malformed; `XffValidator` then emits `XffMalformed` and chain is empty, so `derived().real_ip` falls back to `peer`. Good. **However** `relay_e2e.rs::ipv6_real_ip_resolved_correctly` only asserts `real_ip` and not signal absence — given AsnDb is `EmptyAsnDb` with no record set, this happens to work via `XffValidator`. Acceptable.

### 5. Bench correctness — PASS, with 1 fidelity gap

Spec line 91: "criterion benchmark `evaluate` w/ representative payloads (4-hop chain + ASN lookup)".

`benches/relay_eval.rs`:
- 4-hop chain ✓ (`203.0.113.5, 1.2.3.4, 5.6.7.8, 10.0.0.1`)
- All 4 providers registered ✓ (Xff, ProxyChain, AsnClassifier, TorExit with 10-IP set)
- **AsnDb is `EmptyAsnDb`** — bypasses real mmdb lookup work. The "ASN lookup" path measured is just the trait dispatch + `None` return, not a real binary-tree mmdb walk. Bench p99 will be optimistic vs production.

Verdict: Spec literally says the registry should perform an ASN lookup; current bench skips real lookup work. Recommendation: ship a tiny in-memory `StaticDb` (returns a fixed `AsnRecord`) so the classifier walks its full match logic (DC set lookup + override checks). **Medium priority.**

### 6. Cargo.toml hygiene — PASS, with 1 nit

`[dev-dependencies]` adds only `wiremock`, `proptest` (and bench entry `[[bench]] name = "relay_eval"`). Plan spec also called for `criterion`, `tempfile` — already present from prior phases. Clean.

**Nit:** `reqwest = { workspace = true, features = ["stream", "gzip"] }` was added to `[dev-dependencies]` (line 51 of new Cargo.toml). The same line/features are already present in `[dependencies]` (line 26 post-diff). Cargo will just merge features, but the dev-dep entry is redundant. Drive-by removal won't break anything; flagging as cosmetic.

The `[dependencies]` additions (`futures-util`, `flate2`, `maxminddb`, `http`) are out of phase-07 scope — they were added by prior FR-007 phases (not by phase-07's test work). They are in `git diff` because the diff is uncommitted.

## Critical Issues
None.

## High Priority
None.

## Medium Priority
1. **Proptest seed not pinned** (`relay_xff_proptest.rs:108-113`). Spec requires deterministic CI; default proptest config picks a fresh seed each run. Mitigate via `PROPTEST_SEED` in CI env or hard-code a seed.
2. **Bench uses `EmptyAsnDb`** — measures registry plumbing, not real ASN lookup cost. Replace with a `StaticDb` returning a fixed record so the classifier exercises its DC/override branches. p99 numbers will then better track production.

## Low Priority
3. `Box::leak(Box::new(HeaderMap::new()))` in `relay_asn_classifier.rs::eval` helper — change to `&HeaderMap` parameter.
4. Redundant `reqwest` re-declaration in `[dev-dependencies]`.
5. Dead `evaluate` call in `relay_pipeline_handover.rs::client_identity_real_ip_preferred_over_peer`.
6. `relay_intel_refresh.rs` does not test 304 path for `IptoasnFeed` gzip variant — plan-known deferral, ack'd.
7. WARN-log capture deferred in `relay_hot_reload.rs` — plan-known deferral, ack'd.

## Edge Cases (Scout)
- Wiremock mock ordering: `up_to_n_times(1)` + second mock with `if-none-match` — order matters; wiremock matches most-specific first by default. Tests appear correct but worth a `verify` on the server to ensure the intended request count was hit. Not blocking.
- `relay_hot_reload.rs::watcher_propagates_config_edit_within_one_sec` — 1s deadline on noisy CI runners (especially macOS notify backends with kqueue) may flake. Consider bumping to 3s for CI margin. Plan acceptance is "≤1s" per spec, so leaving as-is is defensible.
- Proptest invariant 2 (`real_ip ∈ {peer} ∪ chain`): when XFF is malformed, `parsed.entries` is empty AND `derived().real_ip` falls back to peer — invariant holds. Verified by inspection.

## Positive Observations
- Tests are 1:1 traceable to phase-07 spec rows (test names map to matrix rows).
- Adversarial file has banner-comment row markers (`─── Matrix row N ───`) — outstanding readability.
- Folded XFF header test correctly uses `headers.append` (not `insert`) to actually fold.
- `derive_real_ip` invariants tested both at unit (`relay_xff_parser.rs`) and e2e (`relay_e2e.rs`) levels.
- ASN classifier override-precedence covered (`operator_allow > operator_deny > asn_ids`).
- All test files have `#![allow(clippy::unwrap_used, clippy::expect_used)]` scoped at file level (acceptable in tests under the iron rules).

## Metrics
- Files: 11 (10 tests + 1 bench)
- LOC added: ~1.6k tests, 79 bench (rough)
- Adversarial matrix coverage: 12 / 12 rows
- Plan TODO items in scope: 12 / 14 covered (2 deferred = CI gates, plan-acknowledged)
- Public API widening: 0
- `cargo test -p waf-engine --tests`: green per task author
- `cargo clippy -p waf-engine --tests --benches -- -D warnings`: green per task author

## Recommended Actions
1. Pin proptest seed (env var in CI workflow OR `proptest_config` with explicit seed).
2. Replace `EmptyAsnDb` with `StaticDb` in `benches/relay_eval.rs` for fidelity.
3. (Optional) Remove redundant `reqwest` dev-dep line; drop `Box::leak` helper; remove dead `evaluate` call in handover test.

## Unresolved Questions
- Should the bench's TorSet contain entries that *might* match (worst-case) or be guaranteed-miss (best-case)? Current: guaranteed-miss. Production traffic is mostly miss, so best-case is defensible — but worst-case bench would harden the 50µs gate. Decide with spec author.
- Is `PROPTEST_SEED` set in the CI workflow file (not in scope here)? If yes, the determinism gap is closed at the CI layer.

---

**Status:** DONE_WITH_CONCERNS

Concerns: (1) proptest seed not pinned at source — mitigated only if CI env sets `PROPTEST_SEED`; (2) bench uses `EmptyAsnDb` so p99 number underestimates real ASN-lookup cost. Both are non-blocking for landing the test suite, but worth fixing before treating bench numbers as a production SLO.
