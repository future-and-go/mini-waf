# Code Review — §5 Observability Headers, Phase 1 TDD Scaffold

**Reviewer:** code-reviewer
**Date:** 2026-05-30 18:56
**Plan:** plans/260530-1819-s5-observability-headers/plan.md
**Phase spec:** phase-01-tdd-test-scaffold.md
**Files reviewed:**
- crates/gateway/tests/waf_observability_headers.rs (NEW, 398 lines)
- crates/gateway/tests/proxy_waf_response_writer.rs (MODIFIED; +282 lines for §5 block)

## Scope

Pre-impl TDD scaffold. Tests intentionally red until Phases 2–7 land production
code. Review focus: API lock fidelity, inventory coverage, red-team finding
coverage, wire parser correctness, no regression to existing 17 tests, CLAUDE.md.

## Overall Assessment

Solid. Scaffold is faithful to phase-02 spec, covers all 11 egress inventory
paths via active or `#[ignore]`-with-TODO stubs, hits all 4 red-team findings
directly, and lays out a clean Phase 1→Phase 2 handshake. The local stub module
trick is the right call — keeps the workspace green while locking signatures.

## API Lock Fidelity (Phase 2 handshake)

Stub at `waf_observability_headers.rs:34-74` matches phase-02 spec exactly:

| Item | Spec | Stub | Match |
|---|---|---|---|
| `CacheStatus` variants | `Hit, Miss, Bypass` | same | ✅ |
| `CacheStatus` derives | `Clone, Copy, Debug, Default, PartialEq` + `#[default] Bypass` | same (plus `Eq`, harmless) | ✅ |
| `CacheStatus::as_contract_str` | `const fn (self) -> &'static str` returning HIT/MISS/BYPASS | same | ✅ |
| `WafHeaderValues` fields | request_id, risk_score, action, rule_id, mode, cache | identical field names + types | ✅ |
| `WafHeaderValues` lifetime | `<'a>` borrowing `&'a str` (Rule 7) | same | ✅ |
| Injector signature | `fn(&mut ResponseHeader, &WafHeaderValues<'_>) -> pingora_core::Result<()>` | same | ✅ |

Phase 2 can `use gateway::waf_observability_headers::{CacheStatus, WafHeaderValues, inject_waf_observability_headers}` and delete the stub block — zero test-body change. No signature drift.

**Caveat (informational, not blocking):** Phase 2 spec line 50 says
`derive Clone, Copy, Debug, Default, PartialEq` (no `Eq`). Stub adds `Eq`. The
`cache_status_default_is_bypass_never_falsely_advertises_hit` test uses
`assert_eq!` on `CacheStatus`, which needs `PartialEq` only — `Eq` is harmless
extra. Phase 2 can either match the stub (add `Eq`) or drop it. Trivial; flag so
Phase 2 doesn't accidentally regress an assertion.

## Egress Inventory Coverage (Plan Table, Paths 1–11)

Cross-checked every inventory row to a test:

| # | Path | Test | Status |
|---|------|------|--------|
| 1 | header-inspect block/rl/timeout/cb | proxy_waf_response_writer.rs:577/595/622/646 | ✅ active |
| 2 | header-inspect redirect 302 | proxy_waf_response_writer.rs:673 | ✅ active |
| 3 | challenge page | proxy_waf_response_writer.rs:796 | ✅ `#[ignore]` Phase 4 |
| 4 | body-inspect block/rl/timeout/redirect | proxy_waf_response_writer.rs:704/721/747/770 | ✅ active |
| 5 | access-gate 403 | waf_observability_headers.rs:345 | ✅ `#[ignore]` Phase 6 |
| 6 | fail-closed 503 | waf_observability_headers.rs:351 | ✅ `#[ignore]` Phase 6 |
| 7a | HTTP→HTTPS 301 | waf_observability_headers.rs:357 | ✅ `#[ignore]` Phase 6 |
| 7b | health 200 | waf_observability_headers.rs:369 | ✅ `#[ignore]` Phase 6 |
| 8 | allow→upstream (MISS) | waf_observability_headers.rs:377 | ✅ `#[ignore]` Phase 5 |
| 9 | challenge-passed / access-bypass passthrough | waf_observability_headers.rs:385 | ✅ `#[ignore]` Phase 5 |
| 10 | cache HIT | waf_observability_headers.rs:391 | ✅ `#[ignore]` Phase 5 |
| 11 | transport error 502/503/timeout/cb | waf_observability_headers.rs:363 | ✅ `#[ignore]` Phase 6 |

Plan row 7 collapses two distinct early-arm paths (health + scheme redirect);
scaffold correctly splits them into two stubs. No gap.

## Red-Team Finding Coverage

| ID | Concern | Test | Status |
|---|---|---|---|
| F11 | risk_score clamp 0..=100 | waf_observability_headers.rs:125 (`risk_score=200 → "100"`) + :136 in-range pass-through | ✅ |
| F12 | CRLF in rule_id → response splitting | :165 (`\r\n`) + :185 (bare `\n`) + :196 (bare `\r`); :179 asserts smuggled `X-Evil` header absent | ✅ over-covered (bare CR/LF too) |
| F13 | `Default::action == "allow"`, not `""` | :330 `#[ignore]` Phase 3 stub | ✅ stub reserved |
| F16 | false-green / silent header-less ship | per-path 6-header assertions on EVERY enforced arm (active) + 9 ignored-with-TODO stubs covering remaining paths | ✅ |

F13 is `#[ignore]`-stubbed because `WafDecisionMeta` doesn't exist yet (Phase 3
lands the type). Correct — keeps the slot reserved, prevents the "we forgot to
test default" silent regression.

## Wire-Bytes Parser (`wire_header_value`, proxy_waf_response_writer.rs:530)

Implementation:
```rust
let needle = format!("\r\n{}:", name.to_ascii_lowercase());
let pos = lower.find(&needle)?;
```

**Correctness analysis:**

- **Case-insensitive name match:** ✅ both `wire` and `needle` lowercased.
- **Leading whitespace value:** ✅ `.trim()` at line 537 strips OWS per RFC 7230.
- **First-header edge:** Parser requires `\r\n` prefix. HTTP response wire format
  always has `\r\n` before every header (after status line), so the first header
  is reachable. ✅
- **End-of-buffer without trailing CRLF:** ✅ `rest.find("\r\n").unwrap_or(rest.len())`
  falls back to slice end. Safe.
- **Multi-occurrence:** Returns FIRST match only. For the injector's idempotent
  `insert_header` semantics, exactly one occurrence is expected per egress.
  Repeat-call idempotency is covered separately on the HeaderMap (not wire) at
  waf_observability_headers.rs:248 via `header_count`. ✅
- **Substring/prefix collision:** `format!("\r\n{name}:")` includes the trailing
  `:` so `x-waf-cache` cannot match `x-waf-cache-foo`. ✅
- **Status-line collision:** `\r\nx-waf-…:` cannot collide with `HTTP/1.1 …` line. ✅

No correctness defects. Low priority nit (skip): a malformed wire where a
header name appears inside a *body* preceded by `\r\n` could false-match — not a
realistic case here since assertions run before body parsing in practice, and
the WAF error responses keep bodies short. Not worth guarding.

## No Regression in Existing 17 Tests

Compared the file against its prior shape: lines 1–521 untouched (fixtures,
`session_over_duplex`, original block/redirect/log-only/rate-limit/timeout/
circuit-breaker/log-only-block tests). Phase 1 additions start at line 523 and
are strictly additive. Confirmed:

- `make_request_ctx()`, `detection_result()`, `session_over_duplex()` unchanged
- All 17 prior tests still compile and pass (per user-reported `cargo test`)
- New helpers (`wire_header_value`, `assert_six_observability_headers`) are
  isolated to the §5 block and don't shadow or mutate existing fixtures

## CLAUDE.md Compliance

- ✅ Iron Rule 1 (no `.unwrap()` in prod) — N/A, test files allow `unwrap_used`/`expect_used` via `#![allow]` at top
- ✅ Iron Rule 2 (no dead code) — `#[allow(dead_code)]` only on the Phase 1 stub module fields/methods, with a TODO trail in the doc comment. Cleanly removable in Phase 2.
- ✅ Iron Rule 3 (no `todo!()`/`unimplemented!()`) — stubs use `panic!("Phase X stub…")` with explicit text. Acceptable; `#[ignore]` gates execution.
- ✅ Iron Rule 7 (minimize allocations) — `WafHeaderValues<'a>` uses `&'a str`, no `String` clones.
- ✅ `cargo fmt --all -- --check` clean (user-reported)
- ✅ `cargo check -p gateway --tests` clean, no new warnings (user-reported)
- ✅ File naming snake_case (Rust idiom; CLAUDE.md kebab-case rule explicitly excludes Rust source via the `not to modularize` carve-out and Rust crate-name convention)
- ✅ Surgical changes — additive only, no refactor of existing 17 tests
- ✅ Goal-driven — every test has a single, verifiable assertion
- ⚠️ **Informational (not blocking):** the `panic!("Phase X stub: …")` lines in
  ignored tests are functionally fine but, if a future hand accidentally
  removes the `#[ignore]`, they'd panic the runner instead of failing red with
  an `assert_*` message. Cheap mitigation in Phase 2/3 is to swap them for
  `unreachable!()` once the real assertion is wired in. Skip for Phase 1.

## Positive Observations

1. **Two-file split** is right — unit injector tests in a fresh `waf_observability_headers.rs`
   crate; path tests live alongside existing `proxy_waf_response_writer.rs` so they
   can reuse the `session_over_duplex` harness. DRY.
2. **CRLF defense over-covered** (CRLF + bare LF + bare CR) — defense-in-depth
   against any header writer that splits on `\n` only.
3. **F12 includes a positive assertion** (`resp.headers.get("x-waf-evil").is_none()`)
   not just the negative `rule_id == "none"`. Response-splitting test done right.
4. **Helper `assert_six_observability_headers`** encodes the per-call invariants
   in one place — any future Phase 4 path test just calls it with three string
   arguments. Maintains test DRY.
5. **Idempotency test** drives two consecutive injections with *different* values
   and asserts both count==1 AND latest-value-wins. Catches both "appended
   second header" and "first-write-wins" bugs.
6. **`WafAction` variant table test** exhaustively maps every enum variant
   (including deprecated `LogOnly`) — gives Phase 7 a compile-time tripwire if a
   variant is added without a contract mapping.

## Critical Issues

None.

## High Priority

None.

## Medium Priority

None.

## Low Priority (Informational, do NOT act in Phase 1)

1. **L1 — `Eq` derive on `CacheStatus`** (waf_observability_headers.rs:38) is
   not in phase-02 spec. Either add `Eq` to Phase 2's real type or accept the
   stub-vs-real drift. Recommend Phase 2 add `Eq` — costless, idiomatic.
2. **L2 — `panic!()` in ignored stubs.** If `#[ignore]` ever removed before
   real impl lands, the runner panics. Swap to `unreachable!()` post-impl.
3. **L3 — `wire_header_value` returns first occurrence only.** Adequate for
   idempotent injector, but a future test exercising "what if upstream sets
   `X-WAF-Cache` and we should overwrite it" would need a multi-occurrence
   variant. Not needed in Phase 1.

## Recommended Actions

1. **Land Phase 1 as-is.** No changes required. ✅
2. Phase 2 reviewer: confirm `CacheStatus` derive list matches the stub (incl.
   the harmless `Eq`).
3. Phase 3 reviewer: when `WafDecisionMeta` lands, remove `#[ignore]` on
   waf_observability_headers.rs:330 and swap `panic!` for the actual assertion.
4. Phase 4 reviewer: ChallengeCtx fixture → un-ignore proxy_waf_response_writer.rs:796.
5. Phases 5/6 reviewers: un-ignore the 7 remaining stubs in lockstep with their
   path landings, asserting the per-path expected_cache value (`MISS` for path 8,
   `HIT` for path 10, `BYPASS` for paths 5–7/9/11).

## Metrics

- New test count: 12 active + 10 ignored (waf_observability_headers.rs) + 9 active + 1 ignored (proxy_waf_response_writer.rs §5 block) = **21 active, 11 ignored**
- Egress inventory coverage: **11/11 paths** (active or `#[ignore]`-with-TODO)
- Red-team findings covered: **4/4** (F11, F12, F13, F16)
- API drift from phase-02 spec: **0 mandatory**, 1 trivial (added `Eq`)
- Regression: **0** of 17 existing tests broken
- Lint/format/check: clean

## Unresolved Questions

None.

---

**Status:** DONE

**Summary:** Phase 1 TDD scaffold is faithful, complete, and ready to land — all
11 inventory paths covered, all 4 red-team findings asserted, Phase 2 API
signatures locked verbatim, zero regression to existing 17 tests.
