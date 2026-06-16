# E10: WAF Control Plane — Closure (Interop Contract v2.3 §2)

**Date:** 2026-06-16
**Severity:** Low (close-out; no defect)
**Component:** Control plane, benchmark-secret auth, capabilities/reset/profile/flush
**Status:** Closed

## What Happened

Epic E10 (WAF Control Plane, interop contract v2.3 §2) was code-complete and
test-covered, but never formally closed: its `README.md` story table still read
`planned` for all six stories, and no closing journal existed (unlike E16/E17).
This entry closes the paperwork gap and records the proof state.

Lane: high-risk (auth hard gate, public control API, audit interaction). Stories
US-1001…US-1006. Code lives in `crates/waf-api/src/interop_control.rs`,
`crates/waf-api/src/server.rs`, `crates/waf-common/src/config.rs`.

## Stories

- **US-1001** — Control plane mounted at `/__waf_control/*` on the admin API
  listener (`server.rs`), separate from the gateway proxy data path; never
  proxied upstream.
- **US-1002** — `benchmark_secret_guard`: `403` on missing/wrong
  `X-Benchmark-Secret` for all four endpoints; correct `waf-hackathon-2026-ctrl`
  proceeds; constant-time compare.
- **US-1003** — `GET /capabilities` returns
  `{ok, features{name:{supported,toggleable,policies[]}}, active{default_mode,overrides}}`;
  secret-gated.
- **US-1004** — `POST /reset_state` clears engine runtime state, response cache,
  crowdsec cache, mode registry; returns `{ok,action,audit_log_preserved:true,ts_ms}`;
  never deletes or truncates `waf_audit.log`.
- **US-1005** — `POST /set_profile` scope all/features/policies; unsupported items
  returned in `unsupported[]` (partial-success per decision 0008); echoes applied + active.
- **US-1006** — `POST /flush_cache` clears the response cache before returning success;
  secret-gated.

## Close-out Detail

The only code-side movement at closure was adding the unit proof for US-1002's
constant-time comparator. `interop_control::constant_time_eq` had integration
coverage (`interop_control_integration`, `interop_mode_enforcement`) but no
dedicated unit test asserting the three comparison branches. Added
`interop_control::tests`: equal inputs match, differing same-length inputs do not,
differing-length inputs do not. The matrix evidence note for US-1002 already
anticipated these three cases; the tests now make that note true.

## Verification

- `cargo test -p waf-api`: all suites green, 0 failures.
  - lib unit: 105 passed (includes the 3 new `interop_control::tests`)
  - `interop_control_integration`: 9 passed (US-1001/1003/1004/1005/1006, 403 path)
  - `interop_mode_enforcement`: 6 passed (US-1005 mode enforcement)
- Durable harness rows US-1001…US-1006 at status `implemented` with unit +
  integration proof flags set (US-1006 integration-only by design: cache is
  always-on in this build, so there is no not-supported branch to unit-test).
- `README.md` story table corrected `planned` → `implemented` for all six stories.

## Lessons Learned

**Durable status and epic paperwork drift apart.** The harness durable layer had
E10 at `implemented` with green proof, but the epic README lagged at `planned`.
Two sources of truth for the same fact will diverge unless one is derived from the
other; the README table is hand-maintained and went stale. Worth periodically
reconciling README status columns against the matrix (E17's README is still stale
at `in_progress` for the same reason).

**Evidence notes can precede the evidence.** US-1002's matrix note cited unit
tests that did not yet exist. Harmless here because integration coverage was real,
but a note describing proof should not outrun the proof it describes.

## Next Steps

None — E10 closed. Control plane is contract-complete: all four endpoints
secret-gated, constant-time auth, reset preserves audit log, set_profile partial-
success, flush_cache wired. Proof recorded; README reconciled.
