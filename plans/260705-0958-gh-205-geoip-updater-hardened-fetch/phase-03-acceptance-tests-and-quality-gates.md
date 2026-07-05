---
phase: 3
title: "Acceptance tests and quality gates"
status: pending
effort: "1.5h"
---

# Phase 3: Acceptance tests and quality gates

## Overview

Prove the three acceptance behaviors — oversized response rejected, private-range URL
rejected, redirect not followed — and run the workspace gates.

## Requirements

- Tests exercise the real download path (`XdbUpdater::download` / `check_update`) against
  a local test HTTP server, not mocks of the client internals.
- Assertions target observable behavior: an `Err` is returned and the live xdb (if any)
  is untouched; no partial/oversized tmp file is promoted.

## Test Matrix

| Behavior | Type | Setup | Expected |
|----------|------|-------|----------|
| Oversized response rejected | integration | local server returns body > `MAX_XDB_RESPONSE_SIZE` (and/or a `Content-Length` over cap); `XdbUpdater::new(dir, server_url)` | `download` returns `Err`; no final xdb written; tmp removed |
| Private-range URL rejected | unit/integration | `XdbUpdater::new(dir, "http://127.0.0.1:<p>/data")` (and one `http://169.254.169.254/...` IMDS case) | `check_update`/`download` return `Err` from SSRF validation, before any socket to the target |
| Redirect not followed | integration | local server replies `302` to a second location | request surfaces the 3xx as non-success → `Err`; redirect target never fetched |
| Helper SSRF unit | unit | `build_validated_client("http://10.0.0.1/")` | `Err` |
| Regression | unit | existing `parse_duration_*`, `xdb_file_info_*`, `updater_constructors_*` | unchanged, green |

- Use the test-server approach already present in the crate (e.g. a `tokio` TcpListener
  or an existing local-server helper used by relay/manager tests) — check
  `crates/waf-engine/tests/` and `rules::manager`/`atomic_swap` tests for the established
  pattern rather than adding a new HTTP-mock dependency.
- Do **not** encode plan/issue IDs or "FR"/"GH" codes in test names (repo rule). Name by
  behavior, e.g. `download_rejects_oversized_response`, `check_update_rejects_private_host`,
  `download_does_not_follow_redirect`.

## Implementation Steps

1. Add the SSRF-reject unit test alongside `build_validated_client` (Phase 1 module).
2. Add integration tests for oversized / private-range / redirect in `geoip_updater.rs`
   `#[cfg(test)]` (or `crates/waf-engine/tests/` if a shared local-server helper lives there).
3. For the oversized case, keep the emitted body modest but over a *test-scoped* cap if
   64 MiB is impractical to stream in CI — prefer asserting the `content_length`
   fast-reject path with a small advertised-oversize header, plus one mid-stream case with
   a lower injected bound if the helper allows a test seam; otherwise document why the
   streamed-oversize case is size-bounded in CI.
4. Run gates.

## Quality Gates

- [ ] `cargo test -p waf-engine geoip_updater` green (incl. new integration tests).
- [ ] `cargo test -p waf-engine validated_fetch` green.
- [ ] `cargo test -p waf-engine rules::manager` green (Phase 1 refactor regression).
- [ ] `cargo clippy -p waf-engine --all-targets` clean (no unused/orphan warnings from
      the removed `build_client`).
- [ ] `scripts/bin/harness-cli query matrix` quick checks pass for the touched lane.

## Success Criteria

- [ ] Oversized response → `download` `Err`, no xdb replaced.
- [ ] Private-range / IMDS `source_url` → `Err` before target connect.
- [ ] Redirect → not followed, `Err`.
- [ ] All existing geoip/manager tests still pass.

## Risk Assessment

- Likelihood Medium / Impact Low: streaming a genuinely 64 MiB body in CI is slow.
  Mitigation: rely primarily on the `content_length` fast-reject for the oversized
  assertion and keep any real streamed-oversize body small via a test-scoped bound if a
  seam exists; note the limitation rather than shipping a slow test.
- Likelihood Low / Impact Medium: private-range validation happens in
  `waf_common::url_validator`; ensure the test URL truly resolves to a blocked range
  (IP literals like `127.0.0.1` / `169.254.169.254` are deterministic; avoid hostnames
  that depend on CI DNS).

## Rollback

Tests are additive. Reverting Phases 1-2 makes these tests fail/compile-error; remove them
in the same revert. No production impact.
</content>
