---
phase: 2
title: "Wire geoip updater to hardened fetch"
status: completed
effort: "1.5h"
---

# Phase 2: Wire geoip updater to hardened fetch

## Overview

Route the xdb updater's HEAD and GET through the Phase 1 validated client, and cap the
download with a streaming write to the tmp file. Remove the drifted `build_client`.

## Requirements

- Functional: `check_update` (HEAD) and `download_one` (GET) build their reqwest client
  via `validated_fetch::build_validated_client`, so both reject SSRF `source_url`s, pin
  IPs, disable redirects, and carry connect timeout + UA.
- Functional: the download body is bounded — an oversized response (advertised via
  `content_length` *or* discovered mid-stream) is rejected before it can OOM or land
  on disk as a completed xdb.
- Non-functional: the validate-then-rename atomicity of the current flow is preserved
  (a failed/oversized download never replaces the live xdb).

## Architecture

- Add `const MAX_XDB_RESPONSE_SIZE: u64 = 64 * 1024 * 1024;` to `geoip_updater.rs`
  (headroom over ~20 MB full xdb; `config.rs:906`). No config field.
- `check_update` (`67-105`): validate the base host once per cycle and build one
  validated client (both files share `github_base_url`), reuse it for both HEAD
  requests. Total timeout stays ~30s, connect timeout 5s, UA the shared `mini-waf/<ver>`.
  Note: HEAD carries no body, so the size cap does not apply here — only SSRF/pin/redirect/timeout.
- `download` (`119-134`): build one validated client (longer total timeout, e.g. 120s,
  matching current `build_client(120)`), pass it into both `download_one` calls.
- `download_one` (`168-211`): replace `client.get(url).send()` + `resp.bytes()` +
  `std::fs::write(tmp, bytes)` (`175-193`) with:
  1. GET; keep the existing status-success check (`181-183`).
  2. Stream the body to `<filename>.tmp` with a running byte cap of
     `MAX_XDB_RESPONSE_SIZE` and a `content_length` fast-reject. Reuse the crate's
     proven streaming-cap loop — either promote `relay::intel::atomic_swap::stream_to_tmp`
     to `pub(crate)` and call it (bounds `1..=MAX_XDB_RESPONSE_SIZE`), or lift the same
     `bytes_stream()`/`saturating_add`/cap loop into `validated_fetch`. Do **not** use
     `resp.bytes()`.
  3. Keep the existing Searcher validation of the tmp file (`197-202`) and the atomic
     `std::fs::rename` into place (`205-206`) — unchanged, and the reason `write_atomic`
     (which renames internally) is *not* used.
- Remove `build_client` (`284-289`) and its unit test `build_client_succeeds_with_reasonable_timeout`
  (`400-403`) — orphaned by the switch.

## Related Code Files

- Modify: `crates/waf-engine/src/geoip_updater.rs` (client build, HEAD, `download_one`,
  const, remove `build_client` + its test)
- Modify (conditional): `crates/waf-engine/src/relay/intel/atomic_swap.rs` — change
  `stream_to_tmp` (or a thin extracted variant) to `pub(crate)` if reusing it. If so,
  its module doc note about FR-007 scope should stay; only visibility changes.
- Depends on: Phase 1 `validated_fetch::build_validated_client`

## Implementation Steps

1. Add `MAX_XDB_RESPONSE_SIZE`; import `validated_fetch::build_validated_client`.
2. Rewrite `check_update` to build the validated client once from `github_base_url` and
   reuse across both HEAD requests; propagate validation errors as today.
3. Rewrite `download` to build the validated client and thread it into `download_one`.
4. Rewrite `download_one`'s fetch+write to stream-with-cap into tmp; keep validate + rename.
5. Decide the streaming-cap reuse (promote `stream_to_tmp` vs lift loop); wire it.
6. Delete `build_client` and its now-dead test.
7. `cargo test -p waf-engine geoip_updater` — existing duration/xdb-info/constructor
   tests still green (they do not touch the network).

## Success Criteria

- [ ] `download_one` contains no `resp.bytes()`; body is streamed to tmp with a cap.
- [ ] Both HEAD and GET clients come from `build_validated_client` (no bare
      `reqwest::Client::builder()` left in `geoip_updater.rs`).
- [ ] `build_client` is gone; `cargo build -p waf-engine` has no unused-fn/import warnings.
- [ ] A `source_url` in a private range causes `check_update`/`download` to `Err`
      (verified fully in Phase 3).

## Risk Assessment

- Likelihood Medium / Impact Medium: sync (`std::fs`) vs async (`tokio::fs`) mismatch if
  reusing `stream_to_tmp` (async). Mitigation: `download_one` is already `async`; await
  the stream, then keep sync Searcher-validate + `std::fs::rename` (or switch that pair to
  `tokio::fs::rename`). Keep the tmp-path naming identical (`<filename>.tmp`) so cleanup
  semantics are unchanged.
- Likelihood Low / Impact High: pinning against the base host but GETting `base/<file>` —
  same host, so one validation/pin covers both files. Confirm both filenames share
  `github_base_url`'s host (they do; URL is `format!("{base}/{file}")`).
- Default `source_url` is a public GitHub host → validation passes in production; a test
  fixture must point at a local server, so tests inject the URL via `XdbUpdater::new`.

## Rollback

Revert `geoip_updater.rs` (and the `atomic_swap.rs` visibility change if made). Phase 1's
`validated_fetch` module can remain — it is independently useful and referenced by the
manager. No persisted state changes.
</content>
