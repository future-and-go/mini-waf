# 2026-07-05 — GH-205: geoip updater hardened fetch

## What

Routed the ip2region xdb updater through the same SSRF-hardened fetch posture
as the remote rules loader, on branch `fix/gh-205-geoip-updater-hardened-fetch`
(stacked on `fix/gh-203-geo-allowonly-fail-policy`):

1. **New shared module `waf-engine/src/validated_fetch.rs`.**
   `build_validated_client(url, connect_timeout, total_timeout, user_agent)`
   validates the URL against private/reserved/loopback/IMDS ranges, pins the
   client to the IPs resolved at validation time (DNS-rebinding TOCTOU),
   disables redirects, and sets timeouts + a stable `mini-waf/<ver>` UA.
   `rules/manager.rs::fetch_remote_content` was refactored onto it — DRY is
   the fix; the drift between the two fetch paths was the root cause.

2. **`geoip_updater.rs` hardened.** `check_update` (HEAD) and `download`
   (GET) build one validated client per cycle from `source_url`; the old
   bare `build_client` (no validation, no redirect policy, no connect
   timeout) is removed. `download_one` no longer buffers the body with
   `resp.bytes()`: it fast-rejects an advertised `Content-Length` over
   `MAX_XDB_RESPONSE_SIZE` (64 MiB) and streams to `<file>.tmp` with a
   running cap via `relay::intel::atomic_swap::stream_to_tmp` (promoted to
   `pub(crate)`). Searcher-validate-then-rename atomicity unchanged.
   Missing-local-file check moved before client construction so the
   "files absent → download needed" answer needs no network and no URL
   validation.

## Verified

- `validated_fetch`: private/loopback/IMDS/file-scheme URLs → `Err`; public
  IP-literal → `Ok`.
- `geoip_updater`: private + IMDS `source_url` rejected in both
  `check_update` (files present) and `download`; oversized response → `Err`,
  no final xdb, no tmp left; 302 → `Err("HTTP 302 …")`, redirect target
  never fetched (wiremock `expect(0)`); invalid xdb body → Searcher
  validation failure, tmp cleaned. Existing duration/xdb-info/constructor
  tests unchanged.
- `rules::manager` 11 tests green after the refactor; waf-engine lib 1448
  passed (only the known 6 docker-gated `engine::tests` failures). Clippy
  (default + `redis-store`, all targets) and fmt clean.

## Gotchas

- SSRF validation rejects loopback by design, so `download()` cannot be
  pointed at a local test server. Tests build the client through
  `build_validated_client` against a public IP-literal placeholder (never
  contacted — same redirect policy/timeouts/UA) and drive `download_one`
  directly; the full-path wiring is covered by the private-host `Err` tests.
- The oversized test relies on the `Content-Length` fast-reject (wiremock
  sets CL from the 64 MiB + 1 body), so no body bytes stream in CI; the
  mid-stream cap loop itself is covered by `atomic_swap`'s own tests.
- `check_update`'s HEAD warn-and-continue on non-success status is
  unchanged; only client construction and ordering moved.
