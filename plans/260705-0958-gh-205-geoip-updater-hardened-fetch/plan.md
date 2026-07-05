---
title: "GH-205 geoip updater: hardened fetch (SSRF validation, size cap, bounded redirects)"
description: "Route the ip2region xdb downloader through a shared SSRF-validated, IP-pinned, redirect-disabled, size-capped fetch path instead of a plain reqwest client"
status: pending
priority: P2
branch: "main-harness"
tags: [bug, area:engine, geoip, security, gh-205]
blockedBy: []
blocks: []
created: "2026-07-05T03:05:58.265Z"
createdBy: "ck:plan"
source: skill
issue: https://github.com/future-and-go/mini-waf/issues/205
---

# GH-205 geoip updater: hardened fetch (SSRF validation, size cap, bounded redirects)

## Overview

Issue: https://github.com/future-and-go/mini-waf/issues/205 (P2 bug, `risk:security`,
CONFIRMED by multi-agent review 2026-07-03; all claims re-verified on HEAD `9ee484b`,
2026-07-05).

The ip2region xdb auto-updater fetches with a bare reqwest client that has drifted
from the crate's hardened fetch posture:

- `geoip_updater.rs:284-289` `build_client(timeout_secs)` sets **only** a total
  timeout. No SSRF validation, no IP pinning, no connect timeout, no User-Agent,
  and reqwest's **default redirect policy (follows up to 10)**.
- `download_one` (`geoip_updater.rs:175-190`) does `client.get(url).send()` then
  `resp.bytes()` (185-188) which **buffers the entire body with no size cap** — a
  misbehaving/compromised upstream can drive OOM.
- `check_update` (`geoip_updater.rs:67-105`) issues `HEAD` through the same
  unhardened client against the same operator URL.

Canonical hardened patterns already in the crate (the fix reuses these rather than
adding a third drifting copy — drift *is* the root cause):

- **SSRF-safe client**: `rules/manager.rs:460-523` `fetch_remote_content` —
  `waf_common::url_validator::validate_public_url_with_ips` (validate + resolved
  addrs), `resolve_to_addrs` IP pinning against DNS rebinding, `redirect::Policy::none()`,
  30s total + 10s connect timeout, 10 MiB body cap (`MAX_RULES_RESPONSE_SIZE`,
  `manager.rs:447`).
- **Streaming size cap**: `relay/intel/atomic_swap.rs:67-97` `stream_to_tmp` —
  `content_length` pre-check + running per-chunk cap via `bytes_stream()`, the only
  form that protects when the server omits/lies about `Content-Length`
  (`resp.bytes()` + post-check does not — it OOMs first).
- **Shared client baseline**: `relay/intel/http.rs:24` `build_client` — connect
  timeout 5s, stable `mini-waf/<ver>` UA, `redirect::limited(5)`. Intentionally
  **not** reused here (see Key Decisions): its allow-CDN-redirect + no-pin posture
  is a different threat model.

Scope note from the issue: `source_url` is operator-set via the **static main config
only** (`waf-common/src/config.rs:874-875`, read at `prx-waf/src/main.rs:402`), never
the admin API. So this is drift/hardening, not an internet-facing hole — the plan
stays proportional: no new config surface, cap is a compile-time const parameter.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Shared validated-fetch helper (extract from rules manager)](./phase-01-shared-validated-fetch-helper-extract-from-rules-manager.md) | Pending |
| 2 | [Wire geoip updater to hardened fetch](./phase-02-wire-geoip-updater-to-hardened-fetch.md) | Pending |
| 3 | [Acceptance tests and quality gates](./phase-03-acceptance-tests-and-quality-gates.md) | Pending |

## Key Decisions

- **Extract one shared SSRF client builder, refactor `fetch_remote_content` onto it.**
  New module `crates/waf-engine/src/validated_fetch.rs` exposes
  `build_validated_client(url, connect_timeout, total_timeout, user_agent) -> Result<reqwest::Client>`
  performing validate-with-ips + pin + `redirect::Policy::none()` + timeouts + UA.
  `fetch_remote_content` is rewritten to call it (keeping its own 10 MiB text cap).
  Rationale: two copies already drifted (that is this bug); a third copy for geoip
  would drift again. Refactoring the manager is in-scope precisely because DRY-ing the
  client is the fix. The manager's behavior is unchanged and covered by existing tests.
- **Redirects disabled (`Policy::none()`), not `limited(5)`.** IP pinning only pins the
  original host's resolved addresses; a followed redirect to a new host escapes the pin
  and reopens SSRF. `raw.githubusercontent.com` serves xdb bytes without redirecting, so
  disabling costs nothing operationally. `limited(5)` (relay intel) is for un-pinned CDN
  feeds — deliberately not reused. "Redirects bounded" (acceptance) is satisfied by a
  bound of zero; a 3xx surfaces as a non-success status → error.
- **Streaming cap, not `resp.bytes()`.** xdb files are large (full-memory policy ~20 MB
  per file, `config.rs:906`) and can grow. The download streams to `<file>.tmp` with a
  running byte cap and a `content_length` fast-reject, reusing the crate's proven
  `stream_to_tmp` technique. Promote `atomic_swap::stream_to_tmp` to `pub(crate)` and
  call it from geoip, or lift the same loop into `validated_fetch` — implementer's
  choice, but do **not** reintroduce an unbounded `resp.bytes()`.
- **Cap is a const parameter, not config.** `const MAX_XDB_RESPONSE_SIZE: u64 = 64 * 1024
  * 1024;` in `geoip_updater.rs`, passed to the streaming helper. 64 MiB gives headroom
  over the ~20 MB full xdb without allowing unbounded growth. No new config field (YAGNI).
- **Validate-then-rename flow preserved.** geoip must open the tmp file as an
  `ip2region::Searcher` *before* the atomic rename, so it cannot use `write_atomic`
  (which renames internally). It reuses only the stream-to-tmp step, then keeps its
  existing Searcher-validate + `rename` sequence (`geoip_updater.rs:195-206`).
- **Both HEAD and GET go through the validated client.** `check_update` builds the same
  validated client (one per cycle — same base host for both files, so validate/pin once
  and reuse for both HEAD requests). The old `build_client` is removed as an orphan.

## Cross-Plan Dependencies

- **GH-208 (soft ordering, same file):** GH-208 removes `UpdateResult.ipv4_updated`/
  `ipv6_updated` (`geoip_updater.rs:27-29`) and reshapes `download()`'s return. This plan
  edits *different regions* of the same file — `check_update` (67-105), `download_one`
  (168-211), `build_client` (284-289) — and does **not** add any new dependence on those
  bools. Either order lands; whichever is second rebases the untouched struct/region.
- **GH-203 (no conflict):** touches `geoip.rs` reload (a different file). This plan does
  not modify `geoip.rs`.
- **No overlap** with the GH-196 risk plan (`engine.rs`, `risk/*`) or GH-202
  (`checks/ddos/*`).

## File Ownership

- New: `crates/waf-engine/src/validated_fetch.rs`
- Modify: `crates/waf-engine/src/lib.rs` (add `pub mod validated_fetch;` after line 11),
  `crates/waf-engine/src/rules/manager.rs` (refactor `fetch_remote_content`),
  `crates/waf-engine/src/geoip_updater.rs` (client + download + HEAD + remove `build_client`),
  `crates/waf-engine/src/relay/intel/atomic_swap.rs` (only if promoting `stream_to_tmp` visibility).

## Acceptance Criteria (from issue)

- [ ] Download path uses the shared validated-fetch helper (SSRF validation + pinned IPs
      + disabled redirects + size cap + connect timeout + stable UA). — Phases 1, 2
- [ ] Redirects bounded, connect timeout set, UA consistent. — Phases 1, 2
- [ ] Test: oversized response is rejected. — Phase 3
- [ ] Test: private-range / SSRF `source_url` is rejected. — Phase 3
- [ ] Test: redirect is not silently followed (bounded). — Phase 3

## Validation

- `cargo test -p waf-engine geoip_updater` and `cargo test -p waf-engine validated_fetch` green.
- `cargo test -p waf-engine rules::manager` green (refactor is behavior-preserving).
- `cargo clippy -p waf-engine --all-targets` clean.
</content>
</invoke>
