---
phase: 1
title: "Shared validated-fetch helper (extract from rules manager)"
status: completed
effort: "1.5h"
---

# Phase 1: Shared validated-fetch helper (extract from rules manager)

## Overview

Create one SSRF-safe reqwest client builder and route the existing rules-manager
fetch through it, so the geoip updater (Phase 2) can reuse the *same* hardened
posture instead of adding a third drifting copy. This phase is behavior-preserving
for the rules manager.

## Requirements

- Functional: a public helper builds a reqwest client that (a) rejects private /
  reserved / loopback / IMDS URLs before any connection, (b) pins the client to the
  IPs resolved at validation time, (c) disables redirects, (d) sets connect + total
  timeouts and a stable User-Agent.
- Non-functional: `fetch_remote_content` keeps identical observable behavior (same
  10 MiB text cap, same error surfaces); existing `rules::manager` tests stay green.

## Architecture

- New module `crates/waf-engine/src/validated_fetch.rs`, registered in `lib.rs`
  (add `pub mod validated_fetch;` after `pub mod geoip_updater;`, `lib.rs:11`).
- Public API:
  ```rust
  /// Build an SSRF-validated, IP-pinned, redirect-disabled reqwest client for `url`.
  ///
  /// Validates `url` against private/reserved ranges, pins the client to the
  /// addresses resolved at validation time (closing the DNS-rebinding TOCTOU gap),
  /// and disables redirects (a followed redirect escapes the pin). Callers issue
  /// the request against the same `url`.
  pub fn build_validated_client(
      url: &str,
      connect_timeout: Duration,
      total_timeout: Duration,
      user_agent: &str,
  ) -> anyhow::Result<reqwest::Client>;
  ```
  Body mirrors `manager.rs:465-489`: `validate_public_url_with_ips(url)` →
  `Client::builder().redirect(Policy::none()).timeout(total).connect_timeout(connect)
  .user_agent(user_agent)`; `if !resolved_addrs.is_empty() { resolve_to_addrs(host, &addrs) }`.
- The response-body size cap stays a *caller* concern (rules cap text at 10 MiB;
  geoip streams to a file with its own cap in Phase 2), so it is **not** baked into
  the client builder.

## Related Code Files

- Create: `crates/waf-engine/src/validated_fetch.rs`
- Modify: `crates/waf-engine/src/lib.rs` (module registration)
- Modify: `crates/waf-engine/src/rules/manager.rs` — rewrite `fetch_remote_content`
  (`460-523`) to call `build_validated_client(url, 10s, 30s, <rules UA>)` then keep
  its existing status check + `content_length` pre-check + `text()` + post-length
  check against `MAX_RULES_RESPONSE_SIZE` (`447`). Remove the now-duplicated inline
  builder block (`468-489`).

## Implementation Steps

1. Add `validated_fetch.rs` with `build_validated_client` + module doc; register in `lib.rs`.
2. Define a stable UA constant. Reuse the existing `mini-waf/<CARGO_PKG_VERSION>` form
   (cf. `relay/intel/http.rs:17`); a per-caller suffix (e.g. `rules`, `geoip`) is
   optional — keep it simple, one shared UA is acceptable.
3. Rewrite `fetch_remote_content` to delegate client construction to the helper;
   leave its cap/text logic untouched.
4. `cargo test -p waf-engine rules::manager` — green, unchanged behavior.

## Success Criteria

- [ ] `validated_fetch::build_validated_client` compiles and is unit-tested:
      private-range URL → `Err`; well-formed public URL → `Ok(client)`.
- [ ] `fetch_remote_content` no longer contains an inline `Client::builder()` —
      it calls the shared helper; its tests pass unchanged.
- [ ] No new inline reqwest client builder remains in `manager.rs`.

## Risk Assessment

- Likelihood Low / Impact Medium: refactoring `fetch_remote_content` could alter an
  error surface a test asserts on. Mitigation: keep status/cap/text logic verbatim;
  only the client-construction lines move. Run `rules::manager` tests before/after.
- `resolve_to_addrs` requires the host string from the validated `Url`; the helper
  returns only the client, so extract the host internally (as `manager.rs:481-484` does)
  before building.

## Rollback

Single new module + one localized function rewrite. Revert the `manager.rs` diff and
delete `validated_fetch.rs`; no data or contract migration.
</content>
