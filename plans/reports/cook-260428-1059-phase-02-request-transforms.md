# Phase 02 — Request-side Transforms — Cook Report

**Date:** 2026-04-28
**Mode:** /cook --auto
**Plan:** plans/260428-1010-fr-001-reverse-proxy-impl/phase-02-request-transforms.md
**Status:** DONE

## Files created
- `crates/gateway/src/policies/mod.rs`
- `crates/gateway/src/policies/host_header_policy.rs` — Strategy enum (`Preserve | Rewrite(String)`)
- `crates/gateway/src/filters/mod.rs`
- `crates/gateway/src/filters/request_xff_filter.rs` — append-or-set XFF
- `crates/gateway/src/filters/request_real_ip_filter.rs` — overwrite X-Real-IP
- `crates/gateway/src/filters/request_forwarded_proto_filter.rs` — http/https from `is_tls`
- `crates/gateway/src/filters/request_forwarded_host_filter.rs` — copy original Host
- `crates/gateway/src/filters/request_host_policy_filter.rs` — adapter to HostHeaderPolicy
- `crates/gateway/src/filters/request_hop_by_hop_filter.rs` — RFC 7230 + Connection-tokens, WS-aware

## Files modified
- `crates/waf-common/src/types.rs` — `HostConfig.preserve_host: bool` (default true, `#[serde(default)]`)
- `crates/gateway/src/lib.rs` — pub mod filters/policies
- `crates/gateway/src/proxy.rs`:
  - `WafProxy::new` calls `build_request_chain()` registering 6 filters in the order `xff → real-ip → fwd-proto → fwd-host → host-policy → hop-by-hop`
  - `upstream_request_filter` derives `peer_ip` from `session.client_addr()` (raw TCP peer) instead of `req_ctx.client_ip` — needed for AC-14 multi-hop append correctness when trust_proxy_headers is on

## ACs closed
- AC-12 XFF inject — `unit_xff sets_when_absent`
- AC-13 X-Forwarded-Proto/Host/X-Real-IP — proto+host+real-ip unit tests
- AC-14 XFF append — `appends_when_present`, `appends_multi_hop_chain`
- AC-20 hop-by-hop — `strips_standard_hop_headers`, `strips_connection_named_tokens`, `preserves_upgrade_for_websocket`, `ws_strips_other_connection_tokens_but_keeps_upgrade`
- AC-25 Host policy — `preserve_leaves_host_untouched`, `rewrite_replaces_host`, `from_host_config_*`

End-to-end (chained-WAF, real Pingora) coverage deferred to phase 06 per plan.

## Verification
- `cargo +nightly check -p gateway -p waf-common` — clean
- `cargo +nightly clippy -p gateway -p waf-common --all-targets -- -D warnings` — clean
- `cargo +nightly test --workspace` — 373 passed / 0 failed; 16 new tests in gateway lib

## Design notes
- HostHeaderPolicy kept as a pure strategy (no FilterCtx coupling) — adapter filter wraps it. Keeps strategy unit-testable in isolation and allows phase 03 to reuse the same shape for ServerHeaderPolicy.
- HopByHop captures `Connection`-token list BEFORE removing the header, then strips per-token, then strips standard list. WS branch detected by `Upgrade: websocket` (case-insensitive); on WS, normalises `Connection` to `upgrade` so stale tokens don't leak.
- ForwardedHost runs BEFORE HostPolicy (chain order) — ensures original `Host` is captured before rewrite mode may overwrite it.
- XFF filter uses **resolved** `client_ip` for set-case (anti-spoof: builder only honours XFF from trusted peers), and **raw peer_ip** for append-case (per-hop chain semantics).
- proxy.rs `peer_ip` fix: previous code passed `req_ctx.client_ip` (resolved) — wrong for AC-14 when trust_proxy_headers is on. Now from `session.client_addr()`.

## Risks closed
- `preserve_host` deserialization: `#[serde(default = "default_preserve_host")]` ensures missing-field configs deserialize to true.
- WS Upgrade preservation: explicit branch in hop-by-hop filter, dedicated unit test.
- Chain ordering: encoded in `build_request_chain`; comment documents the rationale.

## Unresolved questions
- None for phase 02. WS frame-level inspection (plan §Unresolved Q1) remains a product decision; current WS handling is handshake-only as documented.
- E2E AC validation (curl source IP, chained-WAF) deferred to phase 06 test harness as planned.
