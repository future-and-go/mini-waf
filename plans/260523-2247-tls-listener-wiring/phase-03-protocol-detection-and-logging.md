---
phase: 3
title: "Protocol Detection and Logging"
status: pending
priority: P2
effort: "1h"
dependencies: [2]
---

# Phase 3: Protocol Detection and Logging

## Overview

Ensure `GatewayCtx.is_tls` is correctly set for TLS connections so downstream logic (X-Forwarded-Proto, request context) works. Verify the existing `Protocol` enum detection from phase-05 correctly differentiates H1-over-TLS vs h2-over-TLS. Update ALPN startup log to reflect actual protocol surface.

## Requirements

**Functional:**
- `GatewayCtx.is_tls` returns `true` for connections on the TLS listener
- `X-Forwarded-Proto: https` header set for TLS connections (existing filter, just needs `is_tls` to work)
- Phase-05 `Protocol::detect_from_session()` still returns correct protocol (H1 or H2) for TLS connections — TLS doesn't change the protocol enum, only `is_tls`
- Startup log clearly documents the full protocol surface: HTTP (port 80: H1 + h2c), HTTPS (port 443: H1 + H2 via ALPN), optionally H3/QUIC

**Non-functional:**
- No new allocations in the hot path — `is_tls` is a bool read from session digest

## Architecture

```
TLS connection on :443
  → Pingora terminates TLS, populates Session::digest().ssl_digest
  → proxy.rs request_filter():
      ctx.is_tls = session.digest().ssl_digest.is_some()  ← existing logic
      ctx.protocol = Protocol::detect_from_session(session)  ← H1 or H2
  → request_forwarded_proto_filter:
      if ctx.is_tls → X-Forwarded-Proto: https  ← existing filter
```

## Related Code Files

**Modify:**
- `crates/gateway/src/proxy.rs` — verify `is_tls` detection in `request_filter` (may already work, need to audit)
- `crates/prx-waf/src/main.rs` — update startup log block

**Read (context):**
- `crates/gateway/src/context.rs` — `GatewayCtx.is_tls` field
- `crates/gateway/src/protocol.rs` — `Protocol::detect_from_session()`
- `crates/gateway/src/filters/request_forwarded_proto_filter.rs` — uses `is_tls`
- `crates/gateway/src/ctx_builder/request_ctx_builder.rs` — builds `is_tls`

## Implementation Steps

1. Audit `ctx_builder/request_ctx_builder.rs` — find where `is_tls` is set. Verify it reads from `session.digest().ssl_digest.is_some()` (the Pingora-canonical way).

2. If `is_tls` detection is already correct (likely — FR-001 phase-01 fixed this), no code change needed. Just verify with a test.

3. Update the startup log in `main.rs` to produce a consolidated protocol surface summary:
   ```rust
   info!(
       "Protocol surface: HTTP({}) H1+h2c | HTTPS({}) H1+H2 ALPN{}",
       config.proxy.listen_addr,
       config.proxy.listen_addr_tls,
       if config.http3.enabled {
           format!(" | H3/QUIC({})", config.http3.listen_addr)
       } else {
           String::new()
       }
   );
   ```

4. Remove the old multi-line ALPN comment block (~lines 1400-1406) — replaced by the consolidated log.

5. Run `cargo check -p prx-waf` and `cargo check -p gateway`.

## Success Criteria

- [ ] `is_tls == true` for connections arriving on the TLS listener
- [ ] `X-Forwarded-Proto: https` header injected for TLS connections
- [ ] `Protocol::detect_from_session()` returns H1 or H2 (not affected by TLS)
- [ ] Startup log shows consolidated protocol surface
- [ ] `cargo check` passes for all modified crates

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| `is_tls` detection already broken | L | M | FR-001 phase-01 fixed this; verify with test in phase-04 |
| `ssl_digest` not populated for rustls backend | L | H | Pingora's rustls integration populates this — verified in vendor source |
