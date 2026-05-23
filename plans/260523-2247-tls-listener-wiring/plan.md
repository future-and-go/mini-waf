---
title: "FR-040b TLS Listener Wiring (Port 443)"
description: "Wire the existing listen_addr_tls config field to a Pingora TLS listener using rustls. Adds cert_pem/key_pem fields to ProxyConfig, self-signed fallback, ALPN h2+h1.1, and is_tls detection."
status: pending
priority: P1
effort: 1d
branch: "feat/tls-listener-wiring"
tags: [gateway, tls, pingora, rustls, fr-040]
blockedBy: []
blocks: [260428-1010-fr-001-reverse-proxy-impl]
created: "2026-05-23"
createdBy: "ck:plan"
source: skill
---

# FR-040b TLS Listener Wiring (Port 443)

## Overview

The config defines `listen_addr_tls = "0.0.0.0:443"` but no code wires it to a Pingora TLS listener. FR-040 built the `SslManager` (ACME + manual cert upload) but never called `proxy_service.add_tls_with_settings()`. This plan closes that gap.

**Scope:** Add `tls_cert_pem` / `tls_key_pem` path fields to `[proxy]` config, call Pingora's `add_tls_with_settings()` with `enable_h2()`, auto-generate self-signed cert on first boot when no cert configured, ensure `is_tls` detection works in `GatewayCtx`.

**Out of scope:** SNI-based multi-cert, mTLS, cert hot-reload (requires Pingora listener restart), ACME integration into the listener (stays API-driven via SslManager).

## Phases

| Phase | Name | Status | Effort | ACs |
|-------|------|--------|--------|-----|
| 1 | [Config and Self-Signed Fallback](./phase-01-config-and-self-signed-fallback.md) | Pending | 2h | Config fields, fallback cert |
| 2 | [Listener Wiring in main.rs](./phase-02-listener-wiring-in-main-rs.md) | Pending | 2h | add_tls_with_settings, ALPN |
| 3 | [Protocol Detection and Logging](./phase-03-protocol-detection-and-logging.md) | Pending | 1h | is_tls, startup logs |
| 4 | [Tests](./phase-04-tests.md) | Pending | 2h | Unit + integration |

Phase deps: 1 → 2 → 3. Phase 4 runs after 3.

## Key Design Decisions

1. **File-based cert paths** (not PEM inline in TOML) — matches Http3Config pattern, simplifies rotation.
2. **Self-signed fallback** — `SslManager::generate_self_signed()` already exists; reuse it so `cargo run` works without manual cert setup.
3. **Same proxy service, two listeners** — Pingora supports multiple listeners on one `HttpProxy` service. One `add_tcp` (port 80) + one `add_tls_with_settings` (port 443) = same `WafProxy` filter chain for both.
4. **No config breaking change** — `tls_cert_pem` / `tls_key_pem` are `Option<String>`, defaulting to `None`. Existing configs work unchanged (port 443 not bound unless cert paths provided or self-signed fallback enabled).

## Dependencies

- FR-001 phase-06 tests AC-23 (`fr001_tls_termination`) — this plan enables that test.
- FR-001 phase-05 `Protocol` enum — `is_tls` detection relies on `Session::digest()`.

## Unresolved Questions

1. **Should self-signed fallback be opt-in?** Currently planned as auto-generate when no cert configured. Could add `tls_self_signed_fallback = true` toggle. Recommend: auto for dev, warn loudly.
