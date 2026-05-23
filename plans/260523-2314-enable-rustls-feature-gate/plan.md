---
title: "FR-040c Enable rustls Feature Gate for Native TLS"
description: "Enable the rustls feature on vendored pingora-core/pingora-proxy so TlsSettings actually terminates TLS instead of hitting noop_tls::Acceptor::unimplemented!(). Completes FR-040b wiring."
status: done
priority: P1
effort: 2h
branch: "feat/tls-listener-wiring"
tags: [gateway, tls, pingora, rustls, fr-040]
blockedBy: []
blocks: [260428-1010-fr-001-reverse-proxy-impl]
created: "2026-05-23"
createdBy: "ck:plan"
source: skill
---

# FR-040c Enable rustls Feature Gate for Native TLS

## Overview

FR-040b wired `add_tls_with_settings()` but `pingora-core` compiles without `any_tls`, so `TlsSettings` resolves to `noop_tls::listeners::TlsSettings` — a stub whose `Acceptor::tls_handshake` calls `unimplemented!()` and **panics on every TLS connection**. This plan enables `features = ["rustls"]` on both `pingora-core` and `pingora-proxy`.

### Why this was reverted before (PR #96, commit efc90a1)

The previous attempt (PR #90) was reverted because:
1. **Split-brain config** — cert paths were in TOML `[[hosts]]` entries, conflicting with DB-managed hosts (admin UI showed empty)
2. **SslManager bypass** — PR #90 skipped the existing ACME/SslManager infrastructure
3. **Per-host cert in TOML** — required `HostEntry.tls_terminate` field, creating dual source of truth

**FR-040b avoids all three problems:**
- Cert paths are global `[proxy]` fields, not per-host — no split-brain
- Self-signed fallback uses `SslManager::generate_self_signed()` — reuses existing infra
- No `HostEntry` TLS fields added — DB hosts unaffected
- Single cert for the listener (not per-host SNI) — matches current architecture

## CRITICAL: Runtime Panic Without This Fix

**FR-040b MUST NOT ship without this plan completed.** Without the `rustls` feature gate, port 443 binds successfully but every incoming TLS handshake hits `noop_tls::Acceptor::tls_handshake()` → `unimplemented!()` → **instant panic**. This is not a silent failure — it crashes the worker thread.

Evidence: `vendor/pingora/pingora-core/src/protocols/tls/noop_tls/mod.rs:96`
```rust
pub async fn tls_handshake<S: AsyncRead + AsyncWrite>(&self, _: S) -> Result<SslStream<S>> {
    unimplemented!("No tls feature was specified")
}
```

## Phases

| Phase | Name | Status | Effort |
|-------|------|--------|--------|
| 1 | [Enable rustls Feature and Fix Compilation](./phase-01-enable-rustls-feature-and-fix-compilation.md) | Pending | 1h |
| 2 | [Smoke Test and Validation](./phase-02-smoke-test-and-validation.md) | Pending | 1h |

Phase deps: 1 → 2.

## Key Design Decisions

1. **Enable on both pingora-core AND pingora-proxy** — `pingora-proxy` has its own `rustls` feature that forwards to `pingora-core/rustls` + `pingora-cache/rustls`. Must enable at proxy level too.
2. **No pingora-cache concern** — `pingora-cache` is not a direct dependency of this workspace, but `pingora-proxy` pulls it transitively. Its `rustls` feature is benign (TLS-aware cache key helpers).
3. **Version compatibility confirmed** — workspace uses `rustls 0.23.37`, vendored `pingora-rustls` wants `^0.23.12` — compatible.

## Dependencies

- FR-040b (completed, uncommitted) — provides the wiring code this plan activates
- Issue #95 — tracks full SslManager/ACME runtime wiring (out of scope here)

## Unresolved Questions

None — research is complete.
