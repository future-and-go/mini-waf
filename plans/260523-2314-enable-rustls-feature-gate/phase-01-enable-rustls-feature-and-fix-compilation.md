---
phase: 1
title: "Enable rustls Feature and Fix Compilation"
status: done
priority: P1
effort: "1h"
dependencies: []
---

# Phase 1: Enable rustls Feature and Fix Compilation

## Overview

Enable the `rustls` feature on `pingora-core` and `pingora-proxy` in the workspace `Cargo.toml`. Fix any compilation errors caused by the feature gate activation. The noop stub (`noop_tls::Acceptor::tls_handshake` → `unimplemented!()`) is replaced by real rustls TLS termination.

## Requirements

**Functional:**
- `pingora-core` compiled with `rustls` feature → real `TlsSettings` from `listeners/tls/rustls/mod.rs`
- `pingora-proxy` compiled with `rustls` feature → forwards to `pingora-core/rustls` + `pingora-cache/rustls`
- `cargo check --workspace` passes with zero errors
- `cargo test --workspace` passes (existing tests unbroken)

**Non-functional:**
- No version conflicts between workspace `rustls 0.23.37` and vendored `pingora-rustls ^0.23.12`
- Compile time increase acceptable (one additional crate tree)

## Architecture

```
Before (noop):
  pingora-core (no features)
    → pub use protocols::tls::noop_tls as tls
    → TlsSettings::intermediate() → Ok(Self)  // noop
    → Acceptor::tls_handshake() → unimplemented!()  // PANIC

After (rustls):
  pingora-core (features = ["rustls"])
    → pub use pingora_rustls as tls
    → listeners::tls::rustls::TlsSettings  // real rustls ServerConfig
    → Acceptor::tls_handshake() → real TLS termination
```

## Related Code Files

**Modify:**
- `Cargo.toml` (workspace root, lines 171-172) — add `features = ["rustls"]` to both pingora deps

**Read (context):**
- `vendor/pingora/pingora-core/Cargo.toml:102-110` — feature definitions
- `vendor/pingora/pingora-core/src/lib.rs:115-122` — conditional `pub use` for tls module
- `vendor/pingora/pingora-core/src/listeners/mod.rs:85-87` — tls module import path
- `vendor/pingora/pingora-proxy/Cargo.toml:71` — `rustls` feature forwards to pingora-core
- `vendor/pingora/pingora-rustls/Cargo.toml` — rustls `^0.23.12` dependency

## Implementation Steps

1. Edit workspace `Cargo.toml` (lines 171-172):
   ```toml
   # Before:
   pingora-core = { path = "vendor/pingora/pingora-core" }
   pingora-proxy = { path = "vendor/pingora/pingora-proxy" }

   # After:
   pingora-core = { path = "vendor/pingora/pingora-core", features = ["rustls"] }
   pingora-proxy = { path = "vendor/pingora/pingora-proxy", features = ["rustls"] }
   ```

2. Run `cargo check --workspace` — expect compilation. If errors:
   - Check for duplicate `rustls` crate versions (`cargo tree -d | grep rustls`)
   - Check for missing `x509-parser` or `ouroboros` (pulled by `rustls` feature)
   - Check for API mismatches between noop stubs and real implementations

3. Run `cargo test --workspace` — all existing tests must still pass.

4. Run `cargo fmt --all` to ensure formatting.

## Success Criteria

- [ ] `Cargo.toml` has `features = ["rustls"]` on both `pingora-core` and `pingora-proxy`
- [ ] `cargo check --workspace` passes with zero errors/warnings
- [ ] `cargo test --workspace` passes with zero failures
- [ ] `cargo tree -d | grep rustls` shows no duplicate major versions
- [ ] `cargo fmt --all -- --check` clean

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| rustls version conflict (workspace 0.23.37 vs vendored ^0.23.12) | Low | High | Both are ^0.23 semver — confirmed compatible |
| pingora-cache rustls feature pulls unwanted deps | Low | Low | pingora-cache not directly used; transitively benign |
| API mismatch between noop stubs and real TlsSettings | Low | Medium | FR-040b code already matches real API signatures |
| Compile time regression | Medium | Low | One-time cost; CI caches mitigate |
| Prior revert (PR #96) concerns resurface | Low | High | Root causes (split-brain, HostEntry.tls_terminate) don't exist in FR-040b design — verified |
