---
phase: 4
title: "Tests"
status: pending
priority: P1
effort: "2h"
dependencies: [3]
---

# Phase 4: Tests

## Overview

Write unit and integration tests to verify the TLS listener works end-to-end. Unit tests cover config validation (`resolve_tls_paths`). Integration tests verify HTTPS connectivity, ALPN negotiation, `is_tls` detection, and `X-Forwarded-Proto: https`.

## Requirements

**Functional:**
- Config validation unit tests in `waf-common`
- Self-signed cert generation unit test (already exists in `ssl.rs`, verify sufficient)
- Integration test: HTTPS client connects, gets response, verifies TLS
- Integration test: H2-over-TLS via ALPN negotiation
- Integration test: `X-Forwarded-Proto: https` header reaches upstream

**Non-functional:**
- Tests don't require external cert files — generate self-signed in test setup
- Tests bind to `127.0.0.1:0` (random port) — no port conflicts in CI

## Related Code Files

**Create:**
- `crates/waf-common/tests/config_tls_validation.rs` — `resolve_tls_paths` tests

**Modify:**
- `crates/waf-common/tests/config_defaults.rs` — add assertions for new fields

**Read (context):**
- `crates/gateway/src/ssl.rs:298-307` — `generate_self_signed()` test already exists
- FR-001 phase-06 plan — `fr001_tls_termination` test spec (AC-23)

## Implementation Steps

1. **Config unit tests** (`config_tls_validation.rs`):
   ```rust
   #[test]
   fn resolve_tls_paths_both_set() {
       let config = ProxyConfig {
           tls_cert_pem: Some("/path/cert.pem".into()),
           tls_key_pem: Some("/path/key.pem".into()),
           ..Default::default()
       };
       let result = config.resolve_tls_paths().unwrap();
       assert!(result.is_some());
   }

   #[test]
   fn resolve_tls_paths_both_none() {
       let config = ProxyConfig::default();
       let result = config.resolve_tls_paths().unwrap();
       assert!(result.is_none());
   }

   #[test]
   fn resolve_tls_paths_partial_fails() {
       let config = ProxyConfig {
           tls_cert_pem: Some("/path/cert.pem".into()),
           tls_key_pem: None,
           ..Default::default()
       };
       assert!(config.resolve_tls_paths().is_err());
   }
   ```

2. **Config defaults test** — assert `tls_cert_pem` and `tls_key_pem` default to `None`.

3. **TOML deserialization test** — verify existing TOML (without new fields) still parses correctly.

4. **Integration test** (deferred to FR-001 phase-06 `fr001_tls_termination` unless fast-tracked):
   - Generate self-signed cert in test setup via `SslManager::generate_self_signed()`
   - Write to temp dir
   - Start WafProxy with `add_tls_with_settings` on `127.0.0.1:0`
   - Connect via `reqwest::Client` with `danger_accept_invalid_certs(true)`
   - Assert response received
   - Assert `X-Forwarded-Proto: https` in upstream echo

5. Run `cargo test -p waf-common` and full workspace `cargo test`.

## Success Criteria

- [ ] `resolve_tls_paths` unit tests pass (both/none/partial)
- [ ] Config defaults assert `None` for new fields
- [ ] Existing TOML fixtures still deserialize correctly
- [ ] `cargo test --workspace` passes with zero failures
- [ ] Integration test spec documented for FR-001 phase-06 AC-23

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Full integration test requires WafEngine test seam | M | M | Defer full e2e to FR-001 phase-06; unit tests cover config + cert gen here |
| Self-signed cert rejected by test client | L | L | Use `danger_accept_invalid_certs(true)` in reqwest |
| Port collision in CI | L | L | Bind to `127.0.0.1:0` — OS assigns free port |
