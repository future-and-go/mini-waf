---
phase: 1
title: "Config and Self-Signed Fallback"
status: pending
priority: P1
effort: "2h"
dependencies: []
---

# Phase 1: Config and Self-Signed Fallback

## Overview

Add `tls_cert_pem` and `tls_key_pem` optional path fields to `ProxyConfig`. When both are set, phase-02 uses them to bind the TLS listener. When neither is set, auto-generate a self-signed cert via existing `SslManager::generate_self_signed()` and write it to a well-known data directory so the dev server can start with HTTPS out of the box.

## Requirements

**Functional:**
- `ProxyConfig` gains two new optional fields: `tls_cert_pem: Option<String>`, `tls_key_pem: Option<String>`
- Default config (`configs/default.toml`) keeps them commented out (no breaking change)
- When both paths are `None` at startup, generate self-signed cert for `localhost` and write to `{data_dir}/tls/self-signed-cert.pem` + `self-signed-key.pem`
- Log a clear warning when using self-signed: "TLS listener using self-signed certificate — not for production"
- When only one of cert/key is set, fail startup with a clear error message

**Non-functional:**
- Zero impact on existing deployments that don't set the new fields
- Self-signed cert generated once, reused on subsequent boots (check file exists first)

## Architecture

```
ProxyConfig
├── listen_addr: String          # existing, port 80
├── listen_addr_tls: String      # existing, port 443 (was dead config)
├── tls_cert_pem: Option<String> # NEW — path to cert PEM file
└── tls_key_pem: Option<String>  # NEW — path to key PEM file

Startup flow:
  config.proxy.tls_cert_pem?
  ├── Some(cert) + Some(key) → validate paths exist → pass to phase-02
  ├── None + None → generate self-signed → write to data_dir → pass paths to phase-02
  └── Some + None (or None + Some) → startup error
```

## Related Code Files

**Modify:**
- `crates/waf-common/src/config.rs` — add `tls_cert_pem`, `tls_key_pem` to `ProxyConfig`
- `crates/waf-common/tests/config_loader.rs` — update test TOML fixtures
- `crates/waf-common/tests/config_defaults.rs` — assert new defaults are `None`
- `configs/default.toml` — add commented-out `tls_cert_pem` / `tls_key_pem` entries

**Read (context):**
- `crates/gateway/src/ssl.rs` — reuse `SslManager::generate_self_signed()`

## Implementation Steps

1. Add fields to `ProxyConfig` struct (`config.rs:201-217`):
   ```rust
   /// Path to TLS certificate PEM file for the HTTPS listener.
   /// When both tls_cert_pem and tls_key_pem are None, a self-signed
   /// certificate is generated automatically (dev mode only).
   #[serde(default)]
   pub tls_cert_pem: Option<String>,
   /// Path to TLS private key PEM file.
   #[serde(default)]
   pub tls_key_pem: Option<String>,
   ```

2. Update `ProxyConfig::default()` (`config.rs:219-228`) — add `tls_cert_pem: None, tls_key_pem: None`.

3. Add a validation method to `ProxyConfig`:
   ```rust
   pub fn resolve_tls_paths(&self) -> anyhow::Result<Option<(String, String)>> {
       match (&self.tls_cert_pem, &self.tls_key_pem) {
           (Some(cert), Some(key)) => Ok(Some((cert.clone(), key.clone()))),
           (None, None) => Ok(None),  // caller handles self-signed fallback
           _ => anyhow::bail!(
               "Both tls_cert_pem and tls_key_pem must be set together"
           ),
       }
   }
   ```

4. Add self-signed cert generation helper in `main.rs` (near existing cert logic):
   ```rust
   fn ensure_self_signed_cert(data_dir: &Path) -> anyhow::Result<(String, String)> {
       let tls_dir = data_dir.join("tls");
       let cert_path = tls_dir.join("self-signed-cert.pem");
       let key_path = tls_dir.join("self-signed-key.pem");
       if cert_path.exists() && key_path.exists() {
           return Ok((cert_path.display().to_string(), key_path.display().to_string()));
       }
       std::fs::create_dir_all(&tls_dir)?;
       let (cert_pem, key_pem) = gateway::SslManager::generate_self_signed("localhost")?;
       std::fs::write(&cert_path, &cert_pem)?;
       std::fs::write(&key_path, &key_pem)?;
       tracing::warn!("Generated self-signed TLS certificate at {}", cert_path.display());
       Ok((cert_path.display().to_string(), key_path.display().to_string()))
   }
   ```

5. Update `configs/default.toml` — add commented entries after `listen_addr_tls`:
   ```toml
   # tls_cert_pem = "/etc/prx-waf/tls/cert.pem"
   # tls_key_pem  = "/etc/prx-waf/tls/key.pem"
   ```

6. Update existing config tests to include new fields in TOML fixtures.

7. Run `cargo check -p waf-common` to verify.

## Success Criteria

- [ ] `ProxyConfig` has `tls_cert_pem: Option<String>` and `tls_key_pem: Option<String>`
- [ ] `resolve_tls_paths()` returns error when only one field is set
- [ ] `resolve_tls_paths()` returns `None` when both are `None`
- [ ] Self-signed cert generation writes files and reuses existing on next boot
- [ ] `cargo check -p waf-common` passes with zero warnings
- [ ] Existing config tests pass unchanged

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Self-signed cert in production | M | H | Loud warning log + doc comment. Future: add `tls_self_signed_fallback` toggle |
| Data dir doesn't exist | L | M | `create_dir_all` handles this |
| Config deserialization breaks existing TOML | L | H | Fields are `Option` with `#[serde(default)]` — existing TOML without them deserializes to `None` |
