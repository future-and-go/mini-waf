---
phase: 2
title: "Listener Wiring in main.rs"
status: pending
priority: P1
effort: "2h"
dependencies: [1]
---

# Phase 2: Listener Wiring in main.rs

## Overview

Wire Pingora's `add_tls_with_settings()` call in `main.rs` to bind the HTTPS listener on `listen_addr_tls` (port 443). Uses `TlsSettings::intermediate()` with `enable_h2()` for HTTP/2 + HTTP/1.1 ALPN negotiation. The same `WafProxy` instance handles both plaintext and TLS traffic — no duplication of filter chains.

## Requirements

**Functional:**
- `proxy_service.add_tls_with_settings()` called with resolved cert/key paths
- ALPN advertises `h2, http/1.1` (via `TlsSettings::enable_h2()`)
- Same `WafProxy` serves both `:80` (plaintext) and `:443` (TLS)
- Self-signed fallback from phase-01 used when no explicit cert configured
- Startup fails fast with clear error if cert files don't exist or are invalid

**Non-functional:**
- No runtime overhead for plaintext listener (TLS only adds cost on `:443`)
- TLS 1.2 + TLS 1.3 supported (Pingora `intermediate` preset)

## Architecture

```
main.rs startup:
  1. Create WafProxy (existing)
  2. Create proxy_service (existing)
  3. proxy_service.add_tcp(listen_addr)           ← existing, port 80
  4. resolve_tls_paths() → Some(cert, key)        ← NEW
  5. TlsSettings::intermediate(cert, key)?        ← NEW
  6. tls_settings.enable_h2()                     ← NEW
  7. proxy_service.add_tls_with_settings(          ← NEW
       listen_addr_tls, None, tls_settings)
  8. server.add_service(proxy_service)            ← existing
```

**Data flow — same as plaintext but with TLS termination:**
```
Client ──TLS──► :443 ──► Pingora TLS termination ──► WafProxy::request_filter ──► upstream
Client ────────► :80  ──► WafProxy::request_filter ──► upstream
```

## Related Code Files

**Modify:**
- `crates/prx-waf/src/main.rs` — add TLS listener wiring after `add_tcp` call (~line 1396)

**Read (context):**
- `vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs` — `TlsSettings` API
- `vendor/pingora/pingora-core/src/listeners/mod.rs` — `add_tls_with_settings` signature

## Implementation Steps

1. Add import at top of `main.rs`:
   ```rust
   use pingora_core::listeners::tls::TlsSettings;
   ```

2. After existing `proxy_service.add_tcp()` call (~line 1396), add TLS listener wiring:
   ```rust
   // Resolve TLS cert paths: explicit config → self-signed fallback
   let tls_paths = match config.proxy.resolve_tls_paths()? {
       Some(paths) => paths,
       None => {
           // No explicit cert — generate self-signed for dev
           tracing::warn!(
               "No TLS certificate configured — generating self-signed for localhost"
           );
           ensure_self_signed_cert(&data_dir)?
       }
   };

   // Validate cert files exist before handing to Pingora
   // (Pingora panics on missing files inside TlsSettings::build)
   if !std::path::Path::new(&tls_paths.0).exists() {
       anyhow::bail!("TLS cert file not found: {}", tls_paths.0);
   }
   if !std::path::Path::new(&tls_paths.1).exists() {
       anyhow::bail!("TLS key file not found: {}", tls_paths.1);
   }

   let mut tls_settings = TlsSettings::intermediate(&tls_paths.0, &tls_paths.1)
       .context("Failed to create TLS settings")?;
   tls_settings.enable_h2();

   proxy_service.add_tls_with_settings(
       &config.proxy.listen_addr_tls,
       None,
       tls_settings,
   );
   ```

3. Update the startup log block (~line 1399-1406) to replace the comment-only ALPN note:
   ```rust
   info!("Proxy listening on {} (HTTP)", config.proxy.listen_addr);
   info!(
       "Proxy listening on {} (HTTPS, ALPN: h2 + http/1.1)",
       config.proxy.listen_addr_tls
   );
   ```

4. Run `cargo check -p prx-waf` to verify.

5. Test manually: `cargo run -- -c configs/default.toml` — should see both listeners in logs.

## Success Criteria

- [ ] `proxy_service.add_tls_with_settings()` called with cert/key paths
- [ ] `TlsSettings::enable_h2()` called (ALPN h2 + http/1.1)
- [ ] Startup log shows both HTTP and HTTPS listener addresses
- [ ] Startup fails with clear error if cert file path is invalid
- [ ] `cargo check -p prx-waf` passes with zero warnings
- [ ] `curl -k https://localhost:443` returns a response (manual test with self-signed)

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Pingora `TlsSettings::build()` panics on bad cert | H | H | Pre-validate file existence and readability before calling; Pingora's `intermediate()` returns `Result` |
| Port 443 already bound (another process) | M | M | Pingora startup error is clear; document in troubleshooting |
| `data_dir` variable not in scope | L | M | Check existing main.rs for data dir resolution; may need to derive from config or use a constant |

## Security Considerations

- Self-signed cert MUST log a warning — never silently serve self-signed in production
- Cert/key file permissions should be checked (readable by process user only) — deferred to hardening phase
- Private key file should not be world-readable — document in deployment guide
