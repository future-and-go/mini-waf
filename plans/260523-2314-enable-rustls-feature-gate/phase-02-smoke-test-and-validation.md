---
phase: 2
title: "Smoke Test and Validation"
status: done
priority: P1
effort: "1h"
dependencies: [1]
---

# Phase 2: Smoke Test and Validation

## Overview

Validate TLS termination works end-to-end after enabling the rustls feature. Run the WAF server, connect with `curl -k https://localhost:443`, and verify the TLS handshake completes. Confirm `is_tls` detection, startup logs, and self-signed cert generation all function correctly with the real rustls backend.

## Requirements

**Functional:**
- `cargo run -- -c configs/default.toml` starts with both HTTP and HTTPS listeners
- `curl -k https://localhost:443` completes TLS handshake and returns a response
- Startup log shows: `Protocol surface: HTTP(0.0.0.0:80) H1+h2c | HTTPS(0.0.0.0:443) H1+H2 ALPN`
- Self-signed cert warning appears in logs
- Self-signed cert files created in data_dir/tls/

**Non-functional:**
- No panics during TLS handshake (noop `unimplemented!()` gone)
- TLS 1.2 + TLS 1.3 supported (rustls `intermediate` preset)

## Related Code Files

**Read (context):**
- `crates/prx-waf/src/main.rs` — startup flow, TLS wiring, ensure_self_signed_cert
- `configs/default.toml` — listen addresses

## Implementation Steps

1. Build the binary: `cargo build -p prx-waf`

2. Start the server (needs a valid config with database — may need to use Docker):
   ```bash
   cargo run -- -c configs/default.toml run
   ```

3. Check startup logs for:
   - `"TLS listener using self-signed certificate"` warning
   - `"Protocol surface: HTTP(...) H1+h2c | HTTPS(...) H1+H2 ALPN"` info

4. Test TLS handshake:
   ```bash
   curl -k -v https://localhost:443
   ```
   Expected: TLS handshake completes (not connection refused, not panic)

5. Test ALPN negotiation (H2):
   ```bash
   curl -k --http2 https://localhost:443
   ```

6. Verify self-signed cert files exist:
   ```bash
   ls -la <data_dir>/tls/self-signed-cert.pem
   ls -la <data_dir>/tls/self-signed-key.pem
   # Key file should be mode 0600 on Unix
   ```

7. Test idempotent cert reuse — restart server, confirm "Reusing existing self-signed TLS certificate" in logs.

8. If Docker available, run full stack validation:
   ```bash
   podman-compose down && podman-compose up -d --build
   curl -k https://localhost:16843
   ```

## Success Criteria

- [ ] Server starts without panics
- [ ] `curl -k https://localhost:443` returns a response (any status code — we just need TLS to work)
- [ ] Startup logs show both listeners and self-signed warning
- [ ] Self-signed key file has 0600 permissions
- [ ] H2-over-TLS works via `--http2`
- [ ] Server restart reuses existing cert (no regeneration)
- [ ] `cargo test --workspace` still passes after feature enablement

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Server requires DB to start | Medium | Low | Use Docker compose or stub config. TLS wiring is independent of DB |
| Port 443 requires root | Medium | Low | Change `listen_addr_tls` to unprivileged port (e.g. 8443) for testing |
| Self-signed cert rejected by curl | Low | Low | Use `curl -k` (insecure mode) |
