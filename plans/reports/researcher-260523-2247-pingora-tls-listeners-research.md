# Pingora TLS Listeners Research — TlsSettings & ALPN

## 1. add_tls_with_settings API

**Method signature:** `service.add_tls_with_settings(address, sni_callback, tls_settings)`

**Parameters:**
- `address`: Bind address (e.g., `"0.0.0.0:6148"`)
- `sni_callback`: Optional SNI matcher for multi-domain routing (`None` for single cert)
- `tls_settings`: `TlsSettings` object with configuration

**Example:**
```rust
proxy.add_tls_with_settings("0.0.0.0:443", None, tls_settings);
```

---

## 2. TlsSettings Construction & Configuration

**Three backend options** (compile-time selected):
- **BoringSSL/OpenSSL**: Dynamic cert callbacks via `TlsSettings::with_callbacks()`
- **Rustls**: `TlsSettings::intermediate(&cert_path, &key_path)`
- **S2N**: Similar to rustls

**Configuration methods:**
```rust
let mut tls_settings = TlsSettings::intermediate("cert.pem", "key.pem")?;
tls_settings.enable_h2();  // Enable HTTP/2 over TLS
tls_settings.set_max_proto_version(Some(TlsVersion::TLS1_2))?;
```

---

## 3. ALPN Negotiation (h2 + http/1.1)

Pingora **automatically advertises ALPN protocols** based on `enable_h2()` flag:
- When `enable_h2()` called: ALPN list = `["h2", "http/1.1"]`
- When NOT called: ALPN list = `["http/1.1"]`
- **Protocol precedence** determined by NextProtos order in config
- Server selects first matching protocol from client's ClientHello ALPN extension
- Rustls backend handles ALPN via underlying `rustls::ServerConfig`

**No manual ALPN configuration exposed** — determined by `enable_h2()` flag only.

---

## 4. Certificate Hot-Reload

**NOT natively supported by Pingora's listener layer.**

**Workarounds observed in production:**
1. **Dynamic cert callbacks** (BoringSSL only): `TlsSettings::with_callbacks(callback_fn)` invokes callback during TLS handshake to fetch cert
2. **External projects** (Aralez, Pingap): Implement hot-reload via:
   - Polling cert files for changes
   - ArcSwap atomic pointer replacement for zero-downtime cert swap
   - Admin API for runtime config updates

**Current limitation:** Rustls/S2N backends do NOT expose cert callback API — static certs only at listener init.

---

## 5. TlsSettings vs rustls::ServerConfig

| Aspect | TlsSettings | rustls::ServerConfig |
|--------|-----------|----------------------|
| **Scope** | Pingora listener wrapper | Raw TLS protocol config |
| **Abstraction level** | High-level (backend-agnostic) | Low-level (rustls-specific) |
| **Backend support** | BoringSSL, Rustls, S2N | Rustls only |
| **ALPN** | Auto-managed by enable_h2() | Manual via ServerConfig::alpn_protocols |
| **Certs** | Path-based or callback-based | Direct DER/PEM bytes |
| **Exposure** | TlsSettings internals NOT public | Full rustls API available |

**Key difference:** TlsSettings abstracts TLS backend, rustls::ServerConfig is the concrete implementation for Rustls-backed Pingora.

---

## Unresolved Questions

1. **BoringSSL callback API**: Does `DynamicCert` callback support reload without connection drop?
2. **SNI + Rustls**: Does `TlsSettings::intermediate_bundle()` support cert updates post-init?
3. **ALPN edge case**: If both h2 and http/1.1 advertised, does rustls correctly fallback to http/1.1 on h2-incompatible clients?

---

## Sources

- [Pingora Examples Server](https://github.com/cloudflare/pingora/blob/main/pingora/examples/server.rs)
- [Pingora Core Docs](https://docs.rs/pingora-core/)
- [Pingora Load Balancer Example](https://github.com/cloudflare/pingora/blob/main/pingora-proxy/examples/load_balancer.rs)
- [Issue #594: SNI-based Resolver](https://github.com/cloudflare/pingora/issues/594)
- [Pingora Rustls Integration](https://docs.rs/pingora-rustls/)
