# rustls 0.23 Dynamic Per-SNI Certificate Resolver for Production WAF

**Date:** 2026-05-22  
**Scope:** ResolvesServerCert trait integration for DB-backed TLS certificate selection  
**Context:** Pingora WAF + ~50 FQDN hosts, single-node, no cluster cert sync yet

---

## 1. Exact rustls 0.23 API Signatures

### ResolvesServerCert Trait
**Source:** [rustls::server::ResolvesServerCert docs](https://docs.rs/rustls/latest/rustls/server/trait.ResolvesServerCert.html)

```rust
trait ResolvesServerCert {
    fn resolve(
        &self,
        client_hello: ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>>;
    
    fn only_raw_public_keys(&self) -> bool { false }
}
```

- **resolve()** takes `ClientHello<'_>` (borrowed), returns `Option<Arc<CertifiedKey>>`.
- Returning `None` aborts the TLS handshake with a fatal alert.
- **Concurrent calls:** Yes, `resolve()` is called once per connection during handshake (multiple concurrent connections = multiple concurrent calls). NOT lock-free; implementations must handle thread-safe access to shared cert storage.

### ClientHello Available Fields
**Source:** [rustls::server::ClientHello docs](https://docs.rs/rustls/latest/rustls/server/struct.ClientHello.html)

```rust
impl<'a> ClientHello<'a> {
    pub fn server_name(&self) -> Option<&str>         // SNI hostname (None if no SNI sent)
    pub fn signature_schemes(&self) -> &[SignatureScheme]  // Offered sig schemes (RSA, ECDSA, EdDSA variants)
    pub fn alpn(&self) -> Option<impl Iterator<Item = &'a [u8]>>  // ALPN protocols
    pub fn cipher_suites(&self) -> &[CipherSuite]     // Offered ciphers (TLS 1.2/1.3)
}
```

**SNI null case:** `server_name()` returns `None` when TLS handshake omits SNI (rare in HTTP/2+, common in legacy clients). Resolver should either reject (`return None`) or fallback to a default cert. **Industry standard:** Most CDNs (Cloudflare, Akamai) reject; however, for WAF gateway you control, fallback to a catch-all cert is pragmatic.

### CertifiedKey Construction
**Source:** [rustls::sign::CertifiedKey docs](https://docs.rs/rustls/latest/rustls/sign/struct.CertifiedKey.html)

```rust
impl CertifiedKey {
    pub fn new(
        cert: Vec<CertificateDer<'static>>,
        key: Arc<dyn SigningKey>
    ) -> Self {
        // cert chain must be non-empty; first cert MUST be end-entity
    }
    
    pub fn from_der(
        cert_chain: impl IntoIterator<Item = impl AsRef<[u8]>>,
        private_key_der: &[u8],
        provider: &CryptoProvider
    ) -> Result<Self> {
        // Parses private key with provider's KeyProvider, verifies key-cert match
    }
    
    pub fn cert: Vec<CertificateDer<'static>>
    pub fn key: Arc<dyn SigningKey>
    pub fn ocsp: Option<Vec<u8>>  // Optional OCSP response (for stapling)
}
```

**PEM loading pattern:**
1. Load PEM certs via [rustls-pemfile](https://github.com/rustls/pemfile): `rustls_pemfile::certs(&mut reader)` → `Vec<CertificateDer>`.
2. Load PEM key via `rustls_pemfile::pkcs8_private_keys()` or `rsa_private_keys()`.
3. Convert key DER → `SigningKey` via `CryptoProvider::key_provider().load_private_key()`.
4. Call `CertifiedKey::new(cert_vec, Arc::new(signing_key))`.

**SigningKey trait:** Implementations are `Debug + Send + Sync`. Both `ring` and `aws-lc-rs` provide `any_supported_type()` factory that auto-detects RSA/ECDSA/EdDSA and returns the right `SigningKey` impl.
- **ring:** `rustls::crypto::ring::sign::any_supported_type(private_key_der)` → `Arc<dyn SigningKey>`
- **aws-lc-rs:** `rustls::crypto::aws_lc_rs::sign::any_supported_type(private_key_der)` → `Arc<dyn SigningKey>`

### ServerConfig Builder Chain
**Source:** [rustls::server::ServerConfig docs](https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html)

```rust
let config = ServerConfig::builder_with_protocol_versions(&[&TLS13])
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(your_resolver))  // Pass Arc<dyn ResolvesServerCert>
    .build();
```

Or with explicit CryptoProvider:
```rust
let config = ServerConfig::builder_with_provider(&provider)
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(your_resolver))
    .build();
```

---

## 2. Thread-Safety Semantics

### Concurrent resolve() Calls
- **Hot-path:** Each new TLS connection triggers one `resolve()` call during handshake.
- **Lock strategy:** For ~50 domains, a `parking_lot::RwLock<HashMap<String, Arc<CertifiedKey>>>` or `DashMap<String, Arc<CertifiedKey>>` (lock-free, concurrent readers).
- **Expected latency:** Sub-microsecond (< 100ns per lookup). DashMap wins; avoids contention even under high concurrency.

### Arc<CertifiedKey> Sharing
- **Safety:** Completely safe. Multiple connections can hold the same `Arc<CertifiedKey>` reference. `CertifiedKey` is immutable after construction.
- **SigningKey thread-safety:** `SigningKey` trait requires `Send + Sync`. Both ring and aws-lc-rs implementations are thread-safe for concurrent signature operations.
- **No cloning overhead:** `Arc::clone()` is atomic increment, not cryptographic material copy.

### Cache Invalidation During In-Flight Handshakes
**Scenario:** Connection A holds `Arc<CertifiedKey>` (old cert), replaceCertificate in DashMap, Connection B picks new `Arc<CertifiedKey>`. Safe?

**Answer:** Yes. Removing old `Arc` from map doesn't dealloc the cert while Connection A still holds a reference (ARC semantics). Connection A completes handshake with old cert; Connection B gets new cert. No corruption. This is the main virtue of `Arc<_>` over `&'static _`.

---

## 3. CryptoProvider Integration

### Provider Awareness in CertifiedKey Construction
**Source:** main.rs:294 already installs ring as default

```rust
rustls::crypto::ring::default_provider().install_default()
    .ok();  // Already done at startup
```

**Answer:** Once `CryptoProvider::install_default()` is called, `CertifiedKey::from_der()` and `SigningKey` factory methods use the installed provider automatically. You do NOT need to pass provider explicitly to constructors in the hot path.

However, when building resolver at startup, you CAN pass an explicit provider:
```rust
let provider = rustls::crypto::ring::default_provider();
let signing_key = provider.key_provider()
    .load_private_key(private_key_der)?;
```

**Decision:** Stick with auto-installed default (ring). Keep it simple—no feature-gating needed.

### SNI Null Fallback Strategy
**Recommendation:** Return `None` (reject) for SNI-less clients. Reason:
- HTTP/2+ all use SNI (enforced by spec).
- Legacy TLS 1.0 clients are rare in WAF context.
- Avoids fingerprint leakage via fallback cert.
- Forces clients to be explicit about which host they want.

If fallback is needed, keep a `default_cert: Arc<CertifiedKey>` in your resolver and return it when `client_hello.server_name().is_none()`.

---

## 4. Public Examples in the Wild

### rustls-acme (Production ACME Integration)
**Source:** [FlorianUekermann/rustls-acme](https://github.com/FlorianUekermann/rustls-acme)

Implements `ResolvesServerCertAcme` which wraps `ResolvesServerCert`. Pattern:
1. Maintains `Arc<DashMap<String, Arc<CertifiedKey>>>` (DNS name → cert).
2. In `resolve()`, extract SNI, lookup in map, return or request new cert from ACME server.
3. Caches cert + account state on disk via `DirCache` to avoid rate-limit exhaustion.

**tokio variant:** [n0-computer/tokio-rustls-acme](https://github.com/n0-computer/tokio-rustls-acme)

### Pingora Issue #594: SNI-Based Cert Bundling
**Source:** [cloudflare/pingora#594](https://github.com/cloudflare/pingora/issues/594)

Proposes exactly your use case: "multiple TLS certificates, choose by SNI." Accepted as a future enhancement; not yet in stable Pingora release.

**Workaround in your fork:** Patch `TlsSettings::build()` to accept a `cert_resolver: Arc<dyn ResolvesServerCert>` parameter and wire it into `ServerConfig::builder().with_cert_resolver()`.

### Cloudflare Pingora Examples
**Source:** [pingora/examples/server.rs](https://github.com/cloudflare/pingora/blob/main/pingora/examples/server.rs)

Shows static single-cert setup. No dynamic resolver examples in main repo (you're pioneering this for Pingora).

---

## 5. Performance Considerations

### Benchmark: Hash Lookup Latency
For a `DashMap<String, Arc<CertifiedKey>>` with 50 entries:
- **Expected latency:** ~100–500 ns (CPU cache hit, single shard lock).
- **Allocation cost:** Zero (Arc::clone is atomic, no copy).
- **Memory per CertifiedKey:**
  - RSA-2048 cert: ~1.2 KB
  - ECDSA-P256 cert: ~500 bytes
  - Private key (RSA-2048): ~1.6 KB (in-memory, DER)
  - Signing key arc: ~64 bytes (on 64-bit arch)
  - **Total per cert:** ~3–4 KB.
  - **50 certs:** ~150–200 KB resident (negligible).

### Optimization Tricks
- Pre-warm DashMap with all 50 certs at startup (parse + insert).
- Use `client_hello.server_name()` as-is for lookup key (exact match, no normalization needed; browsers send lowercase FQDN).
- Consider caching the last-resolved cert per connection thread-local if lookup is a bottleneck (unlikely at 50 domains).

---

## 6. Concrete Implementation Sketch

### Step 1: Add Resolver to TlsSettings

File: `/Users/admin/lab/mini-waf/vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs`

```rust
use std::sync::Arc;
use rustls::server::ResolvesServerCert;

pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_path: Option<String>,
    key_path: Option<String>,
    cert_resolver: Option<Arc<dyn ResolvesServerCert>>,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

impl TlsSettings {
    pub fn with_cert_resolver(mut self, resolver: Arc<dyn ResolvesServerCert>) -> Self {
        self.cert_resolver = Some(resolver);
        self
    }
    
    pub fn build(self) -> Acceptor {
        pingora_rustls::install_default_crypto_provider();
        
        let config = if let Some(resolver) = self.cert_resolver {
            // Dynamic resolver path
            ServerConfig::builder_with_protocol_versions(&[&TLS12, &TLS13])
                .with_no_client_auth()
                .with_cert_resolver(resolver)
                .build()
        } else {
            // Static cert path (existing)
            let Ok(Some((certs, key))) = load_certs_and_key_files(&self.cert_path?, &self.key_path?)
            else { panic!("Failed to load certs") };
            ServerConfig::builder_with_protocol_versions(&[&TLS12, &TLS13])
                .with_no_client_auth()
                .with_single_cert(certs, key)?
                .build()
        };
        // ... rest of setup
    }
}
```

### Step 2: Implement DbCertResolver

File: `crates/gateway/src/tls/db-cert-resolver.rs`

```rust
use dashmap::DashMap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use tracing::{debug, warn};

pub struct DbCertResolver {
    cache: Arc<DashMap<String, Arc<CertifiedKey>>>,
}

impl DbCertResolver {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
        }
    }
    
    /// Pre-load certificate for a domain (call at startup)
    pub fn add(&self, domain: String, certified_key: Arc<CertifiedKey>) {
        self.cache.insert(domain, certified_key);
    }
    
    /// Replace certificate (hot-reload safe, old Arc dropped when no longer held)
    pub fn update(&self, domain: String, certified_key: Arc<CertifiedKey>) {
        self.cache.insert(domain, certified_key);
    }
}

impl ResolvesServerCert for DbCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;  // Return None if no SNI
        
        self.cache.get(sni).map(|ref_multi| ref_multi.clone())
    }
}
```

### Step 3: Wire into Gateway

```rust
// In gateway startup
let resolver = Arc::new(DbCertResolver::new());
// Load all certs from DB
for domain in domains {
    let cert_key = load_from_db(&domain)?;
    resolver.add(domain, Arc::new(cert_key));
}

let mut tls_settings = TlsSettings::intermediate("", "")?;
tls_settings.with_cert_resolver(resolver);
let acceptor = tls_settings.build();
```

---

## Risks / Open Questions

| Risk | Severity | Mitigation |
|------|----------|-----------|
| SNI spoofing (client sends fake SNI) | Low | TLS is trust-on-first-use; enforced by cert chain validation downstream. Not resolver's concern. |
| Cert reload race during active handshake | Low | Arc semantics handle this. Old Arc persists until all refs dropped. |
| DashMap contention at high conn/s | Low | 50 domains = low collision rate. Monitor with metrics. |
| Provider not installed | High | Call `install_default_crypto_provider()` in main.rs BEFORE any TLS setup. Already done in your code. |
| PEM parsing errors | Medium | Catch `CertifiedKey::from_der()` errors during startup, panic or log fatal. Don't silence. |
| No OCSP stapling | Low | Out of scope per requirements. CertifiedKey.ocsp is optional. |

### Unresolved Questions
1. **Cluster cert sync:** When you move to multi-node (future), how do you sync cert updates across nodes? MCP broadcast? Shared database? Postpone until then.
2. **Cert hotload from file:** Do you want `inotify`-based file-watch to auto-reload certs? Or API-driven reload? Defer to phase 2.
3. **mTLS client certs:** Out of scope, but is this needed for upstream backends later? Document for roadmap.

---

## Recommendation

**Status:** Ready to implement.

1. Patch `TlsSettings` in Pingora fork to add `with_cert_resolver()`.
2. Implement `DbCertResolver` (lock-free DashMap, 30 lines).
3. Integrate into gateway startup (load all domains from AppConfig at init).
4. Test with local ~5 domain certs (use rcgen or LE staging).
5. Monitor `resolve()` latency in production tracing (expect < 1µs).

**Architecture fit:** Minimal friction, no breaking changes to Pingora API, plays well with ring provider already chosen.

---

## Source Citations

- [rustls::server::ResolvesServerCert](https://docs.rs/rustls/latest/rustls/server/trait.ResolvesServerCert.html)
- [rustls::server::ClientHello](https://docs.rs/rustls/latest/rustls/server/struct.ClientHello.html)
- [rustls::sign::CertifiedKey](https://docs.rs/rustls/latest/rustls/sign/struct.CertifiedKey.html)
- [rustls::server::ServerConfig](https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html)
- [rustls::sign::SigningKey](https://docs.rs/rustls/latest/rustls/sign/trait.SigningKey.html)
- [rustls-pemfile](https://github.com/rustls/pemfile)
- [FlorianUekermann/rustls-acme](https://github.com/FlorianUekermann/rustls-acme)
- [n0-computer/tokio-rustls-acme](https://github.com/n0-computer/tokio-rustls-acme)
- [cloudflare/pingora#594 — SNI-based cert resolver feature](https://github.com/cloudflare/pingora/issues/594)
- [pingora/examples/server.rs](https://github.com/cloudflare/pingora/blob/main/pingora/examples/server.rs)
