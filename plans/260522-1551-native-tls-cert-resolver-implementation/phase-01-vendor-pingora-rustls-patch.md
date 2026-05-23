---
phase: 1
title: "Vendor pingora rustls patch — TlsSettings::with_cert_resolver"
status: completed
priority: P1
effort: "1d"
dependencies: []
completed_at: 2026-05-22
verification:
  cargo_check: "1m18s green"
  cargo_test: "3/3 pass — tls_settings_with_resolver"
  code_review: "APPROVED-with-followup → M1/M2 applied + re-verified"
  loc_delta: "~59 net (under 100 budget)"
---

# Phase 01: Vendor pingora rustls patch

## Overview

Patch vendored Cloudflare Pingora 0.8 fork tại `vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs` thêm constructor `TlsSettings::with_cert_resolver(Arc<dyn ResolvesServerCert>) -> Result<Self>` để bypass static file loading, dùng dynamic cert resolver. Re-export `ResolvesServerCert` + `CertifiedKey` qua `pingora-rustls`. Phase này KHÔNG đụng `crates/`, chỉ vendor + 1 vendor unit test.

## Requirements

### Functional
- `TlsSettings::with_cert_resolver(resolver)` constructor mới
- `TlsSettings::intermediate(cert_path, key_path)` constructor cũ giữ nguyên (backward-compat)
- `build()` branch theo `CertSource` enum: static files vs resolver
- `pingora-rustls` re-export `ResolvesServerCert` + `CertifiedKey` để downstream crates import

### Non-functional
- LOC delta ≤ 100 trong vendor/
- Single commit (không file `.patch` riêng)
- Vendor `cargo test -p pingora-core` xanh
- Không đụng handshake path (`server.rs`) — resolver fires transparently qua rustls internals

## Architecture

**IMPLEMENTATION REFERENCE:** Use Option A from `research/researcher-03-pingora-vendor-patch.md §2` (enum-based `CertSource`). Do NOT follow the alternative sketch in `researcher-01 §6 Step 1` — that sketch changes `intermediate()` signature (`cert_path: Option<String>`) which would break every existing caller. The phase signature below is binding.

```
TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_source: CertSource,                       // CHANGED: replaces cert_path/key_path
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

enum CertSource {                                    // NEW
    StaticFiles { cert_path: String, key_path: String },
    Resolver(Arc<dyn ResolvesServerCert>),
}

impl TlsSettings {
    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self>;   // unchanged signature
    pub fn with_cert_resolver(resolver: Arc<dyn ResolvesServerCert>) -> Result<Self>;  // NEW
}

impl TlsSettings {
    pub fn build(self) -> Acceptor {
        let builder = ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13]);
        let builder = if let Some(v) = self.client_cert_verifier { builder.with_client_cert_verifier(v) }
                      else { builder.with_no_client_auth() };
        let mut config = match self.cert_source {
            CertSource::StaticFiles { cert_path, key_path } => {
                let (certs, key) = load_certs_and_key_files(&cert_path, &key_path)? // unchanged path
                builder.with_single_cert(certs, key).explain_err(...)?
            }
            CertSource::Resolver(resolver) => {
                builder.with_cert_resolver(resolver)
            }
        };
        if let Some(alpn) = self.alpn_protocols { config.alpn_protocols = alpn; }
        Acceptor { acceptor: RusTlsAcceptor::from(Arc::new(config)), callbacks: None }
    }
}
```

`pingora-rustls/src/lib.rs` thêm 1 dòng:

```rust
pub use rustls::{server::ResolvesServerCert, sign::CertifiedKey};
```

## Related Code Files

### Modify
- `vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs` — struct change + new constructor + build() branch
- `vendor/pingora/pingora-rustls/src/lib.rs` — re-export `ResolvesServerCert`, `CertifiedKey`

### Create
- `vendor/pingora/pingora-core/tests/tls_settings_with_resolver.rs` — vendor unit test (resolver path build OK, static path build OK)

### Reference (no edit)
- `vendor/pingora/pingora-core/src/protocols/tls/server.rs` — verify `handshake()` (not `handshake_with_callback`) là path resolver dùng

## Implementation Steps

1. Read full `vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs` để confirm hiện trạng struct + build() path.
2. Refactor `TlsSettings` struct: `cert_path: String, key_path: String` → `cert_source: CertSource`.
3. Update `intermediate()` constructor giữ signature cũ nhưng populate `CertSource::StaticFiles { cert_path, key_path }`.
4. Add `with_cert_resolver()` constructor: validate resolver non-null, populate `CertSource::Resolver(resolver)`.
5. Refactor `build()` body: branch theo `cert_source`. Giữ ALPN + acceptor wrap logic.
6. Re-export trong `pingora-rustls/src/lib.rs`.
7. Add vendor unit test `tls_settings_with_resolver.rs` build cả 2 path không panic.
8. Run `cargo test -p pingora-core` trong vendor workspace.
9. Verify downstream `gateway` crate compile (impl `ResolvesServerCert` chưa có, chỉ check imports resolve).

## Success Criteria

- [ ] `vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs` có constructor `with_cert_resolver`
- [ ] `pingora-rustls` re-export `ResolvesServerCert` + `CertifiedKey`
- [ ] Vendor unit test `tls_settings_with_resolver.rs` build OK (static + resolver path)
- [ ] `cargo test -p pingora-core` xanh trong vendor workspace
- [ ] `cargo check -p gateway` xanh (downstream import từ pingora-rustls work)
- [ ] Backward-compat: `TlsSettings::intermediate(cert_path, key_path)` cũ vẫn work, no signature change
- [ ] LOC delta vendor/ ≤ 100

## Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| Vendor patch trôi khi sync upstream pingora | Med | Single commit clean rebase; vendor test guard CI khi diff vendor/ |
| Type visibility chain pingora-rustls re-export bị block | Low | Researcher C đã verify exposure pattern; test downstream `cargo check -p gateway` |
| Refactor làm hỏng `intermediate()` backward-compat | Med | Unit test cover cả 2 path; signature `intermediate(&str, &str) -> Result<Self>` giữ nguyên |
| ServerConfig builder fluent chain change giữa rustls 0.23 minor versions | Low | Pin `rustls = "0.23"` ở vendor Cargo.toml; CI catches |
| `build()` panic vẫn còn (line 71 `.unwrap()` cũ) | Low | Phase này KHÔNG fix `.unwrap()` panic (Iron Rule 1 violation) — track follow-up issue. Phase 01 chỉ refactor struct. |

## Verification gates

- `cargo test -p pingora-core` (vendor workspace) — xanh
- `cargo check -p gateway` — xanh (workspace root)
- Manual `git diff vendor/` — LOC delta ≤ 100, không thay đổi handshake.rs / server.rs

## References

- Research report: [research/researcher-03-pingora-vendor-patch.md](./research/researcher-03-pingora-vendor-patch.md)
- Research report: [research/researcher-01-rustls-resolver-api.md](./research/researcher-01-rustls-resolver-api.md) — API signatures
- Upstream similar PR (dormant): cloudflare/pingora #632
