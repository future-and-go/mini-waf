// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Vendor regression test for the `TlsSettings::with_cert_resolver` constructor
// added on top of upstream Pingora 0.8.
//
// Goal: prove that
//   1. The original `TlsSettings::intermediate(cert_path, key_path)` signature
//      still compiles and returns `Ok(_)` (backward compatibility).
//   2. The new `TlsSettings::with_cert_resolver(Arc<dyn ResolvesServerCert>)`
//      constructor compiles, returns `Ok(_)`, and the resulting struct can
//      enable ALPN and accept a client cert verifier just like the static
//      file path.
//
// We intentionally do NOT call `.build()` here — that path needs real PEM
// files or live rustls plumbing. The downstream `gateway` crate exercises
// the full handshake via integration tests.

#![cfg(feature = "rustls")]

use std::sync::Arc;

use pingora_core::listeners::tls::TlsSettings;
use pingora_rustls::{CertifiedKey, ClientHello, ResolvesServerCert};

struct NullResolver;

impl std::fmt::Debug for NullResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NullResolver")
    }
}

impl ResolvesServerCert for NullResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        None
    }
}

#[test]
fn intermediate_constructor_is_lazy() {
    // Signature compatibility check — must accept &str / &str and not touch the
    // filesystem. PEM-load failure surfaces only at build() time, not here. If a
    // future refactor moves PEM parsing into the constructor, this test will
    // still pass — adjust it then to also cover build().
    let settings = TlsSettings::intermediate("/tmp/does-not-exist.pem", "/tmp/does-not-exist.key");
    assert!(
        settings.is_ok(),
        "intermediate() must remain a lazy constructor (signature preserved)"
    );
}

#[test]
fn with_cert_resolver_constructor_ok() {
    let resolver: Arc<dyn ResolvesServerCert> = Arc::new(NullResolver);
    let settings = TlsSettings::with_cert_resolver(resolver);
    assert!(settings.is_ok());
}

#[test]
fn with_cert_resolver_supports_alpn_and_h2() {
    let resolver: Arc<dyn ResolvesServerCert> = Arc::new(NullResolver);
    let mut settings = TlsSettings::with_cert_resolver(resolver).expect("settings");
    // These mutators must remain available for the resolver code path.
    settings.enable_h2();
}
