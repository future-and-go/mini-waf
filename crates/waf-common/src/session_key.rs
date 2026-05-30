//! Session-key types shared across crates.
//!
//! `SessionKey` and `SessionIdent` live here (waf-common) so that
//! `TxEventToken` can reference `SessionKey` without pulling in
//! waf-engine. The extraction logic (`extract_session_key`) stays in
//! waf-engine because it reads `RequestCtx` fields.

use std::net::IpAddr;

use crate::types::FpKey;

/// Identity tied to a tracked actor.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SessionIdent {
    Cookie(String),
    /// Fingerprint scoped by peer IP to prevent CDN cohort poisoning.
    Fingerprint {
        fp: FpKey,
        ip: IpAddr,
    },
}

/// Composite key the recorder buckets events under. Host scoping prevents
/// cross-tenant collision when the same cookie name is reused.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionKey {
    pub host: String,
    pub ident: SessionIdent,
}
