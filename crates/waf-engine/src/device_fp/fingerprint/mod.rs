//! FR-010 fingerprint algorithms.
//!
//! Phase-02 ships only the trait + per-algorithm stubs. Real JA3 / JA4 /
//! Akamai HTTP-2 implementations land in phase-04.

pub mod fingerprint_trait;
pub mod h2_akamai;
pub mod ja3;
pub mod ja4;

pub use fingerprint_trait::FingerprintProvider;
pub use h2_akamai::H2AkamaiFingerprint;
pub use ja3::Ja3Fingerprint;
pub use ja4::Ja4Fingerprint;
