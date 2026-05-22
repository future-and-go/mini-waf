//! TLS / ACME subsystem.
//!
//! - [`SslManager`] owns the in-memory cert cache and ACME plumbing.
//! - [`DbCertResolver`] adapts the cache to the rustls `ResolvesServerCert`
//!   trait so the Pingora TLS listener can pick a certificate per-SNI.
//! - [`build_certified_key`] is the PEM → `CertifiedKey` helper used by both
//!   the cache hydration and the (future) ACME finalize path.

pub mod build_certified_key;
pub mod manager;
pub mod resolver;

pub use manager::{ChallengeStore, SslManager};
pub use resolver::DbCertResolver;
