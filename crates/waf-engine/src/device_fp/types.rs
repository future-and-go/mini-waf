//! FR-010 phase-02 — shared value types for the device-fingerprinting pipeline.
//!
//! These types are deliberately small, owned, and `Clone` so providers and
//! the identity store can pass them across `Send` boundaries without lifetime
//! gymnastics. Real population happens in phases 03-06.

use std::cell::OnceCell;
use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::device_fp::capture::ConnCtx;
use crate::device_fp::signal::Signal;

/// Concrete computed fingerprint produced by a [`crate::device_fp::FingerprintProvider`].
///
/// Stored as the canonical text representation (e.g. `"771,4865-..."` for
/// JA3 raw, or its MD5/SHA-256 hash). Providers decide their own encoding;
/// the assembler only concatenates them into [`FpKey`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FingerprintValue(pub String);

impl FingerprintValue {
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Composite identity key — the union of every enabled fingerprint algorithm
/// for a single connection. Used as the primary key in
/// [`crate::device_fp::IdentityStore`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FpKey {
    /// JA3 (or MD5(JA3)) when TLS capture enabled.
    pub ja3: Option<FingerprintValue>,
    /// JA4 hash when enabled.
    pub ja4: Option<FingerprintValue>,
    /// Akamai HTTP/2 fingerprint when h2 capture enabled.
    pub h2_akamai: Option<FingerprintValue>,
}

impl FpKey {
    /// True if no fingerprint algorithm produced a value — caller should
    /// skip identity-store interaction (nothing to key on).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ja3.is_none() && self.ja4.is_none() && self.h2_akamai.is_none()
    }
}

/// Per-request derivation cache: parsed UA, normalized fields, etc.
/// Populated lazily by the first signal provider that needs it.
#[derive(Debug, Default, Clone)]
pub struct DeviceDerived {
    pub ua_entropy_x100: Option<u16>,
    pub ua_normalized: Option<String>,
}

/// Per-request input handed to every [`crate::device_fp::SignalProvider`].
///
/// Borrows the inbound `peer_ip`, UA string, and the connection's
/// [`ConnCtx`] (which holds raw TLS/h2 capture). `derived` is a `OnceCell`
/// so the first provider that needs entropy populates it; later providers
/// reuse without recomputation. Mirrors `relay::signal::RelayCtx`.
pub struct DeviceCtx<'a> {
    pub peer_ip: IpAddr,
    pub user_agent: &'a str,
    pub conn: &'a ConnCtx,
    pub key: &'a FpKey,
    derived: OnceCell<DeviceDerived>,
}

impl<'a> DeviceCtx<'a> {
    #[must_use]
    pub const fn new(peer_ip: IpAddr, user_agent: &'a str, conn: &'a ConnCtx, key: &'a FpKey) -> Self {
        Self {
            peer_ip,
            user_agent,
            conn,
            key,
            derived: OnceCell::new(),
        }
    }

    /// Fill the derivation cache once. Subsequent calls are no-ops.
    pub fn set_derived(&self, derived: DeviceDerived) {
        let _ = self.derived.set(derived);
    }

    #[must_use]
    pub fn derived(&self) -> Option<&DeviceDerived> {
        self.derived.get()
    }
}

/// Result of an [`crate::device_fp::IdentityStore::observe`] call —
/// what the store knows about this fingerprint after recording the new
/// observation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observation {
    pub distinct_ips_in_window: u16,
    pub distinct_uas_in_window: u16,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
}

/// Persistent record of a fingerprint identity. Returned by
/// [`crate::device_fp::IdentityStore::lookup`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub key: FpKey,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
    pub distinct_ips: u16,
    pub distinct_uas: u16,
}

/// Resolved per-request device identity emitted by
/// [`crate::device_fp::DeviceFpDetector::evaluate`].
#[derive(Clone, Debug, Default)]
pub struct DeviceIdentity {
    pub key: Arc<FpKey>,
    pub signals: Vec<Signal>,
}
