//! Rate-limit key construction.
//!
//! Keys are namespaced by host so that limits applied to one virtual host
//! do not bleed into another sharing the same backend.

use std::net::IpAddr;

/// Identifier used to scope a rate-limit counter.
pub enum KeyKind<'a> {
    /// Per-IP key, scoped to a host.
    Ip {
        /// Host (virtual host) the request targeted.
        host: &'a str,
        /// Client IP address.
        ip: IpAddr,
    },
    /// Per-session key, scoped to a host.
    Session {
        /// Host (virtual host) the request targeted.
        host: &'a str,
        /// Opaque session identifier (cookie value, token id, …).
        session: &'a str,
    },
}

impl KeyKind<'_> {
    /// Render the key into the canonical string form used by the backend.
    pub fn render(&self) -> String {
        match self {
            Self::Ip { host, ip } => format!("ip:{host}:{ip}"),
            Self::Session { host, session } => format!("sess:{host}:{session}"),
        }
    }
}
