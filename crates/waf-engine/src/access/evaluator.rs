//! Phase-0 access decision (filled by phase-04).

/// Outcome of evaluating an inbound request against the access lists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessDecision {
    /// No access-list match; continue to subsequent WAF phases.
    Continue,
    /// Whitelist hit with `full_bypass` mode for this tier — skip later phases.
    BypassAll,
    /// Hard deny (host gate miss or blacklist hit). 403 to client.
    Block { reason: BlockReason },
}

/// Why a request was blocked at Phase 0. `'static` so audit logging is alloc-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockReason {
    HostGate,
    IpBlacklist,
}

impl BlockReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostGate => "host_gate",
            Self::IpBlacklist => "ip_blacklist",
        }
    }
}
