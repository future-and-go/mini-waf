//! Strategy-pattern policies driven by host configuration.
//!
//! Each policy is a config-driven branch (Strategy) extracted from filter
//! code so the policy itself can be unit-tested in isolation.

pub mod host_header_policy;

pub use host_header_policy::HostHeaderPolicy;
