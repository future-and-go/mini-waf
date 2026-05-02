//! Cache decision gates. Each gate is a single-purpose `CacheGate` impl.
//! The resolver runs them in order; first non-`Continue` verdict wins.

mod method_gate;
mod tier_default_gate;
mod tier_gate;
mod upstream_cc_gate;

pub use method_gate::MethodGate;
pub use tier_default_gate::TierDefaultGate;
pub use tier_gate::TierGate;
pub use upstream_cc_gate::UpstreamCcGate;
