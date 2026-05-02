//! Cache decision gates. Each gate is a single-purpose `CacheGate` impl.
//! The resolver runs them in order; first non-`Continue` verdict wins.

mod auth_gate;
mod method_gate;
mod route_rule_gate;
mod tier_default_gate;
mod tier_gate;
mod upstream_cc_gate;

pub use auth_gate::AuthGate;
pub use method_gate::MethodGate;
pub use route_rule_gate::RouteRuleGate;
pub use tier_default_gate::TierDefaultGate;
pub use tier_gate::TierGate;
pub use upstream_cc_gate::UpstreamCcGate;
