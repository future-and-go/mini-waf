//! Concrete request/response filters wired into the pipeline.
//!
//! Each filter is a small, single-purpose transform implementing
//! [`crate::pipeline::RequestFilter`] or [`crate::pipeline::ResponseFilter`].
//! Order matters: see `WafProxy::new` for registration sequence.

pub mod request_forwarded_host_filter;
pub mod request_forwarded_proto_filter;
pub mod request_hop_by_hop_filter;
pub mod request_host_policy_filter;
pub mod request_real_ip_filter;
pub mod request_xff_filter;

pub use request_forwarded_host_filter::RequestForwardedHostFilter;
pub use request_forwarded_proto_filter::RequestForwardedProtoFilter;
pub use request_hop_by_hop_filter::RequestHopByHopFilter;
pub use request_host_policy_filter::RequestHostPolicyFilter;
pub use request_real_ip_filter::RequestRealIpFilter;
pub use request_xff_filter::RequestXffFilter;
