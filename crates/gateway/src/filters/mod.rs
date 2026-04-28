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
pub mod response_body_mask_filter;
pub mod response_header_blocklist_filter;
pub mod response_location_rewriter;
pub mod response_server_policy_filter;
pub mod response_via_strip_filter;

pub use request_forwarded_host_filter::RequestForwardedHostFilter;
pub use request_forwarded_proto_filter::RequestForwardedProtoFilter;
pub use request_hop_by_hop_filter::RequestHopByHopFilter;
pub use request_host_policy_filter::RequestHostPolicyFilter;
pub use request_real_ip_filter::RequestRealIpFilter;
pub use request_xff_filter::RequestXffFilter;
pub use response_body_mask_filter::{CompiledMask, apply_chunk as apply_body_mask_chunk};
pub use response_header_blocklist_filter::ResponseHeaderBlocklistFilter;
pub use response_location_rewriter::ResponseLocationRewriter;
pub use response_server_policy_filter::ResponseServerPolicyFilter;
pub use response_via_strip_filter::ResponseViaStripFilter;
