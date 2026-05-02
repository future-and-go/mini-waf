// Capture layer — Phase 03.
//
// Real ClientHello + h2 frame inspectors that write parsed fields into a
// per-connection `ConnCtx`. `NoopClientHelloInspector` /
// `NoopH2FrameInspector` remain available as fail-open defaults when
// FR-010 is disabled in config (brainstorm §4.9).

pub mod client_hello_inspector;
pub mod conn_ctx;
pub mod h2;
pub mod h2_frame_inspector;
pub mod parsed;
pub mod tls;

pub use client_hello_inspector::NoopClientHelloInspector;
pub use conn_ctx::{ConnCtx, ConnId, ConnRegistry};
pub use h2::H2FrameTap;
pub use h2_frame_inspector::NoopH2FrameInspector;
pub use parsed::{H2Capture, ParsedClientHello, PriorityFrame, RawCapture};
pub use tls::{ParseError, TlsCapture, parse_client_hello};
