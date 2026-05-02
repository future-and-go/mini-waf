// Capture layer — Phase 01 stubs.
//
// These no-op implementations validate that pingora-core's inspector traits
// are reachable from waf-engine and can be instantiated as `Arc<dyn Trait>`.
// Phase 03 replaces these stubs with real ClientHello / h2 frame capture
// backed by `tls-parser` and a hand-rolled h2 frame walker, plus a per-conn
// `RawCapture` slot keyed by connection id.

pub mod client_hello_inspector;
pub mod conn_ctx;
pub mod h2_frame_inspector;

pub use client_hello_inspector::NoopClientHelloInspector;
pub use conn_ctx::{ConnCtx, RawCapture};
pub use h2_frame_inspector::NoopH2FrameInspector;
