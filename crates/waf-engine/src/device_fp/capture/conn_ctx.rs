// Per-connection capture slot — Phase 01 skeleton.
//
// Holds raw bytes captured during the TLS handshake and the early h2 frame
// window for a single connection. Phase 03 fills it from real inspector
// implementations and indexes it by connection id in a `DashMap` registry.

use parking_lot::Mutex;
use std::sync::Arc;

/// Owned snapshot of fingerprint-relevant bytes for one connection.
///
/// Buffers are bounded externally (caller is expected to truncate to a
/// reasonable max — e.g. 16KB `ClientHello`, 4KB early h2 frames).
#[derive(Debug, Default)]
pub struct RawCapture {
    pub tls_client_hello: Option<Vec<u8>>,
    pub h2_frames: Vec<Vec<u8>>,
}

/// Shared, mutable per-connection context. Cloned cheaply via `Arc`.
#[derive(Debug, Default, Clone)]
pub struct ConnCtx {
    inner: Arc<Mutex<RawCapture>>,
}

impl ConnCtx {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the captured `ClientHello` bytes. Last write wins.
    pub fn set_client_hello(&self, raw: Vec<u8>) {
        self.inner.lock().tls_client_hello = Some(raw);
    }

    /// Append an h2 frame snapshot.
    pub fn push_h2_frame(&self, frame: Vec<u8>) {
        self.inner.lock().h2_frames.push(frame);
    }

    /// Snapshot the current capture state. Cheap clone of small vectors.
    pub fn snapshot(&self) -> RawCapture {
        let g = self.inner.lock();
        RawCapture {
            tls_client_hello: g.tls_client_hello.clone(),
            h2_frames: g.h2_frames.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_capture() {
        let ctx = ConnCtx::new();
        ctx.set_client_hello(vec![0x16, 0x03, 0x01]);
        ctx.push_h2_frame(vec![0x00, 0x00, 0x06]);
        ctx.push_h2_frame(vec![0x00, 0x00, 0x04]);

        let snap = ctx.snapshot();
        assert_eq!(snap.tls_client_hello.as_deref(), Some(&[0x16, 0x03, 0x01][..]));
        assert_eq!(snap.h2_frames.len(), 2);
    }

    #[test]
    fn shared_across_clones() {
        let a = ConnCtx::new();
        let b = a.clone();
        a.set_client_hello(vec![1, 2, 3]);
        assert_eq!(b.snapshot().tls_client_hello.as_deref(), Some(&[1, 2, 3][..]));
    }
}
