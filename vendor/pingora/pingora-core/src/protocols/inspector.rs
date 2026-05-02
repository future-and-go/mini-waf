// Mini-WAF FR-010 device fingerprinting hooks.
//
// Additive, read-only inspector traits invoked synchronously from
// pingora's TLS handshake and HTTP/2 server frame loop. When unset
// (the default), behavior is unchanged. Hook callbacks must not block
// the executor; do heavy work (hashing, store I/O) elsewhere.

use std::sync::Arc;

/// Snapshot of an HTTP/2 frame relevant to Akamai-style fingerprinting.
///
/// Only the fields needed for the fingerprint are exposed. Frame payload
/// is borrowed from pingora's owned copy; do not retain after the call.
#[non_exhaustive]
#[derive(Debug)]
pub enum H2FrameSnapshot<'a> {
    /// SETTINGS frame: ordered (id, value) pairs, in wire order.
    Settings(&'a [(u16, u32)]),
    /// WINDOW_UPDATE on stream 0 (connection) or a specific stream.
    WindowUpdate { stream_id: u32, increment: u32 },
    /// PRIORITY frame.
    Priority {
        stream_id: u32,
        depends_on: u32,
        weight: u8,
        exclusive: bool,
    },
    /// HEADERS frame: pseudo-header order on the request, e.g. `[":method", ":path", ":scheme", ":authority"]`.
    /// `end_headers` indicates whether the END_HEADERS flag was set.
    Headers {
        stream_id: u32,
        pseudo_order: &'a [&'a str],
        end_headers: bool,
    },
}

/// Receives raw ClientHello bytes during TLS handshake.
///
/// Invoked synchronously before handshake completes. Implementations
/// should clone bytes into a per-connection slot and return immediately.
pub trait ClientHelloInspector: Send + Sync {
    /// `raw` is the ClientHello message starting at the TLS record body
    /// (handshake type byte = 0x01). Implementations must not mutate.
    fn on_client_hello(&self, raw: &[u8]);
}

/// Receives early HTTP/2 frames for fingerprinting.
///
/// Invoked synchronously per frame on stream 0 plus the first request stream
/// until END_HEADERS, then auto-detached by the server.
pub trait H2FrameInspector: Send + Sync {
    /// Called once per inspected frame. Return value reserved for future
    /// detach-control; current servers always auto-detach after first
    /// END_HEADERS regardless.
    fn on_frame(&self, frame: &H2FrameSnapshot<'_>);
}

/// Convenience alias for shared inspector handles.
pub type ClientHelloInspectorRef = Arc<dyn ClientHelloInspector>;
/// Convenience alias for shared inspector handles.
pub type H2FrameInspectorRef = Arc<dyn H2FrameInspector>;

// --- InspectStream: inbound-byte tap adapter ---------------------------------
//
// Generic AsyncRead + AsyncWrite passthrough that copies a snapshot of every
// inbound byte chunk to a `ByteTap` until the tap signals it's done. Used by
// Mini-WAF's FR-010 capture layer to:
//   - sniff the TLS ClientHello on the raw TCP stream (pre-handshake), and
//   - sniff the first HTTP/2 frames on the decrypted stream (post-handshake)
// without forking rustls or h2.
//
// The tap is auto-detached on `false` return to bound hot-path overhead to
// the first ~few KB of each connection.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Receiver for inbound bytes captured by [`InspectStream`].
///
/// Returning `false` detaches the tap; subsequent reads bypass it.
/// Implementations must not block — buffer and process elsewhere.
pub trait ByteTap: Send + Sync {
    fn on_bytes(&self, chunk: &[u8]) -> bool;
}

/// Wraps an inbound stream, fanning newly-read bytes to a [`ByteTap`].
///
/// Outbound writes pass through verbatim. The tap may be `None` (zero-cost
/// passthrough) or detach itself; in either case the stream's external
/// behavior matches `S` exactly.
///
/// Requires `S: Unpin`, satisfied by tokio TCP/Unix sockets and rustls/openssl
/// `TlsStream` wrappers — i.e. all stream types pingora hands to TLS or h2.
pub struct InspectStream<S> {
    inner: S,
    tap: Option<Arc<dyn ByteTap>>,
}

impl<S> InspectStream<S> {
    /// Wrap `inner`. Pass `None` for `tap` to obtain a zero-cost passthrough.
    pub fn new(inner: S, tap: Option<Arc<dyn ByteTap>>) -> Self {
        Self { inner, tap }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for InspectStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        // Tap only on successful reads that produced new bytes.
        if let Poll::Ready(Ok(())) = &res {
            if let Some(tap) = self.tap.as_ref() {
                let after = buf.filled().len();
                if after > before {
                    let keep = tap.on_bytes(&buf.filled()[before..after]);
                    if !keep {
                        self.tap = None;
                    }
                }
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for InspectStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
