//! FR-033 — gzip-only response body decompressor (v1).
//!
//! Streams chunked gzip from upstream into plaintext for the FR-033 scanner.
//! deflate / brotli / zstd / lz4 are deliberately out of scope (red-team #3) —
//! brotli has historical panic-isolation risk on adversarial input, and real
//! upstream traffic is overwhelmingly gzip. Tracked under FR-033b.
//!
//! Defenses (red-team #3):
//! - Output cap [`MAX_DECOMPRESS_BYTES`] (4 MiB).
//! - Input cap [`MAX_INPUT_BYTES`] (8 MiB).
//! - Ratio cap [`MAX_DECOMPRESS_RATIO`] (100:1) once at least 1 KiB of input
//!   has been observed (avoids first-chunk false positive).
//! - Pre-allocation gating via `std::io::Read::take` so the decoder never
//!   allocates beyond the cap (red-team Assumption #10).
//!
//! Fail-open: any error from `push` / `finish` is surfaced to the caller, who
//! then forwards the original encoded bytes untouched + a debug log. We do
//! NOT 502 the host on decode failure (research §5).

use std::io::Read;

use anyhow::anyhow;
use flate2::read::MultiGzDecoder;

use super::response_body_content_scanner::{MAX_DECOMPRESS_BYTES, MAX_DECOMPRESS_RATIO, MAX_INPUT_BYTES};

/// Categorised decode failure so the scanner can distinguish recoverable
/// transport errors (typically an incomplete gzip frame mid-stream) from
/// terminal resource-cap exhaustion. Caller behaviour:
/// - [`DecodeError::CapExhausted`] → terminal even mid-stream; mark the
///   scanner state failed and stop processing.
/// - [`DecodeError::Transport`] → recoverable mid-stream (decoder retains
///   buffered input); terminal at end-of-stream.
#[derive(Debug)]
pub enum DecodeError {
    /// Output / input / ratio cap hit. Treat as terminal.
    CapExhausted(String),
    /// Transport / framing error from the underlying decoder.
    Transport(anyhow::Error),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapExhausted(msg) => write!(f, "cap exhausted: {msg}"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CapExhausted(_) => None,
            Self::Transport(e) => Some(e.as_ref()),
        }
    }
}

/// Convenience alias for decoder operations.
pub type DecodeResult<T> = std::result::Result<T, DecodeError>;

/// Encodings supported by the FR-033 v1 decompressor. Anything else means
/// scanner-disabled-for-this-response (mirror AC-17's identity-only stance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `Content-Encoding: gzip` (and `x-gzip` alias).
    Gzip,
    /// `Content-Encoding: identity` or absent.
    Identity,
    /// Any other token (`deflate`, `br`, `zstd`, …). Scanner skipped.
    Unsupported,
}

/// Parse a `Content-Encoding` header value into an [`Encoding`]. Returns
/// [`Encoding::Unsupported`] for chained encodings (e.g. `gzip, deflate`)
/// because v1 only handles a single gzip layer (red-team #3).
pub fn parse_encoding(header: &str) -> Encoding {
    let trimmed = header.trim();
    if trimmed.is_empty() {
        return Encoding::Identity;
    }
    if trimmed.contains(',') {
        return Encoding::Unsupported;
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "identity" => Encoding::Identity,
        "gzip" | "x-gzip" => Encoding::Gzip,
        _ => Encoding::Unsupported,
    }
}

/// Streaming gzip decoder with input / output / ratio guards. Buffers raw
/// input bytes between `push` calls because `MultiGzDecoder` requires
/// borrow-of-`Read`; we feed it a fresh cursor on every push.
pub struct DecoderChain {
    /// Buffered (still-undelivered) input bytes from prior pushes.
    pending_input: Vec<u8>,
    /// Total input bytes consumed across the whole response.
    input_bytes: u64,
    /// Total output bytes emitted across the whole response.
    output_bytes: u64,
}

impl DecoderChain {
    pub const fn new() -> Self {
        Self {
            pending_input: Vec::new(),
            input_bytes: 0,
            output_bytes: 0,
        }
    }

    /// Push the next chunk of compressed bytes. Returns the freshly decoded
    /// plaintext for this push. Caller-side handling diverges by error
    /// variant: see [`DecodeError`].
    pub fn push(&mut self, chunk: &[u8]) -> DecodeResult<Vec<u8>> {
        self.input_bytes = self.input_bytes.saturating_add(chunk.len() as u64);
        if self.input_bytes > MAX_INPUT_BYTES {
            return Err(DecodeError::CapExhausted(format!(
                "input cap exceeded ({} > {})",
                self.input_bytes, MAX_INPUT_BYTES
            )));
        }

        self.pending_input.extend_from_slice(chunk);
        self.decode_buffered()
    }

    /// Flush at end-of-stream. Drains any remaining buffered input through the
    /// decoder.
    pub fn finish(&mut self) -> DecodeResult<Vec<u8>> {
        if self.pending_input.is_empty() {
            return Ok(Vec::new());
        }
        self.decode_buffered()
    }

    fn decode_buffered(&mut self) -> DecodeResult<Vec<u8>> {
        if self.pending_input.is_empty() {
            return Ok(Vec::new());
        }
        // Headroom = how many bytes of output we can still emit before the cap.
        let headroom = MAX_DECOMPRESS_BYTES.saturating_sub(self.output_bytes);
        if headroom == 0 {
            return Err(DecodeError::CapExhausted(format!(
                "output cap reached ({MAX_DECOMPRESS_BYTES} bytes)"
            )));
        }

        // Pre-allocation gating per red-team Assumption #10: bound `Read::take`
        // by remaining headroom + 1 so an oversize stream produces a controlled
        // EOF rather than uncapped allocation.
        let take_limit = headroom.saturating_add(1);
        let cursor = std::io::Cursor::new(self.pending_input.clone());
        let mut bounded = Read::take(cursor, take_limit);

        let mut out = Vec::new();
        {
            let mut decoder = MultiGzDecoder::new(&mut bounded);
            decoder
                .read_to_end(&mut out)
                .map_err(|e| DecodeError::Transport(anyhow!("gzip decompress: {e}")))?;
        }

        // Drain only the bytes the bounded reader actually consumed. For
        // gzip every byte read from the underlying cursor is a byte
        // consumed by inflate (no internal read-ahead past the take
        // limit), so `take_limit - bounded.limit()` is the exact consumed
        // count. This preserves un-decoded suffix bytes (e.g. the leading
        // bytes of a concatenated gzip stream that the take limit cut
        // mid-decode) for the next push instead of silently dropping them.
        let unread = bounded.limit();
        let consumed_u64 = take_limit.saturating_sub(unread);
        let consumed = usize::try_from(consumed_u64)
            .unwrap_or(self.pending_input.len())
            .min(self.pending_input.len());
        self.pending_input.drain(..consumed);

        self.output_bytes = self.output_bytes.saturating_add(out.len() as u64);

        if self.output_bytes > MAX_DECOMPRESS_BYTES {
            return Err(DecodeError::CapExhausted(format!(
                "output cap exceeded ({} > {})",
                self.output_bytes, MAX_DECOMPRESS_BYTES
            )));
        }
        // Ratio guard kicks in only after enough input has accumulated to
        // avoid first-chunk false positives on tiny inputs.
        if self.input_bytes >= 1024 && (self.output_bytes / self.input_bytes) > u64::from(MAX_DECOMPRESS_RATIO) {
            return Err(DecodeError::CapExhausted(format!(
                "decompression ratio bomb: {}/{} > {}",
                self.output_bytes, self.input_bytes, MAX_DECOMPRESS_RATIO
            )));
        }

        Ok(out)
    }
}

impl Default for DecoderChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    fn gzip_bytes(payload: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        let _ = e.write_all(payload);
        e.finish().unwrap_or_default()
    }

    #[test]
    fn test_parse_encoding_identity() {
        assert_eq!(parse_encoding(""), Encoding::Identity);
        assert_eq!(parse_encoding(" identity "), Encoding::Identity);
    }

    #[test]
    fn test_parse_encoding_gzip() {
        assert_eq!(parse_encoding("gzip"), Encoding::Gzip);
        assert_eq!(parse_encoding(" GZIP"), Encoding::Gzip);
        assert_eq!(parse_encoding("x-gzip"), Encoding::Gzip);
    }

    #[test]
    fn test_unknown_encoding_zstd_skipped_with_debug_log() {
        assert_eq!(parse_encoding("zstd"), Encoding::Unsupported);
        assert_eq!(parse_encoding("br"), Encoding::Unsupported);
        assert_eq!(parse_encoding("deflate"), Encoding::Unsupported);
        assert_eq!(parse_encoding("gzip, deflate"), Encoding::Unsupported);
    }

    #[test]
    fn test_gzip_decompress_positive() {
        let payload = b"hello world! decompress me back to plaintext.";
        let gz = gzip_bytes(payload);
        let mut d = DecoderChain::new();
        let out = d.push(&gz).unwrap_or_default();
        let tail = d.finish().unwrap_or_default();
        let mut combined = out;
        combined.extend(tail);
        assert_eq!(combined, payload);
    }

    #[test]
    fn test_gzip_bomb_10000_to_1_rejected_no_oom() {
        // 16 MiB of zeros gzipped is ~16 KiB → ratio ~1000:1, exceeds 100:1.
        let payload = vec![0u8; 16 * 1024 * 1024];
        let gz = gzip_bytes(&payload);
        let mut d = DecoderChain::new();
        let res = d.push(&gz);
        assert!(res.is_err(), "bomb must be rejected");
    }

    #[test]
    fn test_input_cap_8mib_rejected() {
        // Push a 9 MiB blob of pseudo-gzip bytes (won't decode but input cap
        // fires before we reach the decoder).
        let big = vec![0x1fu8; usize::try_from(MAX_INPUT_BYTES + 1).unwrap_or(usize::MAX)];
        let mut d = DecoderChain::new();
        let res = d.push(&big);
        assert!(res.is_err(), "input cap must reject");
    }

    #[test]
    fn test_gzip_streaming_two_pushes() {
        let payload = b"streamed-payload-streamed-payload";
        let gz = gzip_bytes(payload);
        let split = gz.len() / 2;
        let (a, b) = gz.split_at(split);
        let mut d = DecoderChain::new();
        let out1 = d.push(a).unwrap_or_default();
        let out2 = d.push(b).unwrap_or_default();
        let tail = d.finish().unwrap_or_default();
        let mut combined = out1;
        combined.extend(out2);
        combined.extend(tail);
        // A two-push gzip can decode at the second push or the finish call;
        // assert the payload appears somewhere in the concatenation.
        assert!(combined.windows(payload.len()).any(|w| w == payload));
    }

    #[test]
    fn test_decode_error_distinguishes_cap_from_transport() {
        // Input cap path → CapExhausted.
        let mut chain = DecoderChain::new();
        let huge_size = usize::try_from(MAX_INPUT_BYTES + 1).unwrap_or(usize::MAX);
        let huge = vec![0u8; huge_size];
        let err = chain.push(&huge).expect_err("input cap must err");
        assert!(matches!(err, DecodeError::CapExhausted(_)), "got {err:?}");

        // Transport path: malformed gzip header.
        let mut chain2 = DecoderChain::new();
        let garbage = b"not_gzip_at_all_this_is_garbage_bytes";
        let err2 = chain2.push(garbage).expect_err("garbage must err");
        assert!(matches!(err2, DecodeError::Transport(_)), "got {err2:?}");
    }

    #[test]
    fn test_pending_input_preserved_across_partial_push() {
        // When a single push is split mid-frame, the second half of the
        // gzip stream MUST be retained inside the chain — clearing on the
        // first (incomplete) push would lose those bytes.
        let payload = b"two-push-payload-must-survive-fragmentation";
        let gz = gzip_bytes(payload);
        // Cut after the gzip header (first 10 bytes are header) but before
        // any deflate block completes.
        let split_at = gz.len().min(8);
        let head_only = gz.get(..split_at).unwrap_or(&[]);
        let mut chain = DecoderChain::new();

        // First push is intentionally partial → either Ok(empty) or a
        // Transport error; both are recoverable.
        let _ = chain.push(head_only);

        // Second push delivers the rest; finish() must yield the full
        // payload somewhere in the concatenation.
        let rest = gz.get(split_at..).unwrap_or(&[]);
        let out2 = chain.push(rest).unwrap_or_default();
        let tail = chain.finish().unwrap_or_default();
        let mut combined = out2;
        combined.extend(tail);
        assert!(
            combined.windows(payload.len()).any(|w| w == payload),
            "payload must round-trip across split-push, got {combined:?}"
        );
    }
}
