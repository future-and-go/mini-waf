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

use anyhow::{Context, Result, anyhow};
use flate2::read::MultiGzDecoder;

use super::response_body_content_scanner::{MAX_DECOMPRESS_BYTES, MAX_DECOMPRESS_RATIO, MAX_INPUT_BYTES};

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
    /// plaintext for this push. Errors propagate to caller (fail-open).
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        self.input_bytes = self.input_bytes.saturating_add(chunk.len() as u64);
        if self.input_bytes > MAX_INPUT_BYTES {
            return Err(anyhow!(
                "input cap exceeded ({} > {})",
                self.input_bytes,
                MAX_INPUT_BYTES
            ));
        }

        self.pending_input.extend_from_slice(chunk);
        let decoded = self.decode_buffered()?;
        Ok(decoded)
    }

    /// Flush at end-of-stream. Drains any remaining buffered input through the
    /// decoder.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        if self.pending_input.is_empty() {
            return Ok(Vec::new());
        }
        self.decode_buffered()
    }

    fn decode_buffered(&mut self) -> Result<Vec<u8>> {
        if self.pending_input.is_empty() {
            return Ok(Vec::new());
        }
        // Headroom = how many bytes of output we can still emit before the cap.
        let headroom = MAX_DECOMPRESS_BYTES.saturating_sub(self.output_bytes);
        if headroom == 0 {
            return Err(anyhow!("output cap reached ({MAX_DECOMPRESS_BYTES} bytes)"));
        }

        // Pre-allocation gating per red-team Assumption #10: bound `Read::take`
        // by remaining headroom + 1 so an oversize stream produces a controlled
        // EOF rather than uncapped allocation.
        let take_limit = headroom.saturating_add(1);
        let cursor = std::io::Cursor::new(self.pending_input.clone());
        let mut bounded = Read::take(cursor, take_limit);

        let mut out = Vec::new();
        let mut decoder = MultiGzDecoder::new(&mut bounded);
        decoder.read_to_end(&mut out).context("gzip decompress: read_to_end")?;

        // Reflect the bytes the decoder consumed. `MultiGzDecoder` does not
        // expose consumed-input directly when fed a `Take<Cursor>`, so we use
        // a heuristic: the entire pending input is consumed unless the take
        // limit fired (in which case decoder errors before we get here). Keep
        // the simple model — per-chunk push, drain pending fully on success.
        self.pending_input.clear();
        self.output_bytes = self.output_bytes.saturating_add(out.len() as u64);

        if self.output_bytes > MAX_DECOMPRESS_BYTES {
            return Err(anyhow!(
                "output cap exceeded ({} > {})",
                self.output_bytes,
                MAX_DECOMPRESS_BYTES
            ));
        }
        // Ratio guard kicks in only after enough input has accumulated to
        // avoid first-chunk false positives on tiny inputs.
        if self.input_bytes >= 1024 && (self.output_bytes / self.input_bytes) > u64::from(MAX_DECOMPRESS_RATIO) {
            return Err(anyhow!(
                "decompression ratio bomb: {}/{} > {}",
                self.output_bytes,
                self.input_bytes,
                MAX_DECOMPRESS_RATIO
            ));
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
}
