//! AC-17 — streaming response-body internal-ref masker.
//!
//! Given a list of regex patterns (configured per-host as
//! [`waf_common::HostConfig::internal_patterns`]), every match in identity-encoded
//! response bodies is replaced with the configured mask token (default
//! `[redacted]`). The filter runs chunk-by-chunk via Pingora's
//! `response_body_filter` callback so memory stays bounded.
//!
//! Compressed bodies (`Content-Encoding` not `identity` / absent) are skipped
//! upstream — see `proxy::response_filter`. Body decompression is FR-033 scope.

use std::sync::Arc;

use bytes::Bytes;
use regex::bytes::Regex;

use crate::context::BodyMaskState;

/// Hard cap on the inter-chunk straddle buffer. Patterns longer than this
/// will not be detected if they cross a chunk boundary — acceptable for the
/// configured internal-ref use case (host names, IPs are short).
const MAX_TAIL_BYTES: usize = 1024;

/// Compiled per-host masking config. Built once at first use and cached on the
/// proxy keyed by the `Arc<HostConfig>` pointer identity.
pub struct CompiledMask {
    /// Combined alternation regex (`(?:p1)|(?:p2)|...`). `None` when there are
    /// no valid patterns — caller must short-circuit.
    pub regex: Option<Regex>,
    /// Mask replacement bytes.
    pub mask: Bytes,
    /// Maximum bytes scanned per response.
    pub max_bytes: u64,
    /// Number of bytes retained between chunks to catch straddling matches.
    pub keep_tail: usize,
}

impl CompiledMask {
    /// Compile patterns into a single alternation regex. Invalid patterns are
    /// dropped (logged) — fail-open by design (a bad pattern must not 502 a host).
    pub fn build(patterns: &[String], mask_token: &str, max_bytes: u64) -> Self {
        // Validate each pattern individually before combining; combined regex
        // hides which alternative was malformed.
        let valid: Vec<&str> = patterns
            .iter()
            .filter_map(|p| match Regex::new(p) {
                Ok(_) => Some(p.as_str()),
                Err(e) => {
                    tracing::warn!(pattern = %p, err = %e, "body-mask: dropping invalid regex");
                    None
                }
            })
            .collect();

        let regex = if valid.is_empty() {
            None
        } else {
            // Wrap each alternative in a non-capturing group so user-supplied
            // alternations don't bleed across the `|` join.
            let combined = valid.iter().map(|p| format!("(?:{p})")).collect::<Vec<_>>().join("|");
            Regex::new(&combined).ok()
        };

        // Tail size = longest pattern string length minus 1, clamped.
        let max_pat_len = valid.iter().map(|p| p.len()).max().unwrap_or(0);
        let keep_tail = max_pat_len.saturating_sub(1).min(MAX_TAIL_BYTES);

        Self {
            regex,
            mask: Bytes::copy_from_slice(mask_token.as_bytes()),
            max_bytes,
            keep_tail,
        }
    }

    /// `true` when there is nothing to do.
    pub const fn is_noop(&self) -> bool {
        self.regex.is_none()
    }
}

/// Apply the masker to one chunk. `body` is taken in-place: on return, it
/// holds the bytes to forward downstream (possibly empty when everything got
/// buffered into the tail).
///
/// Returns the number of *input* bytes consumed (for the byte-ceiling counter).
pub fn apply_chunk(state: &mut BodyMaskState, compiled: &Arc<CompiledMask>, body: &mut Option<Bytes>, eos: bool) {
    if !state.enabled || compiled.is_noop() {
        return;
    }
    if state.processed >= compiled.max_bytes {
        if !state.ceiling_logged {
            tracing::warn!(
                processed = state.processed,
                limit = compiled.max_bytes,
                "body-mask: byte ceiling reached, forwarding remainder unchanged"
            );
            state.ceiling_logged = true;
        }
        return;
    }

    let chunk = body.take().unwrap_or_default();
    state.processed = state.processed.saturating_add(chunk.len() as u64);

    // Concat tail + chunk into a single contiguous buffer for matching.
    let mut buf: Vec<u8> = Vec::with_capacity(state.tail.len() + chunk.len());
    buf.extend_from_slice(&state.tail);
    buf.extend_from_slice(&chunk);
    state.tail.clear();

    let keep_tail = if eos { 0 } else { compiled.keep_tail };
    // `is_noop()` was checked above, but use `if let` instead of `.expect()`
    // to honor the no-panic-shorthand iron rule.
    let Some(regex) = compiled.regex.as_ref() else {
        if !chunk.is_empty() {
            *body = Some(chunk);
        }
        return;
    };
    let (out, new_tail) = scan_and_replace(regex, &compiled.mask, &buf, keep_tail);

    if !new_tail.is_empty() {
        state.tail.extend_from_slice(&new_tail);
    }
    *body = if out.is_empty() { None } else { Some(Bytes::from(out)) };
}

/// Pure-function core: scan `buf`, emit a replaced output, return the suffix
/// to retain as the next-chunk tail.
///
/// Algorithm: walk non-overlapping matches in order. If a match crosses the
/// `(buf.len() - keep_tail)` boundary we stop, retain everything from the
/// match's start onward as tail, and emit the prefix unchanged.
fn scan_and_replace(re: &Regex, mask: &[u8], buf: &[u8], keep_tail: usize) -> (Vec<u8>, Vec<u8>) {
    let split = buf.len().saturating_sub(keep_tail);
    let mut out: Vec<u8> = Vec::with_capacity(buf.len());
    let mut cursor = 0usize;

    for m in re.find_iter(buf) {
        if m.end() > split {
            // Match crosses the tail boundary — defer it to the next chunk so
            // we don't emit a half-redacted token. Anything before m.start()
            // is safe to flush; from m.start() onward becomes the new tail.
            let new_split = m.start().max(cursor);
            if let Some(slice) = buf.get(cursor..new_split) {
                out.extend_from_slice(slice);
            }
            let tail = buf.get(new_split..).map(<[u8]>::to_vec).unwrap_or_default();
            return (out, tail);
        }
        if let Some(slice) = buf.get(cursor..m.start()) {
            out.extend_from_slice(slice);
        }
        out.extend_from_slice(mask);
        cursor = m.end();
    }

    // No straddling match. Flush up to `split`, retain the rest as tail.
    let flush_to = split.max(cursor);
    if let Some(slice) = buf.get(cursor..flush_to) {
        out.extend_from_slice(slice);
    }
    let tail = buf.get(flush_to..).map(<[u8]>::to_vec).unwrap_or_default();
    (out, tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(patterns: &[&str]) -> Arc<CompiledMask> {
        let owned: Vec<String> = patterns.iter().map(|s| (*s).to_string()).collect();
        Arc::new(CompiledMask::build(&owned, "[redacted]", 1024 * 1024))
    }

    fn run(state: &mut BodyMaskState, c: &Arc<CompiledMask>, chunk: &[u8], eos: bool) -> Vec<u8> {
        let mut body = if chunk.is_empty() {
            None
        } else {
            Some(Bytes::copy_from_slice(chunk))
        };
        apply_chunk(state, c, &mut body, eos);
        body.map(|b| b.to_vec()).unwrap_or_default()
    }

    fn enabled_state() -> BodyMaskState {
        BodyMaskState {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn single_chunk_replaces_match() {
        let c = mk(&["backend\\.internal", r"10\.0\.0\.5"]);
        let mut s = enabled_state();
        let out = run(&mut s, &c, b"see backend.internal at 10.0.0.5 today", true);
        assert_eq!(out, b"see [redacted] at [redacted] today");
        assert!(s.tail.is_empty());
    }

    #[test]
    fn straddle_across_two_chunks_replaced() {
        // Pattern length 17 ⇒ keep_tail 16. Use a chunk longer than that so we
        // get a non-trivial split and exercise the straddle path realistically.
        let c = mk(&["backend\\.internal"]);
        let mut s = enabled_state();
        let part1 = run(&mut s, &c, b"hello world here is some back", false);
        // Anything that could be the start of a pattern (the tail-window) must
        // be buffered, not leaked. So the boundary "back" cannot appear in part1.
        assert!(
            !part1.windows(4).any(|w| w == b"back"),
            "boundary 'back' must not leak: {part1:?}"
        );

        let part2 = run(&mut s, &c, b"end.internal! bye", true);
        // After EOS the full "backend.internal" reassembles and gets masked.
        let combined = [part1, part2].concat();
        assert_eq!(combined, b"hello world here is some [redacted]! bye");
    }

    #[test]
    fn eos_flushes_tail() {
        let c = mk(&["abc"]);
        let mut s = enabled_state();
        let _ = run(&mut s, &c, b"xxab", false);
        // "ab" must be retained as tail (could become "abc").
        assert!(!s.tail.is_empty());
        let out = run(&mut s, &c, b"", true);
        // EOS with no pattern in tail just flushes the tail unchanged.
        assert_eq!(out, b"ab");
    }

    #[test]
    fn disabled_state_passes_through() {
        let c = mk(&["secret"]);
        let mut s = BodyMaskState::default(); // enabled=false
        let out = run(&mut s, &c, b"secret data", true);
        assert_eq!(out, b"secret data");
    }

    #[test]
    fn empty_patterns_is_noop() {
        let c = mk(&[]);
        assert!(c.is_noop());
        let mut s = enabled_state();
        let out = run(&mut s, &c, b"anything", true);
        assert_eq!(out, b"anything");
    }

    #[test]
    fn invalid_pattern_dropped_others_kept() {
        let c = mk(&["[invalid", "valid"]);
        let mut s = enabled_state();
        let out = run(&mut s, &c, b"valid here", true);
        assert_eq!(out, b"[redacted] here");
    }

    #[test]
    fn ceiling_stops_processing() {
        let owned = vec!["secret".to_string()];
        let c = Arc::new(CompiledMask::build(&owned, "X", 5));
        let mut s = enabled_state();
        // First chunk pushes processed past the ceiling.
        let _ = run(&mut s, &c, b"abcdef", true);
        // Second chunk: ceiling already reached → forwarded unchanged.
        let out = run(&mut s, &c, b"secret", true);
        assert_eq!(out, b"secret");
    }

    #[test]
    fn match_at_boundary_not_double_emitted() {
        // Regression: ensure cursor advance over straddling matches is correct.
        let c = mk(&["AB"]);
        let mut s = enabled_state();
        let out1 = run(&mut s, &c, b"xxA", false);
        assert_eq!(out1, b"xx");
        let out2 = run(&mut s, &c, b"By", true);
        assert_eq!(out2, b"[redacted]y");
    }
}
