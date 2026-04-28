//! FR-033 — built-in response-body content scanner.
//!
//! Detects four leak categories on plaintext (post-decompression) bytes and
//! redacts every match with the hardcoded token [`MASK_TOKEN`]. Pattern
//! provenance: `TruffleHog` / Gitleaks / OWASP CRS public catalogs (see research
//! report §2). Each pattern is verified at compile time to have a finite max
//! length (`regex_syntax::hir::Hir::properties().maximum_len() <= 1024`) so it
//! cannot run away on adversarial input.
//!
//! Categories:
//! 1. Stack traces (Java, Python, Rust, Node, .NET, Go, PHP)
//! 2. Verbose error messages (SQL syntax markers, framework prose)
//! 3. API keys / tokens (AWS, GCP, GitHub, Slack, Stripe, JWT, `OpenAI`,
//!    Anthropic, Twilio, generic private-key blocks)
//! 4. Internal IPs (RFC-1918 / loopback / link-local IPv4, IPv6 ULA)
//!
//! ReDoS-safe by construction:
//! - Multi-byte literals routed through Aho-Corasick (linear-time, no
//!   backtracking). Cloudflare 2019 outage class avoided.
//! - Each `Regex` compiled with explicit `RegexBuilder::size_limit` and
//!   `dfa_size_limit`; every quantifier has explicit `{min,max}` bounds.
//! - Internal-IP detection is byte-scan + strict `Ipv4Addr::from_str`, NOT a
//!   regex CIDR alternation. Rejects `0177.0.0.1` style octal aliasing.
//!
//! Single action: replace match span with [`MASK_TOKEN`]. Whole-body block
//! remains FR-005's responsibility (request-time). See plan red-team #2.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use bytes::Bytes;
use parking_lot::Mutex;
use regex::bytes::{Regex, RegexBuilder};
use regex_syntax::ParserBuilder;

use crate::context::BodyScanState;
use crate::filters::response_body_decompressor::DecodeError;

use std::sync::OnceLock;

/// Mask token written in place of every detected leak. Hardcoded per red-team #2.
pub const MASK_TOKEN: &[u8] = b"[redacted]";

/// Hard cap on decompressed bytes per response (red-team #3).
pub const MAX_DECOMPRESS_BYTES: u64 = 4 << 20;

/// Output / input ratio guard (red-team #3).
pub const MAX_DECOMPRESS_RATIO: u32 = 100;

/// Hard cap on input bytes consumed per response (red-team #3 / Sec #1).
pub const MAX_INPUT_BYTES: u64 = 8 << 20;

/// Inter-chunk straddle buffer cap (red-team #7).
pub const MAX_TAIL_BYTES: usize = 1024;

/// Per-chunk tail size — straddle window. `MAX_TAIL_BYTES - 1` so a full
/// pattern of length `MAX_TAIL_BYTES` is always entirely buffered (red-team #7).
pub const KEEP_TAIL: usize = MAX_TAIL_BYTES - 1;

/// Detection categories surfaced for metrics / logs.
#[derive(Debug, Clone, Copy)]
pub enum Category {
    StackTrace,
    VerboseError,
    Secret,
    InternalIp,
}

impl Category {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StackTrace => "stack_trace",
            Self::VerboseError => "verbose_error",
            Self::Secret => "secret",
            Self::InternalIp => "internal_ip",
        }
    }
}

/// Aho-Corasick literals (≥ 20 bytes each, distinctive enough not to FP on
/// unrelated prose). Stack-trace anchors first, then verbose-error markers.
const LITERALS: &[(&[u8], Category)] = &[
    // Stack-trace anchors — high-signal language sentinels.
    (b"Traceback (most recent call last)", Category::StackTrace),
    (b"panicked at '", Category::StackTrace),
    (b"goroutine 1 [running]", Category::StackTrace),
    (b"Fatal error: Uncaught", Category::StackTrace),
    (b"--- End of inner exception stack trace ---", Category::StackTrace),
    // Verbose-error literals — frameworks / DB drivers leaking internals.
    (b"at org.springframework", Category::VerboseError),
    (b"at System.NullReferenceException", Category::VerboseError),
    (b"Microsoft.AspNetCore", Category::VerboseError),
    (b"java.lang.RuntimeException", Category::VerboseError),
    (b"You have an error in your SQL syntax", Category::VerboseError),
    (b"PG::SyntaxError", Category::VerboseError),
];

/// Anchored multi-line stack-trace regexes (one per language). Each has
/// explicit `{min,max}` quantifiers per red-team #10.
const STACK_TRACE_REGEXES: &[&str] = &[
    // Java / Kotlin: leading whitespace, "at <FQCN>(...)" with bounded class
    // identifier and parameter list.
    r"(?m)^\s{1,16}at\s[A-Za-z_][\w$.]{0,255}\([^)]{0,255}\)",
    // Python: '  File "<path>", line <n>, in <fn>'
    r#"(?m)^  File "[^"]{1,512}", line \d{1,10}, in "#,
    // Rust: thread 'name' panicked at <loc>
    r"(?m)^thread '[^']{1,128}' panicked at",
    // Node.js: "    at <fn> (<file>:<line>:<col>)"
    r"(?m)^\s{1,16}at\s[\w$<>.]{1,255}\s\(.{1,512}:\d{1,10}:\d{1,10}\)$",
];

/// Bounded secret regexes — explicit `{min,max}` per red-team #10.
const SECRET_REGEXES: &[&str] = &[
    // GitHub PATs (classic + fine-grained prefixes).
    r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    // AWS access key id.
    r"AKIA[0-9A-Z]{16}",
    // Slack tokens.
    r"xox[baprs]-[0-9A-Za-z-]{20,512}",
    // Stripe live + test secret keys.
    r"sk_(?:live|test)_[0-9a-zA-Z]{24,256}",
    // JWT — three base64url segments, bounded so the total fits MAX_REGEX_LEN.
    r"eyJ[A-Za-z0-9_\-]{8,256}\.eyJ[A-Za-z0-9_\-]{8,256}\.[A-Za-z0-9_\-]{8,256}",
    // Google API key.
    r"AIza[0-9A-Za-z_\-]{35}",
    // OpenAI keys.
    r"sk-[A-Za-z0-9]{20,256}",
    // Anthropic keys.
    r"sk-ant-[A-Za-z0-9_\-]{20,256}",
    // Twilio account / API SIDs.
    r"SK[0-9a-f]{32}",
    // PEM / OpenSSH private-key block markers.
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
];

/// Maximum permitted `regex_syntax::hir::properties::maximum_len` for any
/// built-in regex. Exceeding this means a regex can match longer than our
/// straddle tail buffer, opening a chunk-boundary leak (red-team #7).
const MAX_REGEX_LEN: usize = 1024;

/// Validate a regex pattern at compile time: parse via `regex_syntax`, reject
/// if `properties().maximum_len()` is unbounded or exceeds [`MAX_REGEX_LEN`].
///
/// Parsed in ASCII-only mode (`unicode(false)`) so `\s` / `\w` count as
/// single-byte classes — the catalog targets ASCII payloads and Unicode-mode
/// counting blew past 1024 on legitimate Java FQCN / JWT patterns.
fn pattern_within_bounds(pattern: &str) -> bool {
    ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(pattern)
        .is_ok_and(|hir| hir.properties().maximum_len().is_some_and(|n| n <= MAX_REGEX_LEN))
}

/// Compile a single bounded regex via [`RegexBuilder`] with explicit DFA caps.
/// Returns `None` on compile failure or bound violation — fail-open (mirror
/// AC-17): a bad pattern must never 502 a host.
fn compile_bounded(pattern: &str) -> Option<Regex> {
    if !pattern_within_bounds(pattern) {
        tracing::warn!(pattern = pattern, "body-scan: rejecting unbounded or overlong regex");
        return None;
    }
    match RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .dfa_size_limit(2 << 20)
        .unicode(false)
        .build()
    {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::warn!(pattern = pattern, err = %e, "body-scan: regex compile failed");
            None
        }
    }
}

/// Compiled per-host scanner. Built once per `(host, content-hash)` pair and
/// cached on the proxy via a content-hash map (red-team #6).
pub struct CompiledScanner {
    /// Aho-Corasick automaton over distinctive multi-byte literals. `None`
    /// only on a (documented-impossible) AC build failure on the compile-time
    /// catalog; in that case literal scanning is silently skipped (fail-open).
    literal_ac: Option<AhoCorasick>,
    /// Per-literal category lookup (parallel to `literal_ac`'s pattern ids).
    literal_categories: Vec<Category>,
    /// Anchored multi-line stack-trace regexes.
    stack_trace_regexes: Vec<Regex>,
    /// Secret-pattern regexes.
    secret_regexes: Vec<Regex>,
    /// Hard ceiling on plaintext bytes scanned per response.
    pub max_body_bytes: u64,
}

impl CompiledScanner {
    /// Build the catalog. Always succeeds (fail-open per pattern). Catalog
    /// patterns that fail validation are dropped + warned. The literals AC is
    /// always non-empty; even a degenerate build yields a usable scanner.
    pub fn build(max_body_bytes: u64) -> Self {
        let (literal_bytes, literal_categories): (Vec<&[u8]>, Vec<Category>) =
            LITERALS.iter().map(|(b, c)| (*b, *c)).unzip();

        // Build the literal AC. A failure here is unreachable for the
        // compile-time constant catalog (verified by tests). On hypothetical
        // failure we fall through to a no-op scanner via `Option<AhoCorasick>`.
        let literal_ac_opt = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&literal_bytes)
            .map_err(|e| {
                tracing::warn!(err = %e, "body-scan: AC build failed; literals disabled");
            })
            .ok();

        let stack_trace_regexes = STACK_TRACE_REGEXES.iter().filter_map(|p| compile_bounded(p)).collect();

        let secret_regexes = SECRET_REGEXES.iter().filter_map(|p| compile_bounded(p)).collect();

        Self {
            literal_ac: literal_ac_opt,
            literal_categories,
            stack_trace_regexes,
            secret_regexes,
            max_body_bytes,
        }
    }

    /// Scanner is conceptually never a no-op once built (catalog is built-in),
    /// but the wiring layer still asks so it can cleanly skip on disabled
    /// hosts. Returns `false` so the chain runs.
    pub const fn is_noop(&self) -> bool {
        false
    }
}

/// Per-host metrics counter. Increments inline; the `/metrics` surface in
/// `waf-api` is not yet trivially extensible, so for now this counter lives
/// behind a global mutex for unit-test inspection (red-team #15).
///
/// TODO(FR-033b): wire to Prometheus once `waf-api::stats` exposes a generic
/// counter registry.
static HITS: OnceLock<Mutex<HashMap<(String, &'static str), u64>>> = OnceLock::new();

fn hits_counter() -> &'static Mutex<HashMap<(String, &'static str), u64>> {
    HITS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Inspection helper for the per-host hit counter.
///
/// Exposed for the in-tree integration test that asserts increments (red-team
/// review H3 / M3) and as the future surface point for the FR-033b Prometheus
/// wiring.
pub fn hits_for(host: &str, category: &'static str) -> u64 {
    hits_counter()
        .lock()
        .get(&(host.to_string(), category))
        .copied()
        .unwrap_or(0)
}

fn record_hit(host: &str, category: Category) {
    hits_counter()
        .lock()
        .entry((host.to_string(), category.as_str()))
        .and_modify(|v| *v = v.saturating_add(1))
        .or_insert(1);
}

/// Apply the scanner to one chunk. `body` is taken in place; on return it
/// holds the bytes to forward downstream.
pub fn apply_chunk(
    state: &mut BodyScanState,
    compiled: &Arc<CompiledScanner>,
    body: &mut Option<Bytes>,
    eos: bool,
    host_label: &str,
) {
    if !state.enabled || state.failed {
        return;
    }
    if state.processed >= compiled.max_body_bytes {
        if !state.ceiling_logged {
            tracing::warn!(
                processed = state.processed,
                limit = compiled.max_body_bytes,
                "body-scan: byte ceiling reached, forwarding remainder unchanged"
            );
            state.ceiling_logged = true;
        }
        // Red-team review H1: any tail bytes buffered for boundary-straddle
        // detection on a prior chunk MUST be flushed downstream once we give
        // up scanning, otherwise we silently truncate the response.
        if !state.tail.is_empty() {
            let tail_bytes: Vec<u8> = state.tail.split().to_vec();
            let raw = body.take().unwrap_or_default();
            let mut combined = Vec::with_capacity(tail_bytes.len() + raw.len());
            combined.extend_from_slice(&tail_bytes);
            combined.extend_from_slice(&raw);
            *body = Some(Bytes::from(combined));
        }
        return;
    }

    let raw = body.take().unwrap_or_default();

    // Decompression path (if a decoder is attached) — phase-02 hook.
    //
    // Red-team review B3 + C3 fix: gzip is a stream format whose decoder may
    // reject any single chunk that ends mid-block. We distinguish two error
    // kinds via [`DecodeError`]:
    // - `CapExhausted` is terminal even mid-stream — letting subsequent
    //   chunks through after a cap fired would silently bypass scanning
    //   (e.g. concatenated-stream bypass when the take limit cuts mid-decode).
    // - `Transport` is recoverable mid-stream because `DecoderChain::push`
    //   retains the unconsumed input internally; a later push may complete
    //   the gzip frame. At `eos`, both kinds are terminal.
    // On any terminal failure we replace the body with empty bytes (NOT the
    // raw gzip bytes) because `Content-Encoding` was already stripped in
    // `response_filter`.
    let plaintext: Vec<u8> = if let Some(chain) = state.decoder.as_mut() {
        match chain.push(&raw) {
            Ok(v) => {
                if eos {
                    match chain.finish() {
                        Ok(mut tail) => {
                            let mut combined = v;
                            combined.append(&mut tail);
                            combined
                        }
                        Err(e) => {
                            tracing::warn!(err = %e, "body-scan: decoder finish failed; replacing body with empty");
                            state.failed = true;
                            *body = Some(Bytes::new());
                            return;
                        }
                    }
                } else {
                    // Mid-stream: forward decoded bytes for this push (may be
                    // empty if upstream sent only a partial frame). Pending
                    // input retained inside DecoderChain for the next push.
                    v
                }
            }
            Err(decode_err) => match decode_err {
                DecodeError::CapExhausted(msg) => {
                    // Terminal regardless of `eos`: cap fired, future chunks
                    // would bypass scanning if we tolerated this.
                    tracing::warn!(
                        err = %msg,
                        "body-scan: decoder cap exhausted; replacing remaining body with empty"
                    );
                    state.failed = true;
                    *body = Some(Bytes::new());
                    return;
                }
                DecodeError::Transport(e) => {
                    if eos {
                        // Terminal: corrupt or truncated stream at end-of-stream.
                        tracing::warn!(
                            err = %e,
                            "body-scan: decoder push failed at eos; replacing body with empty"
                        );
                        state.failed = true;
                        *body = Some(Bytes::new());
                        return;
                    }
                    // Mid-stream incomplete frame — decoder retains pending
                    // input; next push may complete the frame.
                    tracing::debug!(
                        err = %e,
                        "body-scan: decoder push deferred (incomplete frame, awaiting more bytes)"
                    );
                    *body = Some(Bytes::new());
                    return;
                }
            },
        }
    } else {
        raw.to_vec()
    };

    // Counter measures plaintext bytes scanned (post-decompression). Counting
    // raw upstream bytes here would let gzip ratio distort the ceiling — a
    // 100 KiB compressed payload that decodes to 1 MiB plaintext would
    // register only 100 KiB and bypass `max_body_bytes`.
    state.processed = state.processed.saturating_add(plaintext.len() as u64);

    // Concat tail + plaintext into a single contiguous scan window.
    let mut buf: Vec<u8> = Vec::with_capacity(state.tail.len() + plaintext.len());
    buf.extend_from_slice(&state.tail);
    buf.extend_from_slice(&plaintext);
    state.tail.clear();

    let keep_tail = if eos { 0 } else { KEEP_TAIL };
    let (out, new_tail) = scan_and_replace(compiled, &buf, keep_tail, host_label);

    if !new_tail.is_empty() {
        state.tail.extend_from_slice(&new_tail);
    }
    *body = if out.is_empty() { None } else { Some(Bytes::from(out)) };
}

/// Pure scan + replace. Walks every matcher, dedups overlapping spans by
/// leftmost-first, applies replacement, returns `(emitted, new_tail)`.
fn scan_and_replace(compiled: &CompiledScanner, buf: &[u8], keep_tail: usize, host_label: &str) -> (Vec<u8>, Vec<u8>) {
    // Collect (start, end, category) for every distinct match. Dedup by
    // sorting and greedy non-overlap.
    let mut spans: Vec<(usize, usize, Category)> = Vec::new();

    // 1. Aho-Corasick literals.
    if let Some(ac) = compiled.literal_ac.as_ref() {
        for m in ac.find_iter(buf) {
            let cat = compiled
                .literal_categories
                .get(m.pattern().as_usize())
                .copied()
                .unwrap_or(Category::VerboseError);
            spans.push((m.start(), m.end(), cat));
        }
    }

    // 2. Stack-trace anchored regexes.
    for r in &compiled.stack_trace_regexes {
        for m in r.find_iter(buf) {
            spans.push((m.start(), m.end(), Category::StackTrace));
        }
    }

    // 3. Secret regexes.
    for r in &compiled.secret_regexes {
        for m in r.find_iter(buf) {
            spans.push((m.start(), m.end(), Category::Secret));
        }
    }

    // 4. Internal IPs (byte-scan + strict parse).
    collect_internal_ipv4_spans(buf, &mut spans);
    collect_internal_ipv6_spans(buf, &mut spans);

    // Sort and dedup overlapping ranges (keep leftmost / longest).
    spans.sort_by_key(|s| (s.0, std::cmp::Reverse(s.1)));
    let mut deduped: Vec<(usize, usize, Category)> = Vec::with_capacity(spans.len());
    let mut last_end = 0usize;
    for (s, e, c) in spans {
        if s >= last_end {
            deduped.push((s, e, c));
            last_end = e;
        }
    }

    let split = buf.len().saturating_sub(keep_tail);
    let mut out: Vec<u8> = Vec::with_capacity(buf.len());
    let mut cursor = 0usize;

    for (s, e, cat) in &deduped {
        let (s, e) = (*s, *e);
        if e > split {
            // Match crosses the boundary — defer to next chunk.
            let new_split = s.max(cursor);
            if let Some(slice) = buf.get(cursor..new_split) {
                out.extend_from_slice(slice);
            }
            let tail = buf.get(new_split..).map(<[u8]>::to_vec).unwrap_or_default();
            return (out, tail);
        }
        if let Some(slice) = buf.get(cursor..s) {
            out.extend_from_slice(slice);
        }
        out.extend_from_slice(MASK_TOKEN);
        record_hit(host_label, *cat);
        cursor = e;
    }

    let flush_to = split.max(cursor);
    if let Some(slice) = buf.get(cursor..flush_to) {
        out.extend_from_slice(slice);
    }
    let tail = buf.get(flush_to..).map(<[u8]>::to_vec).unwrap_or_default();
    (out, tail)
}

/// Scan dotted-quad candidates and gate on RFC-1918 / loopback / link-local
/// via strict `Ipv4Addr::from_str` (rejects octal / leading-zero forms).
fn collect_internal_ipv4_spans(buf: &[u8], out: &mut Vec<(usize, usize, Category)>) {
    let mut i = 0;
    while i < buf.len() {
        // Find next ASCII digit.
        let Some(start_rel) = buf.get(i..).and_then(|s| s.iter().position(u8::is_ascii_digit)) else {
            return;
        };
        let start = i + start_rel;
        // Reject if preceded by an alphanumeric / dot (word-boundary check).
        let prev_ok = start
            .checked_sub(1)
            .and_then(|p| buf.get(p))
            .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'.'));
        // Walk the candidate up to 15 chars (max IPv4 dotted-quad length).
        // Red-team review C2: cap at 3 dots so `127.0.0.1.5` does not consume
        // beyond the dotted-quad and bypass the strict-parse + CIDR gate.
        let mut end = start;
        let mut dot_count = 0usize;
        let mut stopped_at_4th_dot = false;
        while end < buf.len() && end - start < 15 {
            let b = match buf.get(end) {
                Some(v) => *v,
                None => break,
            };
            if b.is_ascii_digit() {
                end += 1;
            } else if b == b'.' {
                if dot_count >= 3 {
                    stopped_at_4th_dot = true;
                    break;
                }
                dot_count += 1;
                end += 1;
            } else {
                break;
            }
        }
        // When we stopped because a 4th dot would have appeared (C2 padded
        // form), accept the dotted-quad we already collected; the trailing
        // `.` is NOT a valid IPv4 continuation so a word-boundary check on
        // it would be too strict.
        let next_ok = stopped_at_4th_dot || buf.get(end).is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'.'));
        if prev_ok
            && next_ok
            && let Some(slice) = buf.get(start..end)
            && let Ok(s) = std::str::from_utf8(slice)
            && let Ok(addr) = Ipv4Addr::from_str(s)
            && (addr.is_loopback() || addr.is_private() || addr.is_link_local())
            && end - start >= 7
        {
            out.push((start, end, Category::InternalIp));
        }
        i = end.max(start + 1);
    }
}

/// Best-effort IPv6 internal detection. Scans for sequences of hex digits +
/// colons, strict-parses, gates on loopback (`::1`), unique-local (`fc00::/7`),
/// and unicast link-local (`fe80::/10`). Red-team review C1: previously only
/// ULA was flagged; loopback and link-local additions close the parity gap
/// with the IPv4 path.
fn collect_internal_ipv6_spans(buf: &[u8], out: &mut Vec<(usize, usize, Category)>) {
    let mut i = 0;
    while i < buf.len() {
        // Find next hex digit or colon.
        let Some(start_rel) = buf
            .get(i..)
            .and_then(|s| s.iter().position(|b| b.is_ascii_hexdigit() || *b == b':'))
        else {
            return;
        };
        let start = i + start_rel;
        let prev_ok = start
            .checked_sub(1)
            .and_then(|p| buf.get(p))
            .is_none_or(|b| !(b.is_ascii_hexdigit() || *b == b':'));
        let mut end = start;
        let mut colon_count = 0usize;
        while end < buf.len() && end - start < 39 {
            let b = match buf.get(end) {
                Some(v) => *v,
                None => break,
            };
            if b.is_ascii_hexdigit() {
                end += 1;
            } else if b == b':' {
                colon_count += 1;
                end += 1;
            } else {
                break;
            }
        }
        let next_ok = buf.get(end).is_none_or(|b| !(b.is_ascii_hexdigit() || *b == b':'));
        // Length floor 3 admits `::1` (loopback shortest form). Red-team C1.
        if prev_ok
            && next_ok
            && colon_count >= 2
            && (end - start) >= 3
            && let Some(slice) = buf.get(start..end)
            && let Ok(s) = std::str::from_utf8(slice)
            && let Ok(addr) = Ipv6Addr::from_str(s)
            && (addr.is_loopback() || addr.is_unique_local() || addr.is_unicast_link_local())
        {
            out.push((start, end, Category::InternalIp));
        }
        i = end.max(start + 1);
    }
}

/// Build cache key half: a 64-bit content hash over the host-config fields
/// that influence scanner behavior. Used by `WafProxy::resolve_scanner`.
pub fn scanner_config_hash(body_scan_enabled: bool, body_scan_max_body_bytes: u64) -> u64 {
    use std::hash::Hasher;
    use twox_hash::XxHash64;
    let mut h = XxHash64::with_seed(0);
    h.write_u8(u8::from(body_scan_enabled));
    h.write_u64(body_scan_max_body_bytes);
    h.finish()
}

// ---------------------------------------------------------------------------
// Tests — phase-05 lives here to keep coverage gated to the file itself.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::BodyScanState;

    fn scanner() -> Arc<CompiledScanner> {
        Arc::new(CompiledScanner::build(1 << 20))
    }

    fn run(state: &mut BodyScanState, c: &Arc<CompiledScanner>, chunk: &[u8], eos: bool) -> Vec<u8> {
        let mut body = if chunk.is_empty() {
            None
        } else {
            Some(Bytes::copy_from_slice(chunk))
        };
        apply_chunk(state, c, &mut body, eos, "test-host");
        body.map(|b| b.to_vec()).unwrap_or_default()
    }

    fn enabled() -> BodyScanState {
        BodyScanState {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_mask_token_constant_is_hardcoded() {
        assert_eq!(MASK_TOKEN, b"[redacted]");
    }

    #[test]
    fn test_disabled_passthrough() {
        let c = scanner();
        let mut s = BodyScanState::default(); // enabled=false
        let out = run(&mut s, &c, b"AKIAABCDEFGHIJKLMNOP", true);
        assert_eq!(out, b"AKIAABCDEFGHIJKLMNOP");
    }

    #[test]
    fn test_stack_trace_python_traceback_detected() {
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"oops: Traceback (most recent call last) here", true);
        assert!(out.windows(MASK_TOKEN.len()).any(|w| w == MASK_TOKEN));
        assert!(!out.windows(8).any(|w| w == b"Tracebac"));
    }

    #[test]
    fn test_stack_trace_java_at_pattern_anchored_multiline() {
        let c = scanner();
        let mut s = enabled();
        let body = b"some prose\n    at com.example.foo.Bar(Bar.java:42)\n";
        let out = run(&mut s, &c, body, true);
        assert!(out.windows(MASK_TOKEN.len()).any(|w| w == MASK_TOKEN));
    }

    #[test]
    fn test_stack_trace_rust_panicked_at_detected() {
        let c = scanner();
        let mut s = enabled();
        let body = b"thread 'main' panicked at src/main.rs:5";
        let out = run(&mut s, &c, body, true);
        assert!(out.windows(MASK_TOKEN.len()).any(|w| w == MASK_TOKEN));
    }

    #[test]
    fn test_secret_aws_access_key_redacted() {
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"key=AKIAFAKEFAKEFAKEFAKE end", true);
        assert!(!out.windows(20).any(|w| w == b"AKIAFAKEFAKEFAKEFAKE"));
        assert!(out.windows(MASK_TOKEN.len()).any(|w| w == MASK_TOKEN));
    }

    #[test]
    fn test_secret_github_pat_redacted() {
        let c = scanner();
        let mut s = enabled();
        let pat = b"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut body: Vec<u8> = b"token=".to_vec();
        body.extend_from_slice(pat);
        body.extend_from_slice(b" end");
        let out = run(&mut s, &c, &body, true);
        assert!(!out.windows(pat.len()).any(|w| w == pat));
    }

    #[test]
    fn test_secret_jwt_redacted() {
        let c = scanner();
        let mut s = enabled();
        let body = concat!(
            "auth: eyJhbGciOiJIUzI1NiJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            " end"
        )
        .as_bytes();
        let out = run(&mut s, &c, body, true);
        assert!(out.windows(MASK_TOKEN.len()).any(|w| w == MASK_TOKEN));
    }

    #[test]
    fn test_secret_private_key_block_redacted() {
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"hi -----BEGIN RSA PRIVATE KEY----- yo", true);
        assert!(out.windows(MASK_TOKEN.len()).any(|w| w == MASK_TOKEN));
    }

    #[test]
    fn test_internal_ip_rfc1918_detected_ipv4() {
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"upstream=10.0.0.5 ok", true);
        assert!(!out.windows(8).any(|w| w == b"10.0.0.5"));
    }

    #[test]
    fn test_internal_ip_loopback_127_8_full_cidr() {
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"link http://127.8.4.1/", true);
        assert!(!out.windows(9).any(|w| w == b"127.8.4.1"));
    }

    #[test]
    fn test_internal_ip_octal_form_rejected() {
        // 0177.0.0.1 is octal for 127.0.0.1 — strict Ipv4Addr::from_str rejects.
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"weird=0177.0.0.1 here", true);
        // The literal must survive (no IP redaction on octal aliasing).
        assert!(out.windows(10).any(|w| w == b"0177.0.0.1"));
    }

    #[test]
    fn test_internal_ip_public_8_8_8_8_not_flagged() {
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"dns=8.8.8.8 ok", true);
        assert!(out.windows(7).any(|w| w == b"8.8.8.8"));
    }

    #[test]
    fn test_internal_ip_ipv6_ula_detected() {
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"v6=fd12:3456:789a::1 done", true);
        assert!(!out.windows(15).any(|w| w == b"fd12:3456:789a:"));
    }

    #[test]
    fn test_chunk_boundary_split_at_offset_1023_secret_redacted() {
        // Build a buffer that places the start of an AWS key precisely at offset 1023.
        let mut prefix = vec![b'.'; 1023];
        prefix.extend_from_slice(b"AKIAFAKEFAKEFAKEFAKE end");
        let c = scanner();
        let mut s = enabled();
        let first = run(&mut s, &c, &prefix, false);
        let second = run(&mut s, &c, b"", true);
        let combined: Vec<u8> = [first, second].concat();
        assert!(!combined.windows(20).any(|w| w == b"AKIAFAKEFAKEFAKEFAKE"));
    }

    #[test]
    fn test_chunk_boundary_split_at_offset_1024_secret_redacted() {
        let mut prefix = vec![b'.'; 1024];
        prefix.extend_from_slice(b"AKIAFAKEFAKEFAKEFAKE end");
        let c = scanner();
        let mut s = enabled();
        let first = run(&mut s, &c, &prefix, false);
        let second = run(&mut s, &c, b"", true);
        let combined: Vec<u8> = [first, second].concat();
        assert!(!combined.windows(20).any(|w| w == b"AKIAFAKEFAKEFAKEFAKE"));
    }

    #[test]
    fn test_oversize_body_forward_unscanned() {
        let c = Arc::new(CompiledScanner::build(8));
        let mut s = enabled();
        let _out1 = run(&mut s, &c, b"abcdefghijklm", true);
        // Past the ceiling: subsequent chunk forwarded unchanged.
        let out2 = run(&mut s, &c, b"AKIAFAKEFAKEFAKEFAKE", true);
        assert!(out2.windows(20).any(|w| w == b"AKIAFAKEFAKEFAKEFAKE"));
    }

    #[test]
    fn test_extra_pattern_not_supported_ac17_owns_extras() {
        // Negative assertion: CompiledScanner does not consume operator extras
        // (red-team #1). The catalog is built-in only.
        let c = scanner();
        // Body shaped like an operator-defined tag — must NOT be touched.
        let mut s = enabled();
        let out = run(&mut s, &c, b"<MY_INTERNAL_PATTERN/> ok", true);
        assert!(out.windows(22).any(|w| w == b"<MY_INTERNAL_PATTERN/>"));
    }

    #[test]
    fn test_scanner_config_hash_changes_with_field_change() {
        let a = scanner_config_hash(false, 1 << 20);
        let b = scanner_config_hash(true, 1 << 20);
        let c = scanner_config_hash(true, 2 << 20);
        assert_ne!(a, b);
        assert_ne!(b, c);
    }

    #[test]
    fn test_pattern_within_bounds_rejects_unbounded() {
        assert!(!pattern_within_bounds(r"a.*"));
        assert!(pattern_within_bounds(r"a{1,16}"));
    }

    #[test]
    fn test_byte_ceiling_flushes_pending_tail() {
        // Red-team review H1: when state.processed reaches max_body_bytes, the
        // tail buffer accumulated for boundary-straddle detection on the prior
        // chunk MUST be emitted downstream rather than dropped.
        // max_body_bytes = 1500 so chunk1 (1500 bytes, eos=false) leaves
        // state.processed = 1500 = ceiling, which fires on chunk2 entry.
        let c = Arc::new(CompiledScanner::build(1500));
        let mut s = enabled();
        let chunk1 = vec![b'.'; 1500];
        let _ = run(&mut s, &c, &chunk1, false);
        assert_eq!(s.tail.len(), KEEP_TAIL, "expected boundary tail to be retained");
        // Second chunk crosses the ceiling on entry. tail (1023 dots) MUST be
        // flushed in front of the chunk; otherwise we silently truncate.
        let chunk2 = vec![b'X'; 100];
        let out = run(&mut s, &c, &chunk2, false);
        assert_eq!(out.len(), KEEP_TAIL + chunk2.len());
        assert!(out.iter().take(KEEP_TAIL).all(|b| *b == b'.'));
        assert!(out.iter().skip(KEEP_TAIL).all(|b| *b == b'X'));
        assert!(s.tail.is_empty(), "tail must be drained after ceiling flush");
    }

    #[test]
    fn test_hits_counter_increments_on_redact() {
        // Red-team review #15 / M3: per-host counter must increment on each
        // category match so the future Prometheus surface has real data to
        // export. We use a unique host label so other tests don't pollute the
        // global counter.
        let host = "hits-counter-test.example";
        let c = scanner();
        let mut s = enabled();
        let _ = apply_chunk_with_host(
            &mut s,
            &c,
            b"oops: Traceback (most recent call last) here AKIAFAKEFAKEFAKEFAKE end",
            true,
            host,
        );
        assert!(
            hits_for(host, Category::StackTrace.as_str()) >= 1,
            "stack-trace hit not recorded"
        );
        assert!(
            hits_for(host, Category::Secret.as_str()) >= 1,
            "secret hit not recorded"
        );
    }

    fn apply_chunk_with_host(
        state: &mut BodyScanState,
        c: &Arc<CompiledScanner>,
        input: &[u8],
        eos: bool,
        host: &str,
    ) -> Vec<u8> {
        let mut body = Some(Bytes::copy_from_slice(input));
        apply_chunk(state, c, &mut body, eos, host);
        body.map_or_else(Vec::new, |b| b.to_vec())
    }

    // ---- Red-team review pass-2 regressions ----

    #[test]
    fn test_ipv4_internal_with_trailing_dotted_segment_redacted() {
        // C2: `127.0.0.1.5` previously bypassed detection because the walker
        // consumed all 11 chars; Ipv4Addr::from_str failed; walker advanced
        // past the entire span. The dot-count cap stops at 3 dots so the
        // `127.0.0.1` candidate is parsed and detected.
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"trace at 127.0.0.1.5 line 42", true);
        assert!(
            !out.windows(9).any(|w| w == b"127.0.0.1"),
            "internal IP must be redacted even when padded with trailing segment"
        );
        assert!(out.windows(MASK_TOKEN.len()).any(|w| w == MASK_TOKEN));
    }

    #[test]
    fn test_ipv4_public_passthrough_with_trailing_segment() {
        // Counter-test for C2: `8.8.8.8.5` candidate parses to 8.8.8.8 which
        // is public DNS, NOT internal — must remain unredacted.
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"upstream dns 8.8.8.8.5 ok", true);
        assert!(
            out.windows(7).any(|w| w == b"8.8.8.8"),
            "public IP must not be redacted"
        );
    }

    #[test]
    fn test_ipv6_loopback_detected() {
        // C1: `::1` is RFC 4291 loopback. Previously missed because the
        // scanner only flagged ULA `(seg[0] & 0xfe00) == 0xfc00`.
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"localhost ::1 trace", true);
        assert!(!out.windows(3).any(|w| w == b"::1"), "IPv6 loopback must be redacted");
    }

    #[test]
    fn test_ipv6_link_local_detected() {
        // C1: `fe80::/10` is unicast link-local; std stable since 1.84.
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"peer fe80::1 unreachable", true);
        assert!(
            !out.windows(7).any(|w| w == b"fe80::1"),
            "IPv6 link-local must be redacted"
        );
    }

    #[test]
    fn test_ipv6_ula_still_detected() {
        // C1 regression: the ULA path that already worked must keep working.
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"backend fc00::1 internal", true);
        assert!(
            !out.windows(7).any(|w| w == b"fc00::1"),
            "IPv6 ULA must still be redacted"
        );
    }

    #[test]
    fn test_ipv6_global_unicast_passthrough() {
        // Counter-test for C1: `2001:db8::1` is documentation prefix, NOT
        // internal — must remain unredacted.
        let c = scanner();
        let mut s = enabled();
        let out = run(&mut s, &c, b"docs 2001:db8::1 example", true);
        assert!(
            out.windows(11).any(|w| w == b"2001:db8::1"),
            "IPv6 documentation prefix must not be redacted"
        );
    }

    #[test]
    fn test_streaming_gzip_split_across_three_chunks_decoded_and_scanned() {
        // C3: a multi-chunk gzipped body MUST scan correctly. Previously each
        // chunk error before the gzip frame was complete set state.failed and
        // the rest of the response was forwarded raw. Now mid-stream errors
        // are tolerated; pending input accumulates inside DecoderChain until
        // the frame completes.
        use crate::filters::response_body_decompressor::DecoderChain;
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let plaintext = b"trace: AKIAFAKEFAKEFAKEFAKE here is the secret".repeat(20);
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&plaintext).expect("gzip write");
        let gz = enc.finish().expect("gzip finish");
        assert!(gz.len() >= 9, "gzip must produce at least header bytes");

        let third = gz.len() / 3;
        let chunk1 = gz.get(..third).unwrap_or(&[]);
        let chunk2 = gz.get(third..2 * third).unwrap_or(&[]);
        let chunk3 = gz.get(2 * third..).unwrap_or(&[]);

        let c = scanner();
        let mut s = BodyScanState {
            enabled: true,
            decoder: Some(DecoderChain::new()),
            ..BodyScanState::default()
        };

        let mut emitted = Vec::new();
        emitted.extend(run(&mut s, &c, chunk1, false));
        emitted.extend(run(&mut s, &c, chunk2, false));
        emitted.extend(run(&mut s, &c, chunk3, true));

        assert!(!s.failed, "multi-chunk gzip must not mark failed");
        assert!(
            !emitted.windows(20).any(|w| w == b"AKIAFAKEFAKEFAKEFAKE"),
            "secret must be redacted in streamed output"
        );
        assert!(emitted.windows(MASK_TOKEN.len()).any(|w| w == MASK_TOKEN));
    }

    #[test]
    fn test_corrupt_gzip_at_eos_replaces_body_empty() {
        // B3: when gzip is truly corrupt (not just incomplete) at EOS, body
        // becomes empty rather than forwarding raw bytes labeled identity.
        use crate::filters::response_body_decompressor::DecoderChain;
        let c = scanner();
        let mut s = BodyScanState {
            enabled: true,
            decoder: Some(DecoderChain::new()),
            ..BodyScanState::default()
        };
        let garbage = vec![0xffu8; 64];
        let out = run(&mut s, &c, &garbage, true);
        assert!(s.failed, "corrupt gzip at eos must mark failed");
        assert!(out.is_empty(), "body must be empty (not garbled raw bytes)");
    }

    #[test]
    fn test_processed_counter_measures_plaintext_not_compressed() {
        // PR #19 review fix: with a decoder attached, `state.processed` MUST
        // count post-decompression plaintext, not the raw upstream bytes —
        // otherwise a high-ratio gzip would dodge `max_body_bytes` (only the
        // compressed length is registered) or trip the ceiling prematurely
        // when ratio < 1. We verify by feeding a highly-redundant plaintext
        // that compresses much smaller than itself: the processed counter
        // must reflect plaintext size after the chunk is scanned.
        use crate::filters::response_body_decompressor::DecoderChain;
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let plaintext = vec![b'A'; 100 * 1024];
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&plaintext).expect("gzip write");
        let gz = enc.finish().expect("gzip finish");
        assert!(
            (gz.len() as u64) < 2 * 1024,
            "fixture: gzip must compress redundant input well, got {}",
            gz.len()
        );

        let c = Arc::new(CompiledScanner::build(1 << 20));
        let mut s = BodyScanState {
            enabled: true,
            decoder: Some(DecoderChain::new()),
            ..BodyScanState::default()
        };
        let _ = run(&mut s, &c, &gz, true);

        assert!(
            s.processed >= (plaintext.len() as u64),
            "processed must reflect plaintext bytes (≥ {}), got {}",
            plaintext.len(),
            s.processed
        );
        assert!(
            s.processed < (plaintext.len() as u64) + 1024,
            "processed must not vastly exceed plaintext len, got {}",
            s.processed
        );
    }

    #[test]
    fn test_decoder_cap_exhausted_marks_failed_mid_stream() {
        // PR #19 review fix: when DecoderChain returns CapExhausted (e.g. the
        // 4 MiB output cap fired) the scanner MUST mark state.failed = true
        // even if `eos = false`. Letting subsequent chunks through after a
        // cap fired is a fail-open (concatenated-stream bypass).
        use crate::filters::response_body_decompressor::DecoderChain;
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        // 5 MiB of zeros → tiny compressed → ratio bomb path → CapExhausted.
        let plaintext = vec![0u8; 5 * 1024 * 1024];
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&plaintext).expect("gzip write");
        let gz = enc.finish().expect("gzip finish");

        let c = Arc::new(CompiledScanner::build(1 << 30));
        let mut s = BodyScanState {
            enabled: true,
            decoder: Some(DecoderChain::new()),
            ..BodyScanState::default()
        };

        // Push the whole stream as a single mid-stream chunk (`eos = false`).
        // Cap should fire and scanner must mark failed regardless.
        let _ = run(&mut s, &c, &gz, false);
        assert!(s.failed, "CapExhausted mid-stream must set state.failed = true");
    }
}
