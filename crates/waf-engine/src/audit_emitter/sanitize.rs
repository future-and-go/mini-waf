/// Detail-field sanitisation helper.
///
/// Applied to every `detail` string before it enters the DB or a WS broadcast:
/// 1. JSON-encodes the raw string via `serde_json` (escapes control chars,
///    double-quotes, and backslashes).
/// 2. HTML-escapes `<`, `>`, and `&` to prevent stored-XSS when the value is
///    rendered without additional escaping.
/// 3. Truncates to at most `MAX_DETAIL_BYTES` bytes at a valid UTF-8 boundary.
///
/// No new dependencies — uses the existing `serde_json` workspace dep.

/// Hard cap on the byte length of a sanitised detail string.
pub const MAX_DETAIL_BYTES: usize = 4096;

/// Sanitise a raw detail string for safe storage and broadcast.
///
/// Returns an owned `String` that is safe to embed in JSON fields and HTML.
pub fn sanitize_detail(raw: &str) -> String {
    // Step 1: JSON-encode (wraps in quotes and escapes control/special chars).
    let json_encoded = serde_json::to_string(raw).unwrap_or_else(|_| {
        // serde_json::to_string on a &str should never fail in practice,
        // but the return type forces us to handle it — fall back to empty.
        "\"\"".to_string()
    });

    // Step 2: HTML-escape the three dangerous chars.
    let html_escaped = json_encoded
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    // Step 3: Truncate at a valid UTF-8 boundary within MAX_DETAIL_BYTES.
    truncate_utf8_boundary(&html_escaped, MAX_DETAIL_BYTES)
}

/// Truncate `s` to at most `max_bytes` bytes, always at a valid UTF-8
/// character boundary (never splits a multi-byte code point).
fn truncate_utf8_boundary(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    // Walk back from max_bytes to find the nearest char boundary.
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_string_wrapped_in_json_quotes() {
        let out = sanitize_detail("hello world");
        assert_eq!(out, r#""hello world""#);
    }

    #[test]
    fn control_chars_escaped_by_json() {
        let raw = "line1\nline2\ttab";
        let out = sanitize_detail(raw);
        assert!(out.contains(r"\n"));
        assert!(out.contains(r"\t"));
    }

    #[test]
    fn html_chars_escaped() {
        let raw = "<script>alert('xss')</script>";
        let out = sanitize_detail(raw);
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
        assert!(out.contains("&lt;"));
        assert!(out.contains("&gt;"));
    }

    #[test]
    fn ampersand_escaped() {
        let raw = "foo & bar";
        let out = sanitize_detail(raw);
        assert!(!out.contains(" & "));
        assert!(out.contains("&amp;"));
    }

    #[test]
    fn truncate_at_boundary_respects_4kb_cap() {
        let raw = "x".repeat(10_000);
        let out = sanitize_detail(&raw);
        assert!(out.len() <= MAX_DETAIL_BYTES);
    }

    #[test]
    fn truncate_at_utf8_boundary_no_split() {
        // 2-byte UTF-8: é = 0xC3 0xA9
        let raw: String = "é".repeat(3000);
        let out = sanitize_detail(&raw);
        assert!(out.len() <= MAX_DETAIL_BYTES);
        // Must be valid UTF-8 after truncation
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn path_with_html_chars_safely_encoded() {
        let raw = r#"/search?q=<b>bold</b>&lang=en"#;
        let out = sanitize_detail(raw);
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
        assert!(out.contains("&lt;"));
        assert!(out.contains("&gt;"));
        assert!(out.contains("&amp;"));
    }

    #[test]
    fn empty_string_produces_empty_json() {
        let out = sanitize_detail("");
        assert_eq!(out, r#""""#);
    }

    #[test]
    fn backslash_escaped_by_json() {
        let raw = r"path\to\file";
        let out = sanitize_detail(raw);
        assert!(out.contains(r"\\"));
    }

    #[test]
    fn double_quote_escaped_by_json() {
        let raw = r#"say "hello""#;
        let out = sanitize_detail(raw);
        assert!(out.contains(r#"\""#));
    }
}
