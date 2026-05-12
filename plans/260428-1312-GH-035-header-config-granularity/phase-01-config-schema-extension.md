# Phase 01 — Config Schema Extension

**Status:** completed
**Owner:** main agent
**Effort:** S (~80 LOC config, ~30 LOC docs)

## Goal

Extend `HeaderFilterConfig` with allowlist (`preserve_headers`, `preserve_prefixes`) + nested `PiiConfig`. Update `configs/default.toml` with commented examples. No engine change yet — just types and defaults.

## Files to Modify

| File | Change |
|------|--------|
| `crates/waf-common/src/config.rs` | + `preserve_headers`, `preserve_prefixes`, `pii: PiiConfig` on `HeaderFilterConfig`; + new `PiiConfig` struct |
| `configs/default.toml` | append commented examples under `[outbound.headers]` and new `[outbound.headers.pii]` block |

## Schema (target)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderFilterConfig {
    // ── existing fields unchanged ───────────────────────────────
    pub strip_server_info: bool,
    pub strip_debug_headers: bool,
    pub strip_error_detail: bool,
    pub strip_php_fingerprint: bool,
    pub strip_aspnet_fingerprint: bool,
    pub strip_framework_fingerprint: bool,
    pub strip_cdn_internal: bool,
    pub detect_pii_in_values: bool,
    pub strip_session_headers_on_pii_match: bool,
    pub strip_headers: Vec<String>,
    pub strip_prefixes: Vec<String>,

    /// NEW — Headers preserved even when matched by an active family
    /// toggle or an extras list. Case-insensitive exact match.
    /// Beats every strip rule EXCEPT the unconditional CRLF strip
    /// and the always-on hop-by-hop guard.
    #[serde(default)]
    pub preserve_headers: Vec<String>,

    /// NEW — Header-name prefixes to preserve. Same precedence rules
    /// as `preserve_headers`. Case-insensitive.
    #[serde(default)]
    pub preserve_prefixes: Vec<String>,

    /// NEW — PII regex tuning (only relevant when
    /// `detect_pii_in_values = true`).
    #[serde(default)]
    pub pii: PiiConfig,
}

/// FR-035 — PII detection tuning for response header values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiConfig {
    /// Names of built-in patterns to disable. Valid names:
    /// `email`, `credit_card`, `ssn`, `phone`, `ipv4_private`,
    /// `jwt`, `aws_key`, `google_api_key`, `slack_token`, `github_pat`.
    /// Unknown names → startup error.
    #[serde(default)]
    pub disable_builtin: Vec<String>,

    /// Additional regex patterns. Compiled once at startup;
    /// invalid pattern → startup error. Subject to the same
    /// `max_scan_bytes` cap as built-ins.
    #[serde(default)]
    pub extra_patterns: Vec<String>,

    /// Hard cap on header-value bytes scanned by PII regexes.
    /// Default 8192. `0` disables the cap (NOT recommended; logged
    /// as warning at startup).
    #[serde(default = "default_pii_max_scan_bytes")]
    pub max_scan_bytes: usize,
}

const fn default_pii_max_scan_bytes() -> usize { 8192 }

impl Default for PiiConfig {
    fn default() -> Self {
        Self {
            disable_builtin: Vec::new(),
            extra_patterns: Vec::new(),
            max_scan_bytes: default_pii_max_scan_bytes(),
        }
    }
}
```

`HeaderFilterConfig::default()` extended:

```rust
impl Default for HeaderFilterConfig {
    fn default() -> Self {
        Self {
            // ... existing field defaults unchanged ...
            preserve_headers: Vec::new(),
            preserve_prefixes: Vec::new(),
            pii: PiiConfig::default(),
        }
    }
}
```

## TOML changes (`configs/default.toml`)

Append under existing `[outbound.headers]` block (keep commented — outbound stays disabled by default):

```toml
# strip_headers                 = []     # Extra exact header names (case-insensitive)
# strip_prefixes                = []     # Extra header-name prefixes (case-insensitive)
#
# ── Allowlist (NEW) ──
# Headers preserved even when matched by an active family toggle or extras.
# Use to keep built-in headers your application legitimately needs to expose.
# Wins over every strip rule except the unconditional CRLF strip (RFC 9110 §5.5)
# and the hop-by-hop guard (RFC 9110 §7.6.1).
# preserve_headers              = []     # e.g. ["server"] — keep `Server` even with strip_server_info=true
# preserve_prefixes             = []     # e.g. ["x-debug-trace-id"] — keep this prefix family
#
# ── PII tuning (NEW; only relevant when detect_pii_in_values = true) ──
# [outbound.headers.pii]
# disable_builtin   = []        # Names: email | credit_card | ssn | phone | ipv4_private |
#                               # jwt | aws_key | google_api_key | slack_token | github_pat
# extra_patterns    = []        # Custom regexes, compiled at startup. Invalid → error.
# max_scan_bytes    = 8192      # Hard cap on per-value scan length (DoS guard). 0 = no cap.
```

## Implementation Steps

1. Edit `crates/waf-common/src/config.rs`:
   - Add `PiiConfig` struct + `default_pii_max_scan_bytes` helper.
   - Add the three new fields to `HeaderFilterConfig`.
   - Update `HeaderFilterConfig::default()`.
2. Edit `configs/default.toml` — append commented schema as above.
3. `cargo check -p waf-common` — verify types compile.

## Todo

- [ ] Add `PiiConfig` to `waf-common/src/config.rs`
- [ ] Extend `HeaderFilterConfig` with `preserve_headers`, `preserve_prefixes`, `pii`
- [ ] Update `Default` impl
- [ ] Append commented examples to `configs/default.toml`
- [ ] `cargo check -p waf-common` clean
- [ ] `cargo fmt -p waf-common`

## Success Criteria

- `cargo check -p waf-common` passes.
- `cargo fmt --all -- --check` clean.
- `cargo clippy -p waf-common --all-targets --all-features -- -D warnings` clean.
- Existing TOML parses without changes (verify by deserialising the unmodified `configs/default.toml`).

## Risk

- Forgetting `#[serde(default)]` on a new field → existing TOML breaks. Mitigation: every new field gets `#[serde(default)]`, covered by a deserialisation test in phase 03.

## Next

→ Phase 02: wire the new config into `HeaderFilter`.
