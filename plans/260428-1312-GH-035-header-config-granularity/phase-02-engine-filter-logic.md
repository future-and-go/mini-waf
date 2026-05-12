# Phase 02 — Engine Filter Logic

**Status:** completed
**Owner:** main agent
**Effort:** M (~120 LOC engine, +error path)

## Goal

Wire `preserve_headers` / `preserve_prefixes` into `HeaderFilter::should_strip`. Replace the hard-coded `MAX_PII_SCAN_LEN` constant + fixed pattern list with the operator-supplied `PiiConfig`. Validate operator regexes + pattern names at startup.

## Files to Modify

| File | Change |
|------|--------|
| `crates/waf-engine/src/outbound/header_filter.rs` | `HeaderFilter::new` → `HeaderFilter::try_new(&HeaderFilterConfig) -> Result<Self>`; honour preserve lists in `should_strip`; honour `pii.max_scan_bytes` + filtered patterns in `detect_pii_in_value` |
| `crates/waf-engine/src/outbound/mod.rs` | Propagate constructor error type |
| `crates/gateway/src/proxy.rs` | Construction site uses fallible builder; on failure → log + skip outbound (preserve current "fail-safe" semantics) |

## Logic Changes

### 1. `should_strip` precedence

```text
1. Empty name           → false
2. Hop-by-hop list      → false                        (pinned, never changes)
3. preserve_headers     → false   ← NEW
4. preserve_prefixes    → false   ← NEW
5. strip_exact contains → true
6. strip_prefixes match → true
7. otherwise            → false
```

CRLF strip in `filter_headers` runs **before** `should_strip`, so preserve cannot save a malformed value — this is intentional (header-injection is never legitimate).

### 2. Constructor: fallible

```rust
pub fn try_new(cfg: &HeaderFilterConfig) -> Result<Self, OutboundConfigError> {
    // ... build strip_exact, strip_prefixes (unchanged) ...

    let preserve_exact: HashSet<String> =
        cfg.preserve_headers.iter().map(|h| h.to_lowercase()).collect();
    let preserve_prefixes: Vec<String> =
        cfg.preserve_prefixes.iter().map(|p| p.to_lowercase()).collect();

    // PII pattern build — validate disable_builtin names + compile extras.
    let (pii_patterns, pii_pattern_names) = if cfg.detect_pii_in_values {
        build_pii_patterns_filtered(&cfg.pii)?
    } else {
        (Vec::new(), Vec::new())
    };

    if cfg.detect_pii_in_values && cfg.pii.max_scan_bytes == 0 {
        tracing::warn!(
            "FR-035: outbound.headers.pii.max_scan_bytes = 0 — \
             no per-value length cap; ReDoS DoS surface widened by operator choice"
        );
    }

    Ok(Self {
        strip_exact,
        strip_prefixes,
        preserve_exact,
        preserve_prefixes,
        pii_patterns,
        pii_pattern_names,
        max_pii_scan_len: cfg.pii.max_scan_bytes,
        detect_pii: cfg.detect_pii_in_values,
        strip_session_on_pii_match: cfg.strip_session_headers_on_pii_match,
    })
}
```

### 3. `build_pii_patterns_filtered`

```rust
fn build_pii_patterns_filtered(
    cfg: &PiiConfig,
) -> Result<(Vec<Regex>, Vec<String>), OutboundConfigError> {
    // Validate disable_builtin names — error on unknown.
    let valid: HashSet<&str> = PII_PATTERN_NAMES.iter().copied().collect();
    for name in &cfg.disable_builtin {
        if !valid.contains(name.as_str()) {
            return Err(OutboundConfigError::UnknownPiiPattern {
                name: name.clone(),
                valid: PII_PATTERN_NAMES.iter().map(|s| (*s).to_string()).collect(),
            });
        }
    }
    let disabled: HashSet<&str> = cfg.disable_builtin.iter().map(String::as_str).collect();

    let mut regexes: Vec<Regex> = Vec::new();
    let mut names: Vec<String> = Vec::new();

    // Built-ins, minus disabled.
    for (i, name) in PII_PATTERN_NAMES.iter().enumerate() {
        if disabled.contains(*name) { continue; }
        regexes.push(builtin_pii_regex(i)?);
        names.push((*name).to_string());
    }

    // Extras — compile, name as `custom_<index>`.
    for (i, src) in cfg.extra_patterns.iter().enumerate() {
        let r = Regex::new(src).map_err(|e| OutboundConfigError::InvalidExtraPattern {
            index: i,
            source: e.to_string(),
        })?;
        regexes.push(r);
        names.push(format!("custom_{i}"));
    }

    Ok((regexes, names))
}
```

`builtin_pii_regex(i)` returns the i-th built-in pattern (factored from existing inline array).

### 4. `detect_pii_in_value`

```rust
pub fn detect_pii_in_value(&self, value: &str) -> Option<&str> {
    if !self.detect_pii { return None; }
    if self.max_pii_scan_len > 0 && value.len() > self.max_pii_scan_len {
        return None;
    }
    for (pattern, name) in self.pii_patterns.iter().zip(self.pii_pattern_names.iter()) {
        if pattern.is_match(value) {
            return Some(name.as_str());
        }
    }
    None
}
```

(Returns `Option<&str>` — lifetime bound to `self.pii_pattern_names`. Update callers.)

### 5. Error type

Add to `crates/waf-engine/src/outbound/mod.rs`:

```rust
#[derive(thiserror::Error, Debug)]
pub enum OutboundConfigError {
    #[error("FR-035: unknown PII pattern '{name}'. Valid: {valid:?}")]
    UnknownPiiPattern { name: String, valid: Vec<String> },
    #[error("FR-035: invalid extra_patterns[{index}] regex: {source}")]
    InvalidExtraPattern { index: usize, source: String },
    #[error("FR-035: built-in PII regex compile failed: {0}")]
    BuiltinRegex(String),
}
```

### 6. Gateway construction site

Find the `HeaderFilter::new(...)` call in `crates/gateway/src/proxy.rs`. Replace with `try_new`. On error: `tracing::error!` with the message and **skip outbound filtering** for the rest of the process lifetime (preserve fail-safe behaviour: a misconfig must not break the proxy). State this explicitly in the log line.

## Implementation Steps

1. Add `OutboundConfigError` to `outbound/mod.rs` (re-export at module root).
2. Refactor `header_filter.rs` to expose pattern names as runtime data (keep `PII_PATTERN_NAMES` const, but the filter holds an owned `Vec<String>`).
3. Add `try_new`. Keep `new` as a deprecated thin wrapper or remove entirely (greenfield — remove; only one caller).
4. Update `should_strip` with preserve precedence.
5. Update `detect_pii_in_value` lifetime + cap-zero handling.
6. Update gateway call site + add error-skip log.
7. `cargo build -p waf-engine` and `cargo build -p gateway` — green.
8. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.

## Todo

- [ ] Add `OutboundConfigError`
- [ ] Factor `builtin_pii_regex(i)` helper
- [ ] Implement `build_pii_patterns_filtered`
- [ ] Replace `HeaderFilter::new` with `try_new`
- [ ] Add preserve precedence in `should_strip`
- [ ] Update `detect_pii_in_value` to use runtime cap + names
- [ ] Update gateway call site (fail-safe on error)
- [ ] Update existing call sites in tests (use `.unwrap()` only inside `#[cfg(test)]` per Iron Rule 1)
- [ ] `cargo fmt`, `cargo clippy`, `cargo build --release` — all clean

## Success Criteria

- All existing 30+ outbound tests still pass after the refactor.
- New constructor returns `Err` on invalid extra regex / unknown disable name.
- Gateway logs error and continues without filter when config is invalid.
- No `.unwrap()` / `.expect()` in production paths (Iron Rule 1).

## Risk

- Lifetime change of `detect_pii_in_value` return (`&'static str` → `&str`) ripples to one caller in `filter_headers` — straightforward, but verify clippy clean.
- Forgetting to update gateway → engine rebuild succeeds but binary fails. Cover with a workspace build at the end of the phase.

## Next

→ Phase 03: tests for the new semantics.
