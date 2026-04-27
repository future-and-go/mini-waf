# Phase 01 — Config + Masker Module

## Priority
P0 — foundational; Phase 02 depends on this.

## Objective
Add masking configuration and a pure, well-tested masker module. No wiring yet.

## Files to Create
- `crates/waf-engine/src/log_masker.rs` (~180 lines, keep under 200)

## Files to Modify
- `crates/waf-common/src/config.rs` — add `LogMaskingConfig` struct + default
- `crates/waf-common/src/config.rs` — add `log_masking: LogMaskingConfig` field to `AppConfig`
- `crates/waf-engine/src/lib.rs` (or `engine.rs` mod declarations) — `mod log_masker;`
- `crates/waf-engine/Cargo.toml` — add `regex` if not present

## Config Shape

All sensitive-field lists live in config. Defaults apply only when field omitted (so users can override with empty `[]` to disable a category).

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMaskingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Header names whose values are redacted (case-insensitive match).
    #[serde(default = "default_masked_headers")]
    pub masked_headers: Vec<String>,
    /// JSON/form keys whose values are redacted (case-insensitive match).
    #[serde(default = "default_masked_body_keys")]
    pub masked_body_keys: Vec<String>,
    /// Regex patterns applied to body text.
    #[serde(default = "default_body_regex")]
    pub body_regex_patterns: Vec<String>,
    /// Max bytes of body to store after masking.
    #[serde(default = "default_body_cap")]
    pub body_cap_bytes: usize,
    /// Watch config file with `notify` and auto-rebuild masker on change.
    #[serde(default)] // false
    pub watch_config_file: bool,
}
```

Defaults:
- `masked_headers`: `authorization, cookie, set-cookie, proxy-authorization, x-api-key, x-auth-token, x-csrf-token`
- `masked_body_keys`: `password, passwd, pwd, token, secret, api_key, access_token, refresh_token, client_secret, credit_card, cc_number, cvv, ssn`
- `body_regex_patterns`:
  - JWT: `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
  - Bearer: `(?i)bearer\s+[A-Za-z0-9._\-]+`
  - CC (loose): `\b(?:\d[ -]*?){13,19}\b`
- `body_cap_bytes`: `4096`

## Masker API (pure functions)

```rust
pub struct Masker {
    enabled: bool,
    header_set: HashSet<String>,          // lowercased
    body_key_set: HashSet<String>,        // lowercased
    body_regexes: Vec<Regex>,
    body_cap: usize,
}

impl Masker {
    pub fn from_config(cfg: &LogMaskingConfig) -> Result<Self, regex::Error>;
    pub fn mask_headers(&self, headers: &HashMap<String, String>) -> serde_json::Value;
    pub fn mask_body_preview(&self, body: &[u8], content_type: Option<&str>) -> Option<String>;
}
```

## Implementation Notes
- Header masking: iterate, lowercase key, replace value with `***REDACTED***` if in set; keep other headers verbatim.
- Body masking dispatch by `content_type`:
  - `application/json` → parse with `serde_json::from_slice`; walk tree, redact string values whose key is in `body_key_set` (case-insensitive). On parse failure → fall back to regex-only path.
  - `application/x-www-form-urlencoded` → split on `&`, mask values whose key matches.
  - anything else → treat as opaque text; regex-only pass.
- Non-UTF8 body → `String::from_utf8_lossy` before regex; truncate AFTER masking.
- If `!enabled` → `mask_headers` returns full headers JSON, `mask_body_preview` returns `None` (no body in logs when masking disabled — keep safe default).

## Todo
- [ ] Add `LogMaskingConfig` + defaults in `config.rs`
- [ ] Wire into `AppConfig` with `#[serde(default)]`
- [ ] Create `log_masker.rs` with `Masker` struct + 3 public methods
- [ ] JSON walker helper (recursive, key-case-insensitive)
- [ ] Form-urlencoded walker helper
- [ ] Compile: `cargo check -p waf-engine -p waf-common`
- [ ] Clippy clean: `cargo clippy -p waf-engine -p waf-common -- -D warnings`

## Success Criteria
- `cargo check` passes
- `Masker::from_config(&LogMaskingConfig::default())` constructs without error
- No callers yet — module is dead-code-allowed for this phase only via being referenced in Phase 02; if phase 02 is delayed, add `#[allow(dead_code)]` on the struct temporarily (remove in Phase 02)

## Risks
- Regex compile cost: construct `Masker` once at engine init, not per-request. Store on `Engine` struct.
- Regex catastrophic backtracking: all default patterns are linear; document requirement in config doc-comment.
