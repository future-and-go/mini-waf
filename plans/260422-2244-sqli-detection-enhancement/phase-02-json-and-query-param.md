# Phase 02 — JSON Body Walker + Per-Parameter Attribution

## Priority
P0 — depends on Phase 01.

## Objective
Detect SQLi inside JSON body string leaves. Attribute query-string hits to specific parameter names.

## Files to Modify
- `crates/waf-engine/src/checks/sql_injection_scanners.rs` — add `scan_json_body`, `scan_query_params`
- `crates/waf-engine/src/checks/sql_injection.rs` — integrate scanners in `check()`

## JSON Scanner Design

```rust
/// Returns (param_path, matched_value) on first hit.
/// `param_path` e.g. "body.user.credentials.password" — dot path into JSON.
pub fn scan_json_body(
    body: &[u8],
    patterns: &RegexSet,
) -> Option<(String, usize)> {  // (json_pointer-ish path, regex idx)
    if body.len() > JSON_PARSE_CAP { return None; }   // fallback to raw scan
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    walk(&v, &mut String::from("body"), patterns)
}

fn walk(v: &Value, path: &mut String, set: &RegexSet) -> Option<(String, usize)> {
    match v {
        Value::String(s) => {
            let m = set.matches(s);
            m.iter().next().map(|idx| (path.clone(), idx))
        }
        Value::Object(map) => {
            for (k, child) in map {
                let restore = path.len();
                path.push('.'); path.push_str(k);
                if let Some(hit) = walk(child, path, set) { return Some(hit); }
                path.truncate(restore);
            }
            None
        }
        Value::Array(arr) => {
            for (i, child) in arr.iter().enumerate() {
                let restore = path.len();
                use std::fmt::Write;
                let _ = write!(path, "[{i}]");
                if let Some(hit) = walk(child, path, set) { return Some(hit); }
                path.truncate(restore);
            }
            None
        }
        _ => None,  // numbers, bools, null — can't carry SQLi text
    }
}
```

- `JSON_PARSE_CAP = 256 * 1024` (256 KB)
- serde_json has built-in 128 recursion limit — relies on default; no custom `RECURSION_LIMIT` needed

## Query Param Scanner Design

```rust
pub fn scan_query_params(
    query: &str,
    patterns: &RegexSet,
) -> Option<(String, usize)> {  // (param name, regex idx)
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        let m = patterns.matches(&v);
        if let Some(idx) = m.iter().next() {
            return Some((format!("query.{k}"), idx));
        }
    }
    None
}
```

Also scan raw `k=v` string (already encoded) AND the decoded value — both are valuable (recursive URL-decode already handled upstream, but `form_urlencoded` handles `+` and `%` naturally).

## Integration in `check()`

Dispatch order (preserve fast-path for clean requests):
1. path + query blob (existing `request_targets`) — cheap
2. `scan_query_params(&ctx.query, …)` — per-param attribution if hit
3. `scan_json_body(&ctx.body_preview, …)` if `Content-Type: application/json`
4. Body fallback: existing raw body scan (kept for non-JSON)
5. Cookie (existing)

On hit: `detail` string includes precise location (`"UNION injection detected in query param 'id'"` or `"… detected in body.user.password"`).

## Files to Read for Context
- `crates/waf-engine/src/checks/mod.rs:85-150` — `request_targets` helper
- Workspace `Cargo.toml` — confirm `url` crate present (`waf-common` uses it for URL validation)

## Todo
- [x] `cargo tree -p waf-engine | grep -E "^(url|form_urlencoded)"` — verify availability
- [x] If `url` not direct dep of waf-engine, add it: `url = { workspace = true }` or copy version from waf-common
- [x] Implement `scan_json_body` with recursion + path tracking
- [x] Implement `scan_query_params`
- [x] Wire into `SqlInjectionCheck::check` preserving existing behavior as fallback
- [x] Unit tests: JSON nested hit, JSON array hit, clean JSON, malformed JSON → fallback, oversize JSON → fallback, query param attribution
- [x] Clippy + fmt clean
- [x] Add URL decode to scanners for evasion resistance (reviewer feedback)
- [x] Tests for double-encoded evasion payloads

## Success Criteria
- JSON-nested payload like `{"user":{"name":"' OR '1'='1"}}` → detected with path `body.user.name`
- Query `id=1+UNION+SELECT` → detected with `query.id`
- Malformed JSON still processed via raw fallback
- Oversize JSON (>256 KB) still processed via raw fallback
- All Phase 01 tests still pass

## Risks
- Cloning paths on every recursion step → use `&mut String` with truncate-on-backtrack as shown
- serde_json parse cost → bound by 256 KB cap; benchmark in Phase 04
- Duplicate detection (raw scan + JSON walker both match) → scanners are ordered; first-hit wins; no double-logging

## Non-Regressions
- Non-JSON bodies behave exactly as before
- Query string without `&` (single param) still detected
- Cookie / path scanning untouched
