# Phase 03 — Header Scan + Hot-Reloadable Config

## Priority
P0 — depends on Phase 02.

## Objective
Scan all headers by default (configurable allow/denylist), cap per-value size, hot-reload config via ArcSwap + admin endpoint.

## Files to Create
- `crates/waf-engine/src/checks/sql_injection_config.rs` — `SqliScanConfig` struct + defaults

## Files to Modify
- `crates/waf-common/src/config.rs` — add `pub sqli_scan: SqliScanConfig` to `AppConfig` (imported from waf-engine? NO — keep config in waf-common). Move struct to `waf-common/src/config.rs` instead. Update: struct lives in `waf-common`, used by waf-engine.
- `crates/waf-engine/src/checks/sql_injection_scanners.rs` — add `scan_headers`
- `crates/waf-engine/src/checks/sql_injection.rs` — `SqlInjectionCheck` holds `Arc<ArcSwap<SqliScanConfig>>`
- `crates/waf-engine/src/engine.rs` — construct with config, add `reload_sqli_scan_config`
- `crates/waf-api/src/handlers.rs` — add `reload_sqli_scan` handler
- `crates/waf-api/src/server.rs` — route `POST /api/sqli-scan/reload`

## Config Shape (in `waf-common/src/config.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliScanConfig {
    #[serde(default = "default_true")] pub scan_headers: bool,
    #[serde(default = "default_header_denylist")] pub header_denylist: Vec<String>,
    /// If non-empty, ONLY these headers are scanned (overrides denylist).
    #[serde(default)]                   pub header_allowlist: Vec<String>,
    #[serde(default = "default_header_cap")] pub header_scan_cap: usize,
    #[serde(default = "default_json_cap")]   pub json_parse_cap: usize,
}
```

Defaults:
- `header_denylist`: `["content-length", "content-type", "host", "connection", "accept-encoding"]`
- `header_scan_cap`: `4096`
- `json_parse_cap`: `262144` (256 KB)

## Header Scanner

```rust
pub fn scan_headers(
    headers: &HashMap<String, String>,
    cfg: &SqliScanConfig,
    patterns: &RegexSet,
) -> Option<(String, usize)> {
    if !cfg.scan_headers { return None; }
    let allowlist: Option<HashSet<String>> = (!cfg.header_allowlist.is_empty())
        .then(|| cfg.header_allowlist.iter().map(|s| s.to_ascii_lowercase()).collect());
    let denylist: HashSet<String> = cfg.header_denylist.iter()
        .map(|s| s.to_ascii_lowercase()).collect();

    for (name, value) in headers {
        let key = name.to_ascii_lowercase();
        match &allowlist {
            Some(a) if !a.contains(&key) => continue,
            None if denylist.contains(&key) => continue,
            _ => {}
        }
        let slice = if value.len() > cfg.header_scan_cap {
            &value[..cfg.header_scan_cap]
        } else { value.as_str() };
        let m = patterns.matches(slice);
        if let Some(idx) = m.iter().next() {
            return Some((format!("header.{key}"), idx));
        }
    }
    None
}
```

Pre-build allow/deny sets once per config version (move into `Masker`-style cached struct if benchmarks show overhead — YAGNI for now, allowlist/denylist are small).

## Hot Reload

Pattern mirrors masking plan (`260422-logging-sensitive-data-masking` phase-03):
- `SqlInjectionCheck` holds `cfg: Arc<ArcSwap<SqliScanConfig>>`
- Reader: `self.cfg.load()` per `check()` call (lock-free)
- Writer: `self.cfg.store(Arc::new(new_cfg))` in engine's `reload_sqli_scan_config`
- Bad config (empty denylist + empty allowlist OK) → validation done in `SqliScanConfig::validate` called before store; on err, return 500 and keep old cfg

Admin endpoint signature matches masking:
```
POST /api/sqli-scan/reload  → 200 {"success": true, "data": "SQLi scan config reloaded"}
```

## Todo
- [x] Add `SqliScanConfig` to `waf-common/src/config.rs` + defaults
- [x] Add `sqli_scan: SqliScanConfig` field to `AppConfig` with `#[serde(default)]`
- [x] Implement `scan_headers` in `sql_injection_scanners.rs`
- [x] Thread `Arc<ArcSwap<SqliScanConfig>>` into `SqlInjectionCheck`
- [x] Wire `scan_headers` into `check()` dispatch (after query/body, before cookie fallback)
- [x] Add `Engine::reload_sqli_scan_config(&self, cfg: SqliScanConfig)` — accepts config directly (no file reload, config passed via API body)
- [x] Add API handler + route (`POST /api/sqli-scan/reload`)
- [x] Auth: reuses admin auth middleware already applied to `/api/reload`
- [x] Unit tests: allowlist precedence over denylist, default denylist effective, cap truncates
- [x] Hot-reload unit test: swap cfg → next call uses new allowlist
- [x] `cargo check --workspace`, clippy, fmt (waf-engine and waf-common pass; waf-api has unrelated admin-ui/dist missing issue)

## Files to Read for Context
- `crates/waf-engine/src/geoip.rs:20-95` — ArcSwap pattern
- `crates/waf-api/src/handlers.rs:346-349` — reload handler shape
- `crates/waf-api/src/server.rs:100-110` — route registration

## Success Criteria
- `User-Agent: '; DROP TABLE users--` → detected, `detail: "… in header.user-agent"`
- `curl -X POST /api/sqli-scan/reload` after config edit → next request uses new rules
- Failed reload → prior config still active, 500 returned
- Config field `SqliScanConfig` survives `toml::from_str` with all fields omitted (defaults apply)

## Risks
- **Config live in waf-common creates circular risk**: waf-common must NOT depend on waf-engine. Keep `SqliScanConfig` as plain data in waf-common; construction of runtime state stays in waf-engine.
- **AppState must know `config_path`**: verify present; if not, add `config_path: Arc<PathBuf>` during Phase 03 (same requirement as masking plan — coordinate if masking plan lands first)
- **Content-Length header scanned for numeric digits**: benign but noisy — denylist handles it

## Non-Regressions
- Cookie scan path still works (via existing `request_targets`; cookie lives in headers too — avoid double-scan by adding `"cookie"` to default denylist so only the dedicated cookie path runs it). Alternative: remove cookie from `request_targets` once header scan exists. Decision: **keep cookie in denylist** for v1 — preserves existing attribution string.
