# Phase 01 — Host Config & Detector Catalog

> **RED-TEAM PATCH (mandatory before implementation):**
> - **#1** Drop `body_scan_extra_patterns` field — AC-17 owns operator extras (DRY).
> - **#2** Drop `body_scan_action`, `body_scan_mask_token`, `body_scan_categories`. Hardcode module const `MASK_TOKEN: &[u8] = b"[redacted]"`.
> - **#3 / scope-#10** Drop `body_scan_max_decompress_bytes`, `body_scan_max_decompress_ratio`. Hardcode `MAX_DECOMPRESS_BYTES = 4 << 20`, `MAX_DECOMPRESS_RATIO = 100`, `MAX_TAIL_BYTES = 1024`, `MAX_PII_SCAN_LEN = 8 << 10`.
> - **Final HostConfig surface:** `body_scan_enabled: bool` (default `false`), `body_scan_max_body_bytes: u64` (default `1 << 20`). Two fields total.
> - Catalog patterns from this phase MUST satisfy `regex_syntax::hir::Hir::properties().maximum_len() <= 1024` (red-team #7).
> - Reference: [`reports/red-team-260428-2332-fr033-adjudication.md`](reports/red-team-260428-2332-fr033-adjudication.md).

## Context Links
- Research: `research/researcher-01-fr033-best-practices-and-attacks.md` §2 (pattern catalogs), §7 (standards)
- Existing reference: `crates/waf-common/src/types.rs` lines 143–235 (`HostConfig`)
- AC-17 mirror: `crates/gateway/src/filters/response_body_mask_filter.rs` (`CompiledMask::build`)
- CLAUDE.md: Seven Iron Rules — NO unwrap, NO panic shorthand

## Overview
- **Priority:** P0 (blocks all subsequent phases)
- **Status:** completed 2026-04-28
- Append FR-033 fields to `HostConfig`; define detector data structures and built-in pattern catalogs as `OnceLock` static. No I/O, no async, pure types + compile.

### Deviations
- HostConfig: `body_scan_enabled` + `body_scan_max_body_bytes` only (red-team scope cuts); all other params hardcoded as module constants.
- No separate `ScanAction`/`BodyScanCategories` structs created in HostConfig; scanner owns those internally.

## Key Insights
- AC-17's `internal_patterns: Vec<String>` is operator-supplied; FR-033 adds **built-in** catalogs that don't require operators to write regex.
- Per research §1, prefer `aho_corasick` for literal multipattern (stack-trace anchors, fixed secret prefixes) over big alternations (avoids Cloudflare-2019-class ReDoS).
- Per research §6.7, FP allowlist must be operator-overridable; defaults exclude `127.0.0.1` and exclude `Authorization: Bearer` JWT-in-error-log false-positives.
- Field-append order matters for clean PR 18 merge: append AFTER PR 18's `redact_*` fields textually (semantic clean — no shared field name).

## Requirements
**Functional**
- `HostConfig` exposes per-host scan toggle, per-category enable, action choice, mask token, byte/decompression caps, optional extra patterns.
- Built-in catalog covers 4 categories: stack traces (Java/Python/Rust/Go/PHP/Node/.NET), verbose errors (SQL/file paths/framework markers/ORM), secrets (AWS/GCP/Slack/GitHub/Stripe/JWT/private key), internal IPs (RFC-1918/ULA/link-local/loopback).

**Non-functional**
- Zero `.unwrap()` outside `#[cfg(test)]`.
- Pattern compilation fail-open: invalid regex → drop + warn (mirror AC-17 line 49).
- All new types `Serialize + Deserialize` with `#[serde(default = ...)]` so existing host configs load unchanged (backwards compat).

## Architecture
```
waf-common::types::HostConfig
   └── + body_scan_enabled / body_scan_action / body_scan_categories
       + body_scan_extra_patterns / body_scan_mask_token
       + body_scan_max_body_bytes / body_scan_max_decompress_bytes / body_scan_max_decompress_ratio

waf-common::types
   └── + ScanAction { Mask, Block }
       + BodyScanCategories { stack_traces, verbose_errors, secrets, internal_ips }

gateway::filters::response_body_content_scanner (NEW, phase-03)
   └── CompiledScanner { ac: AhoCorasick, regex_set: RegexSet, ip_scanner, mask, action, ... }
       + static catalogs::{STACK_TRACE_LITERALS, VERBOSE_ERROR_LITERALS, SECRET_PATTERNS, IP_PATTERNS}
```

## Related Code Files
**Modify**
- `/Users/admin/lab/mini-waf/crates/waf-common/src/types.rs` — append `ScanAction`, `BodyScanCategories`, append fields to `HostConfig`, append default fns, append `Default::default()` initializers

**Create (data only — scanner impl in phase-03)**
- none in this phase (catalog statics live next to scanner code in phase-03)

## Implementation Steps
1. Open `crates/waf-common/src/types.rs`. After existing `body_mask_max_bytes` field (line 187), append fields:
   ```rust
   #[serde(default)]
   pub body_scan_enabled: bool,
   #[serde(default)]
   pub body_scan_action: ScanAction,
   #[serde(default)]
   pub body_scan_categories: BodyScanCategories,
   #[serde(default)]
   pub body_scan_extra_patterns: Vec<String>,
   #[serde(default = "default_scan_mask_token")]
   pub body_scan_mask_token: String,
   #[serde(default = "default_scan_max_body_bytes")]
   pub body_scan_max_body_bytes: u64,
   #[serde(default = "default_scan_max_decompress_bytes")]
   pub body_scan_max_decompress_bytes: u64,
   #[serde(default = "default_scan_max_decompress_ratio")]
   pub body_scan_max_decompress_ratio: u32,
   ```
2. Append default fns (mirror line 198 style):
   - `default_scan_mask_token()` → `"[redacted]"` (research §6.4 — TBD format, default chosen here)
   - `default_scan_max_body_bytes()` → `1 << 20` (1 MiB; research §1, §5)
   - `default_scan_max_decompress_bytes()` → `4 << 20` (4 MiB; research §4)
   - `default_scan_max_decompress_ratio()` → `100` (research §4)
3. Append matching field initializers in `HostConfig::Default::default()` (line 207).
4. Define enums (above `HostConfig` or in a new mini-module at file end):
   ```rust
   #[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
   #[serde(rename_all = "snake_case")]
   pub enum ScanAction { #[default] Mask, Block }

   #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
   pub struct BodyScanCategories {
       #[serde(default)] pub stack_traces: bool,
       #[serde(default)] pub verbose_errors: bool,
       #[serde(default)] pub secrets: bool,
       #[serde(default)] pub internal_ips: bool,
   }
   ```
   Default = all-false (operator must opt-in per category — fail-open default).
5. Re-export `ScanAction`, `BodyScanCategories` from `crates/waf-common/src/lib.rs` (mirror existing `HostConfig` export).
6. Run `cargo check -p waf-common` then `cargo check -p gateway` to confirm no breakage in callers.
7. **Catalog statics deferred to phase-03** (lives next to scanner so it can wrap directly into `AhoCorasick` / `RegexSet`).

## Todo List
- [x] Append 2 FR-033 fields to `HostConfig` in `types.rs` (`body_scan_enabled`, `body_scan_max_body_bytes`)
- [x] Add 2 default fns matching field defaults
- [x] Append matching initializers to `Default::default()`
- [~] Add `ScanAction` enum — deferred to scanner module (scanner owns action choice)
- [~] Add `BodyScanCategories` struct — deferred to scanner module (scanner owns category toggles)
- [x] Re-export new types from `waf-common/src/lib.rs`
- [x] `cargo check -p waf-common` green
- [x] `cargo check -p gateway` green (no caller breakage)
- [x] `cargo clippy -p waf-common --all-targets -- -D warnings` green

## Success Criteria
- `cargo check --workspace` green.
- Existing host configs deserialize unchanged (serde defaults cover all new fields).
- `HostConfig::default()` returns scan-disabled (`body_scan_enabled = false`).
- No new `.unwrap()` introduced (Iron Rule #1).

## Risk Assessment
- **PR 18 textual conflict on HostConfig** (Likelihood: High, Impact: Low): both PRs append fields. Mitigation: phase-06 conflict probe; resolution is mechanical (append both blocks).
- **Default-on regret**: Mitigated — defaults all-off; operator must opt-in. Aligns with FR-001 fail-open philosophy.

## Security Considerations
- All new fields private to in-process config; no auth path. No log of operator-supplied `body_scan_extra_patterns` raw (echo only on validation failure with truncation).

## Next Steps
- Phase 02: build decompression pipeline that consumes `body_scan_max_decompress_bytes` / `body_scan_max_decompress_ratio` set here.
