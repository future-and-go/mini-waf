---
name: FR-035 Header Filter — Granular Config
description: Extend FR-035 outbound header filter config beyond per-family booleans — add allowlist (preserve specific built-ins), tunable PII patterns/scan cap. Push to PR 14.
type: implementation
status: completed
created: 2026-04-28
completed: 2026-04-28
branch: feat/fr-035-header-leak-prevention
target_pr: https://github.com/future-and-go/mini-waf/pull/14
commits:
  - 8b4a8f6  # feat(outbound): granular config for FR-035 header filter
  - f12db13  # docs(plans): add FR-035 detection-hardening and config-granularity plans
scope: FR-035 config refinement only
follows: 260426-1553-fr035-header-leak-prevention, 260426-1919-GH-035-detection-hardening
blockedBy: []
blocks: []
---

# FR-035 Header Filter — Granular Config

## Why

PR 14 ships FR-035 with **per-family boolean toggles** (`strip_server_info`, `strip_debug_headers`, …). Reviewer feedback (TODO.md):

> "config file `configs/default.toml` chỉ set true/false là không đủ … user có thể thêm các header, … có thể loại bỏ các default sẵn có … user cần có quyền tinh chỉnh nhiều hơn mức độ chi tiết cao."

Translation:
- `true/false` is not enough.
- Operator must be able to **add** specific headers — *already done* via `strip_headers` / `strip_prefixes`.
- Operator must be able to **remove specific built-in defaults** — **not supported**.
- Operator wants finer control over PII detection — **not supported** (patterns + 8 KiB cap are hard-coded).

This plan closes those two gaps, surgically.

## Design Anchor (unchanged)

```
Detection cases   → hard-coded const lists in waf-engine::outbound (one per family)
Activation        → one boolean per family in HeaderFilterConfig (TOML)
Operator extras   → strip_headers / strip_prefixes (existing, additive)
Operator subtract → preserve_headers / preserve_prefixes (NEW, allowlist)
PII tuning        → extra_patterns / disable_builtin / max_scan_bytes (NEW)
```

No regex DSL. No per-route policy. No body filtering. KISS.

## What Changes

| Surface | Change |
|---------|--------|
| `waf-common::config::HeaderFilterConfig` | + `preserve_headers: Vec<String>`, + `preserve_prefixes: Vec<String>`, + `pii: PiiConfig` |
| `waf-common::config::PiiConfig` | NEW — `disable_builtin: Vec<String>`, `extra_patterns: Vec<String>`, `max_scan_bytes: usize` |
| `waf-engine::outbound::header_filter::HeaderFilter` | `should_strip` honours `preserve_*`; `detect_pii_in_value` uses configured patterns + cap; pattern compile validates extras |
| `configs/default.toml` | document new keys (commented examples) |
| Tests | + ≥ 8 unit tests covering new semantics |
| `docs/system-architecture.md` | extend FR-035 section with new keys |

**Backward compat:** every new field `#[serde(default)]`. Existing TOMLs parse unchanged; behaviour identical when new fields empty / default.

## Phases

| # | Phase | File | Status |
|---|-------|------|--------|
| 01 | Config schema extension (`HeaderFilterConfig`, `PiiConfig`, default.toml) | [phase-01-config-schema-extension.md](./phase-01-config-schema-extension.md) | completed |
| 02 | Engine filter logic (preserve allowlist, dynamic PII patterns, tunable cap) | [phase-02-engine-filter-logic.md](./phase-02-engine-filter-logic.md) | completed |
| 03 | Tests for new semantics | [phase-03-tests.md](./phase-03-tests.md) | completed |
| 04 | Build, commit, push, update PR 14 description | [phase-04-build-and-update-pr-14.md](./phase-04-build-and-update-pr-14.md) | completed |

## Key Decisions

1. **Allowlist beats family toggle.** `preserve_headers` / `preserve_prefixes` are the highest-priority rule. If a header matches both a strip rule and a preserve rule → keep.
2. **Allowlist does NOT override CRLF strip.** Header-injection is malicious regardless; `\r` / `\n` in value still drops.
3. **Allowlist does NOT override hop-by-hop preservation** — already a hard guard; preserve is layered on top.
4. **PII pattern names are stable IDs.** `disable_builtin` accepts the exact names already in `PII_PATTERN_NAMES` (`email`, `credit_card`, `ssn`, `phone`, `ipv4_private`, `jwt`, `aws_key`, `google_api_key`, `slack_token`, `github_pat`). Unknown names → startup error.
5. **`extra_patterns` validated at startup.** Invalid regex → `HeaderFilter::new` returns error (propagated through `OutboundConfig` validation). No silent dropping.
6. **`max_scan_bytes = 0` means "no cap".** Logged as a warning at startup — operator's choice.
7. **No per-family override lists.** "Disable family + use my list via `strip_headers`" already supports this. Adding 9 override lists doubles config surface for marginal value (YAGNI).
8. **Same branch / same PR.** Stack on PR 14.

## Success Criteria

- All 30+ existing outbound tests pass unchanged.
- ≥ 8 new tests covering: preserve overrides family strip; preserve overrides extras; preserve does NOT save CRLF; preserve does NOT touch hop-by-hop; `disable_builtin` removes named pattern; `extra_patterns` adds custom detection; invalid `extra_patterns` regex aborts startup; `max_scan_bytes = 0` disables cap.
- `cargo fmt --all -- --check` clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- `cargo build --release` green.
- Default-config behaviour bit-for-bit identical to PR 14 baseline.
- PR 14 description updated to list new keys.

## Risk

| Risk | Mitigation |
|------|-----------|
| Operator preserves a header that genuinely leaks (`Server`) thinking they need it | Document trade-off in `default.toml` comment + `docs/system-architecture.md`. No code change. |
| `extra_patterns` ReDoS regex | Apply same `max_scan_bytes` cap to all patterns (built-in + extra) — already the design |
| Unknown `disable_builtin` name silently ignored → operator thinks pattern off but isn't | Hard error at startup with list of valid names |
| Config bloat alienates new operators | New keys all default empty / safe; commented out in `default.toml`; existing flat-toggle UX preserved |

## Out of Scope

- Per-route / per-host outbound policy.
- Per-family override lists (alternative covered by toggle=false + extras).
- Inline TOML table form per family (`[outbound.headers.server_info]`).
- FR-033 (response body content filter) and FR-034 (JSON field redaction).
- Cluster sync of outbound config.

## Unresolved

- None. Design self-contained; PR 14 update on completion.
