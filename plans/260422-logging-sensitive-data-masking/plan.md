---
name: Logging Pipeline — Sensitive Data Masking
date: 2026-04-22
status: draft
blockedBy: []
blocks: []
---

# Plan — Mask Sensitive Data in Logging Pipeline

## Goal
Redact secrets (auth tokens, cookies, credentials, PII) from request **headers** and **body previews** before they are persisted by the logging pipeline. Feature is strictly scoped to the logging path — no effect on detection, routing, or proxying.

## Scope (hard boundaries)
- IN scope: `AttackLog` persistence path in `crates/waf-engine/src/engine.rs::log_attack`.
- IN scope: any future logging-pipeline writer that serializes headers/body.
- OUT of scope: WAF detection, rule matching, `SecurityEvent` (no body/headers stored), tracing `info!/warn!` calls that don't carry headers/body, community reporter.

## Non-Goals
- No encryption at rest (masking ≠ encryption).
- No UI-side masking changes (data is already masked when it reaches DB).
- No retroactive masking of existing rows.

## Design (summary)
1. Add `LogMaskingConfig` to `waf-common::config` — header denylist, body key denylist, regex patterns, enabled flag, body cap. **All sensitive-field definitions live in config only — no hardcoded lists inside the masker.** Defaults exist only via `#[serde(default = ...)]` fns so an empty config still ships safe defaults.
2. New module `crates/waf-engine/src/log_masker.rs` — `Masker` struct + pure methods:
   - `mask_headers(&HashMap<String,String>) -> serde_json::Value`
   - `mask_body_preview(&[u8], content_type) -> Option<String>`
3. **Hot reload**: engine holds `masker: Arc<ArcSwap<Masker>>`. Reload path rebuilds a new `Masker` from fresh config and `store()`s it — readers never block (matches `geoip.rs` pattern).
4. Reload triggers:
   - Admin API `POST /api/log-masking/reload` → re-reads config file, rebuilds masker (matches existing `POST /api/reload` pattern).
   - Optional file watcher on the config file via `notify` crate (mirrors `rules/hot_reload.rs`), gated by config flag `watch_config_file: bool` (default `false` to avoid surprise reloads).
5. Wire into `log_attack()`: `self.masker.load()` → mask headers + body → persist.
6. Migration: add `request_body` TEXT column to `attack_logs`.
7. Shipped defaults (config-overridable):
   - Masked headers: `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key`, `x-auth-token`, `x-csrf-token`
   - Masked body keys: `password`, `passwd`, `pwd`, `token`, `secret`, `api_key`, `access_token`, `refresh_token`, `client_secret`, `credit_card`, `cc_number`, `cvv`, `ssn`
   - Regex patterns: JWT, credit-card-shaped, Bearer token
8. Replacement: full value → `"***REDACTED***"`. Keep key so operators can audit which field was masked.

## Phases
| Phase | File | Status |
|-------|------|--------|
| 01 | [phase-01-config-and-masker.md](phase-01-config-and-masker.md) | todo |
| 02 | [phase-02-integrate-and-migrate.md](phase-02-integrate-and-migrate.md) | todo |
| 03 | [phase-03-hot-reload.md](phase-03-hot-reload.md) | todo |
| 04 | [phase-04-tests.md](phase-04-tests.md) | todo |

## Key Dependencies
- `serde_json`, `arc_swap`, `notify` (all already in workspace — see `engine/geoip.rs`, `engine/rules/hot_reload.rs`)
- `regex` (check: `cargo tree -p waf-engine | grep regex`) — add if missing
- No new external crates unless regex missing

## Verify (definition of done)
- `cargo fmt --all -- --check` clean
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- Unit tests cover: each default header masked, each default body key masked, regex match, disabled flag bypass, non-UTF8 body handled, malformed JSON body handled, hot-swap visible without restart
- Manual: trigger a block with `Authorization: Bearer abc.def.ghi` → DB row shows `"authorization":"***REDACTED***"`
- Manual hot-reload: edit config, `POST /api/log-masking/reload`, trigger new block → new denylist in effect, no process restart
- No changes to `SecurityEvent`, detection behavior, proxy, or rule engine (grep diff to confirm)

## Open Questions
- Should body preview be logged at all when no rule matched body? (Default: yes — needed for incident forensics.)
- Size cap for stored masked body? (Proposed: 4 KB truncated + `"...[truncated]"` suffix.)
- Case-sensitivity for header names: always lowercase-compare (HTTP headers are case-insensitive).
