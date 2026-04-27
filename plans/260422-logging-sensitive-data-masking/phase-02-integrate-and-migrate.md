# Phase 02 — Integrate Masker into Logging Pipeline + DB Migration

## Priority
P0 — wiring phase, depends on Phase 01.

## Objective
Populate masked headers + body preview in `AttackLog` rows. Add `request_body` column via migration. No other code paths touched.

## Files to Modify
- `crates/waf-storage/src/models.rs` — add `pub request_body: Option<String>` to `AttackLog`
- `crates/waf-storage/src/repo.rs` — extend `create_attack_log` INSERT to include new column
- `crates/waf-engine/src/engine.rs::log_attack` — populate `request_headers` + `request_body`
- `crates/waf-engine/src/engine.rs::Engine` struct — add `masker: Arc<ArcSwap<Masker>>` field (hot-swappable, lock-free — mirrors `geoip.rs`); construct in `Engine::new`
- Migration file: `crates/waf-storage/migrations/<next-number>_add_attack_log_body.sql`

## Migration SQL

```sql
-- up
ALTER TABLE attack_logs ADD COLUMN request_body TEXT;
```

Check existing migration numbering under `crates/waf-storage/migrations/` before naming. SQLite + Postgres compatibility: `ALTER TABLE ADD COLUMN` works on both; nullable default is NULL.

## Engine Integration

Construction:
```rust
// in Engine::new(...)
let masker_inner = Masker::from_config(&config.log_masking)
    .context("invalid log masking config")?;
let masker = Arc::new(ArcSwap::from_pointee(masker_inner));
```

In `log_attack`:
```rust
let masker = self.masker.load();        // Guard<Arc<Masker>>, lock-free
let request_headers = Some(masker.mask_headers(&ctx.headers));
let content_type = ctx.headers
    .iter()
    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    .map(|(_, v)| v.as_str());
let request_body = masker.mask_body_preview(&ctx.body_preview, content_type);

let log = AttackLog {
    // ... existing fields ...
    request_headers,
    request_body,
    // ...
};
```

## Files to Read for Context
- `crates/waf-storage/migrations/` — numbering convention
- `crates/waf-engine/src/engine.rs:419-467` — current `log_attack` body
- `crates/waf-engine/src/engine.rs` — `Engine::new` constructor

## Todo
- [ ] Find latest migration number, create next
- [ ] Add `request_body` column to migration
- [ ] Add field to `AttackLog` struct
- [ ] Update `create_attack_log` INSERT + bind
- [ ] Add `masker: Arc<ArcSwap<Masker>>` field to `Engine` + `pub fn swap_masker(&self, new: Masker)` helper
- [ ] Construct in `Engine::new`, propagate error
- [ ] Wire `log_attack` to call masker for headers + body
- [ ] `cargo check --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`

## Success Criteria
- Compiles cleanly, no clippy warnings
- `AttackLog` query paths (list, get) still work (no schema mismatch)
- No code outside `engine.rs`, `models.rs`, `repo.rs`, migrations, `config.rs`, `log_masker.rs` touched
- `git diff --stat` shows only files above

## Risks
- Migration ordering: SQLx offline query cache (`sqlx-data.json` / `.sqlx/`) may need regeneration — run `cargo sqlx prepare` if the project uses it. Check `.sqlx/` dir existence.
- Backward compat: old rows have `NULL` in new column — ensure `FromRow` derive handles `Option<String>` (it does).
- Performance: masker runs fire-and-forget inside `tokio::spawn`, already off hot path.

## Non-Regressions to Verify
- `log_security_event` untouched (no body/headers there anyway)
- `report_community_signal` untouched
- Rule engine, detection, proxy flow: zero changes (grep should confirm)
