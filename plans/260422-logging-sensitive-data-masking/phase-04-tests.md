# Phase 04 — Tests

## Priority
P0 — ships with Phases 02 + 03.

## Objective
Prove masker correctness, prove integration doesn't leak secrets, prove no regression elsewhere.

## Files to Modify
- `crates/waf-engine/src/log_masker.rs` — add `#[cfg(test)] mod tests`
- Optionally: `crates/waf-engine/tests/log_attack_masking.rs` — integration test if feasible without full DB

## Unit Tests (in `log_masker.rs`)

Header masking:
- [ ] `authorization` header → redacted
- [ ] `Cookie` (mixed case) → redacted (case-insensitive)
- [ ] `User-Agent` → preserved
- [ ] Empty headers → empty JSON object

Body masking — JSON:
- [ ] `{"password":"hunter2","user":"alice"}` → password redacted, user kept
- [ ] Nested: `{"auth":{"token":"abc"}}` → token redacted
- [ ] Array: `[{"api_key":"k"}]` → redacted
- [ ] Malformed JSON → falls back to regex pass

Body masking — form:
- [ ] `username=a&password=b` → `password=***REDACTED***` kept

Body masking — regex:
- [ ] JWT string redacted
- [ ] `Authorization: Bearer abc.def.ghi` inside plain text → bearer value redacted
- [ ] Credit-card-shaped digits redacted

Body edge cases:
- [ ] Non-UTF8 bytes → lossy decode, no panic
- [ ] Body > `body_cap_bytes` → truncated with suffix
- [ ] `enabled: false` → `mask_body_preview` returns `None`, `mask_headers` returns untouched

Hot reload (new):
- [ ] Swap masker via `ArcSwap::store` → next `load()` sees new denylist
- [ ] `Engine::reload_log_masking` with tmp config file: adds `x-custom-secret` → header now redacted on subsequent call
- [ ] `reload_log_masking` with malformed TOML → returns Err, old masker still active (verify by masking behavior unchanged)
- [ ] `reload_log_masking` with invalid regex → returns Err, old masker still active
- [ ] Concurrent load + store loop (spawn 8 readers + 1 writer for 1s) → no panic, no torn state

## Integration Check (manual or scripted)
- [ ] Run `podman-compose up -d --build`
- [ ] Trigger an IP-blocked request with `curl -H "Authorization: Bearer xyz" -d '{"password":"p"}' ...`
- [ ] Query `attack_logs` row — confirm `request_headers.authorization == "***REDACTED***"` and `request_body` contains `"password":"***REDACTED***"`
- [ ] Confirm `security_events` rows unchanged in shape
- [ ] Hot-reload: edit `configs/*.toml` to add `x-custom-secret` → `curl -X POST http://localhost:16827/api/log-masking/reload` → trigger request with that header → confirm redacted in new row, process uptime unchanged

## Non-Regression Checks
- [ ] `cargo test --workspace` — all prior tests still green
- [ ] Grep diff: no files changed outside scope listed in plan.md
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo fmt --all -- --check`

## Todo
- [ ] Add 12+ unit tests per list above
- [ ] Run `cargo test -p waf-engine`
- [ ] Run full workspace test
- [ ] Manual integration smoke test
- [ ] Delegate final review to `code-reviewer` agent

## Success Criteria
- 100% of listed test cases pass
- No panics on malformed inputs
- Zero secrets present in `attack_logs` for test requests

## Open Questions (carry-forward)
- Do we want a metric counting redactions performed? (Out of scope for v1.)
- Should operators be able to per-host override the denylist? (Out of scope; global config only for v1.)
