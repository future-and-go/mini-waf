# Phase 5 — Tests, Benches, Coverage Gate

**Effort:** 2d · **Priority:** P0 (gate for merge) · **Status:** pending · **Depends on:** Phases 1-4

## Context

- Brainstorm: [`../reports/brainstorm-260502-2140-fr-009-smart-caching.md`](../reports/brainstorm-260502-2140-fr-009-smart-caching.md) §11
- Coverage precedent: `crates/gateway/CLAUDE.md` §"Testing & coverage" — 95% line coverage gate via cargo-llvm-cov

## Goal

Lock in correctness + performance. Ship coverage gate that future PRs cannot regress.

## Related Code

**Read:** all `cache/**/*.rs` from Phases 1-4

**Modify:**
- `crates/gateway/src/cache/**` — fill any inline-test gaps
- CI workflow (e.g. `.github/workflows/*`) — add llvm-cov gate for `cache/**`

**Create:**
- `crates/gateway/tests/cache_integration.rs` — end-to-end via `WafEngine` test seam (or shared test harness if FR-001 phase-06b lands)
- `crates/gateway/benches/cache_resolver_bench.rs` — decision pipeline microbench
- `crates/gateway/benches/cache_purge_bench.rs` — tag purge throughput

## Test Matrix (must-pass — audit-defensible)

### Tier-gate invariants (security)
- [ ] CRITICAL + upstream `Cache-Control: max-age=3600` → not cached
- [ ] CRITICAL + matching YAML rule with ttl=86400 → not cached
- [ ] CRITICAL + `get()` after entry inserted by tier reclassification race → returns None

### Method gate
- [ ] POST/PUT/DELETE/PATCH → bypass regardless of tier/rule

### Auth gate
- [ ] `Authorization: Bearer xyz` → bypass even on matching public route
- [ ] `Cookie: session=abc` → bypass
- [ ] No auth headers → proceed

### Route rule
- [ ] Path `/static/main.js` matches `static-assets` rule → cached at 86400s
- [ ] Path `/static/main.js` with `?v=hash` → query in key, separate entry
- [ ] Method-restricted rule rejects non-listed methods
- [ ] Host wildcard `*` matches every host
- [ ] Host exact `api.example.com` does not match `api.example.com.evil.tld`
- [ ] Rule order: first match wins
- [ ] `ttl_seconds: 0` → explicit bypass

### Upstream Cache-Control
- [ ] `no-store` → bypass
- [ ] `private` → bypass
- [ ] `max-age=N` capped by route TTL
- [ ] `Set-Cookie` in response → bypass

### Tier default fallback
- [ ] No matching rule + MEDIUM `Aggressive(300)` → cached at 300s
- [ ] No matching rule + HIGH `ShortTtl(30)` → cached at 30s

### Hot reload
- [ ] Edit `cache.yaml` → new TTL applied within debounce + 100ms
- [ ] Bad YAML (invalid regex) → prior config still serves; warn logged
- [ ] Missing file at runtime → empty ruleset, no panic
- [ ] `version: 2` → rejected

### Tag index / purge
- [ ] register N keys with tag T → keys_for_tag(T).len() == N
- [ ] purge_by_tag → all gone, other tags intact
- [ ] TTL eviction → tag index shrinks
- [ ] Concurrent put + purge — no deadlock, no panic
- [ ] purge_by_route_id wraps purge_by_tag(rule.id)

### Admin API
- [ ] Unauthenticated purge → 401
- [ ] Malformed body → 400
- [ ] Tag with `\n` → 400
- [ ] Successful purge returns `{ ok, purged, duration_ms }`

### Cache key safety
- [ ] Host case-insensitive (`Example.com` == `example.com`)
- [ ] Default port stripped (`host:80` == `host`)
- [ ] Query params sorted (`?a=1&b=2` == `?b=2&a=1`)

## Benches

```
cache_resolver_bench:
  - resolve_critical_bypass:     target p99 < 10µs
  - resolve_route_match_hit:     target p99 < 50µs
  - resolve_no_match_fallback:   target p99 < 30µs

cache_purge_bench:
  - purge_by_tag_10k_keys:       target < 50ms
  - put_with_5_tags:             target p99 < 5µs
```

Use `criterion` (already a workspace dep — verify in `Cargo.toml`).

## Coverage Gate

Mirror gateway's existing pattern in `crates/gateway/CLAUDE.md`:

```bash
cargo llvm-cov -p gateway \
  --include-build-script \
  --include-pattern 'cache/**' \
  --fail-under-lines 95
```

Add a new CI job (or extend existing gateway-coverage job) targeting `cache/**` paths. Gate fails the PR on regression.

## Implementation Steps

1. Audit Phase 1-4 inline tests; identify gaps using `cargo llvm-cov --html`.
2. Fill gaps with table-driven tests (one `#[test]` per row to keep failure messages readable).
3. Write integration tests against the `WafEngine` test seam — coordinate with FR-001 phase-06b for shared harness; if not landed, use a minimal in-process fake upstream.
4. Write criterion benches.
5. Add CI workflow update (or document the local gate in `crates/gateway/CLAUDE.md`).
6. Run full pipeline:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test -p gateway
   cargo bench -p gateway --bench cache_resolver_bench --bench cache_purge_bench
   cargo llvm-cov -p gateway --include-pattern 'cache/**' --fail-under-lines 95
   ```
7. Document bench baselines in plan.md success criteria for regression tracking.

## Todo

- [ ] All test-matrix rows have a `#[test]` (no skipped)
- [ ] Integration test file compiles + passes
- [ ] Criterion benches compile + meet targets
- [ ] CI gate enforces 95% coverage on `cache/**`
- [ ] `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test` all clean
- [ ] No `.unwrap()`, `todo!()`, `unimplemented!()` in non-test code (Seven Iron Rules)
- [ ] Plan-level success criteria in `plan.md` all checked

## Success Criteria

- 95% line coverage on `crates/gateway/src/cache/**`
- All resolver bench targets met
- Tag purge bench < 50ms for 10k keys
- Test matrix 100% pass
- Zero clippy warnings, zero fmt drift

## Risks

| Risk | Mitigation |
|---|---|
| FR-001 phase-06b test harness unavailable | Inline fake upstream in `tests/cache_integration.rs`; minimal Pingora bypass |
| Bench flakiness on CI | Use `cargo bench --no-default-features` or skip on CI by default; run locally + nightly job |
| Coverage gate flips on adjacent file edits | Tightly scope `--include-pattern 'cache/**'` |
| Hot-reload integration test relies on real fs notify | Use `tempfile::tempdir` + `tokio::time::sleep(debounce + ε)`; document timing tolerance |

## Security Considerations

- Tests are the audit trail. Any test asserting a security invariant (CRITICAL bypass, AuthGate, Set-Cookie bypass) must include a comment referencing the FR-009 AC it covers.
- Reviewers should be able to grep `// FR-009 AC-1` and find the regression guard immediately.

## Next Steps

→ Plan complete. Run `/ck:plan validate` then `/ck:cook` to execute Phase 1.
