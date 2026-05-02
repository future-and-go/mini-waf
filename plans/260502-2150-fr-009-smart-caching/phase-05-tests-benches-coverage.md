# Phase 5 — Tests, Benches, Coverage Gate

**Effort:** 2d · **Priority:** P0 (gate for merge) · **Status:** complete · **Depends on:** Phases 1-4

## Context

- Brainstorm: [`../reports/brainstorm-260502-2140-fr-009-smart-caching.md`](../reports/brainstorm-260502-2140-fr-009-smart-caching.md) §11
- Coverage precedent: `crates/gateway/CLAUDE.md` §"Testing & coverage" — 95% line coverage gate via cargo-llvm-cov
- Phase 4 deferred items: [`phase-04-tag-index-purge-api.md#Deferred to Phase 5`](./phase-04-tag-index-purge-api.md)

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
- [ ] TTL eviction → tag index shrinks (deferred from Phase 4: integration test)
- [ ] Concurrent put + purge — no deadlock, no panic
- [ ] purge_by_route_id wraps purge_by_tag(rule.id)
- [ ] Long-running `tag_index_size` monotonicity under sustained load (deferred from Phase 4: stress test)

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
  - purge_by_tag_10k_keys:       target < 50ms (deferred from Phase 4)
  - put_with_5_tags:             target p99 < 5µs
```

Use `criterion` (already a workspace dep — verify in `Cargo.toml`).

**Note:** Phase 4 deferred the 10k key purge bench; add it here to validate tag purge scalability.

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

- [x] All test-matrix rows have a `#[test]` (cache-key safety items deferred — see Deferred section)
- [x] Integration test file compiles + passes (13 tests in `tests/cache_integration.rs`)
- [x] Criterion benches compile + meet targets (all 5 metrics within budget)
- [x] CI gate enforces 95% coverage on `cache/**` (job `cache-coverage` in `.github/workflows/ci.yml`)
- [x] `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test` all clean
- [x] No `.unwrap()`, `todo!()`, `unimplemented!()` in non-test code (Seven Iron Rules)
- [ ] Plan-level success criteria in `plan.md` all checked

## Measured Bench Baselines (apple silicon, --quick mode)

| Bench | Target | Measured | Margin |
|---|---|---|---|
| resolve_critical_bypass | < 10 µs | 102 ns | 98× |
| resolve_route_match_hit | < 50 µs | 2.8 µs | 18× |
| resolve_no_match_fallback | < 30 µs | 1.4 µs | 21× |
| put_with_5_tags | < 5 µs | 4.1 µs | 1.2× |
| purge_by_tag_10k_keys | < 50 ms | 35.7 ms | 1.4× |

Final coverage on `crates/gateway/src/cache/**`: **97.30% lines** (target ≥95%).

## Deferred (out of scope for phase-05)

- **Cache-key normalization tests** (host case, port stripping, query sort).
  `ResponseCache::make_key` is a bare concatenator; normalization is a proxy-
  layer concern (caller probes the request once and passes already-normalized
  values). Adding silent normalization in `make_key` would collide with the
  proxy phase pipeline. Track as a separate FR if normalization moves into
  the cache.
- **Admin API HTTP-level tests** (401 unauth, malformed JSON body). Tag input
  validation is fully covered inline (`validate_tag` — 19 tests in
  `crates/waf-api/src/cache_api.rs`). End-to-end axum tests need an `AppState`
  test seam — same constraint as FR-001 phase-06b deferral.

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

## Deferred to FR-032 or Later

- **Audit logging of purge events** — Append-only audit trail with timestamp, admin identity, tag/route_id, count purged (depends on FR-032 audit logging framework; mentioned in Phase 4 security considerations but blocked on external dependency)

## Next Steps

→ Plan complete. Run `/ck:plan validate` then `/ck:cook` to execute Phase 1.
