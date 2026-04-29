# Phase 6 — Tests, Bench, Docs

## Context
- Design doc §11 (test plan), §13 (phase 6 outline).
- Depends on: Phases 1-5 complete.

## Why
Final gate. The previous phases each ship unit tests for their unit. This phase covers cross-cutting concerns: end-to-end behavior, perf, and the *consumer-facing contract* future FRs read.

## Goals
- E2E integration test: TOML → request → tier on ctx → policy reachable.
- Criterion bench proves classifier hot-path < 50µs at 50 rules.
- Coverage on tier code ≥ 90% (loose, not 95% gate).
- Consumer doc published for FR-005/006/009/027 implementers.

## Files
- **Create:** `crates/gateway/tests/tier_e2e.rs`
- **Create:** `crates/gateway/benches/tier_classifier_bench.rs`
- **Create:** `docs/tiered-protection.md`
- **Modify:** `docs/system-architecture.md` (add Tier flow diagram)
- **Modify:** `docs/project-changelog.md` (FR-002 entry)

## Implementation Notes

### E2E Integration Test
```
1. Load fixture TOML (4 tiers + 5 classifier rules)
2. Build registry + gateway with stub upstream
3. For each (path, method, expected_tier) tuple → send request → assert ctx.tier
4. Assert ctx.tier_policy fields match TOML
```

### Bench (criterion)
- 50 rules: 25 path-prefix, 15 path-regex, 10 host-suffix.
- 1000 random request paths.
- Assert mean < 50µs, p99 < 200µs.
- Run via `cargo bench -p gateway tier_classifier`.

### Consumer Doc (`docs/tiered-protection.md`)
Sections:
1. **Overview** — what FR-002 provides
2. **Tier semantics** — when each tier applies (link to spec §6 routes)
3. **Reading the policy in your check** — code snippet:
   ```rust
   let policy = ctx.tier_policy.clone();
   match policy.fail_mode { FailMode::Close => ..., FailMode::Open => ... }
   ```
4. **TOML schema** — copy from design doc §7
5. **Hot-reload semantics** — what guarantees readers have during a swap
6. **For FR-005 implementers** — reading `ddos_threshold_rps`
7. **For FR-006 implementers** — reading `risk_thresholds`
8. **For FR-009 implementers** — reading `cache_policy` enum variants
9. **Adding a new field to TierPolicy** — migration guide

WHY this doc: future-FR implementers need a single page; otherwise each rediscovers the API. DRY — write once.

### Architecture Doc Update
Add Tier flow diagram (Mermaid) to `docs/system-architecture.md`:
```
Request → ctx_builder → [TierPolicyRegistry.classify]
       → RequestCtx{tier, tier_policy} → checks → upstream
```

## Tests Checklist
- [ ] E2E: 4 tiers reachable
- [ ] E2E: default tier on no-match
- [ ] E2E: hot-reload mid-test changes policy
- [ ] Bench: 50-rule classify < 50µs
- [ ] `cargo tarpaulin -p gateway --include-files 'crates/gateway/src/tiered/**'` ≥ 90%
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- [ ] `cargo fmt --all -- --check` clean

## Acceptance
- All tests pass on CI.
- Bench numbers documented in PR description.
- `docs/tiered-protection.md` reviewed by another engineer (or self via `code-reviewer` agent).
- Plan status updated to `completed` in plan.md frontmatter.

## Common Pitfalls
- Bench measuring debug build → always `--release`.
- Coverage tool counting trait-impl boilerplate → use `--include-files` filter.
- Doc rotting fast — link from `docs/development-roadmap.md` so future-you finds it.
- Forgetting changelog entry → ops can't tell what shipped.

## Todo
- [ ] E2E test (4 scenarios)
- [ ] Criterion bench
- [ ] `docs/tiered-protection.md`
- [ ] Update system-architecture.md
- [ ] Update project-changelog.md
- [ ] Run full quality gate (fmt + clippy + test + bench)
- [ ] Mark all phase statuses `completed`

## Done Definition
FR-002 is shipped when:
1. All 6 phases marked `completed`
2. Plan-level Success Criteria (plan.md) all met
3. Consumer doc merged
4. Branch ready for FR-005/006/009/027 to start
