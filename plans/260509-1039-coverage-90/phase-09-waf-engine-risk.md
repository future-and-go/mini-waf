# Phase 09 — waf-engine: `risk/` (91→95%) + `device_fp/` mop-up → 95%

## Context Links
- Baseline: `plans/260509-1039-coverage-90/plan.md`
- Crate: `crates/waf-engine/`
- Existing: 23+ inline modules across `risk/`, `device_fp/`. `risk/` weighted line% currently **91.27%**, `device_fp/` **95.65%**.
- Recent FR-025 phase plans: `plans/260506-1329-fr-025-cumulative-risk-scoring/`, `plans/260508-1346-fr025-phase4-async-ingest/`.

## Overview
- **Priority:** P3 (lift already-strong area to ceiling)
- **Status:** pending
- **Target:** 95% line for `risk/` + `device_fp/` combined
- File ownership glob: `crates/waf-engine/src/{risk,device_fp}/**` AND new `crates/waf-engine/tests/risk_*.rs`, `device_fp_*.rs`

## Key Insights
- **Lowest in `risk/`:**
  - `store/store_trait.rs` (24 regions, **8.33%**) — trait default impls; very few callable lines.
  - `seed/mod.rs` (236 regions, **74.58%**) — seed orchestrator
  - `key.rs` (139 regions, **76.98%**) — RiskKey builder
  - `scorer.rs` (465 regions, **77.20%**) — orchestrator
  - `challenge_credit/mod.rs` (256 regions, **80.08%**)
  - `challenge_credit/secret.rs` (172 regions, **83.14%**)
  - `seed/reload.rs` (315 regions, **84.44%**)
- **Lowest in `device_fp/`:**
  - `identity/memory.rs` (223 regions, **81.17%**)
  - `device_fp/capture/tls.rs` (623 regions, **91.33%**)
  - `device_fp/reload.rs` (222 regions, **91.44%**)
  - everything else ≥ 93%.

## Requirements
- `scorer.rs`: cover every WafAction decision branch (Allow / Challenge / Block); cover seed-bypass path; cover store-error path.
- `key.rs`: cover triple-index merge strategy (IP+FP+session collisions).
- `challenge_credit/`: cover Valid / Invalid / Replay / Expired outcomes; HMAC-secret load + generate + persist.
- `store/store_trait.rs`: trait default impls invoked.
- `device_fp/identity/memory.rs`: cover LRU eviction at capacity, conflict resolution.
- `device_fp/capture/tls.rs`: missing branch coverage on malformed ClientHello variants.

## Architecture
```
waf-engine/src/
├── risk/                       (44 files, 9935 LOC, weighted 91%)
│   ├── store/store_trait.rs    ← 8% (mostly default impls)
│   ├── seed/mod.rs             ← 75%
│   ├── key.rs                  ← 77%
│   ├── scorer.rs               ← 77%
│   ├── challenge_credit/       ← 80-95%
│   ├── seed/reload.rs          ← 84%
│   └── … (remainder ≥ 90%)
└── device_fp/                  (40 files, 6339 LOC, weighted 96%)
    ├── identity/memory.rs      ← 81%
    ├── capture/tls.rs          ← 91%
    ├── reload.rs               ← 91%
    └── … (remainder ≥ 93%)
```

## Related Code Files
**Modify (inline tests):**
- `crates/waf-engine/src/risk/store/store_trait.rs` — invoke default trait methods on a no-op impl
- `crates/waf-engine/src/risk/key.rs` — collision merge cases
- `crates/waf-engine/src/risk/scorer.rs` — every gate branch
- `crates/waf-engine/src/risk/seed/mod.rs` + `seed/reload.rs`
- `crates/waf-engine/src/risk/challenge_credit/{mod,secret}.rs`
- `crates/waf-engine/src/device_fp/identity/memory.rs`
- `crates/waf-engine/src/device_fp/capture/tls.rs`
- `crates/waf-engine/src/device_fp/reload.rs`

**Create:**
- `crates/waf-engine/tests/risk_scorer_decision_matrix.rs` — Allow/Challenge/Block × seed-bypass × store-error matrix (~50 cases via parameterized table)
- `crates/waf-engine/tests/risk_key_collision_merge.rs` — IP-only / FP-only / session-only / IP+FP / IP+FP+session collision blends
- `crates/waf-engine/tests/risk_challenge_credit_outcomes.rs` — Valid/Invalid/Replay/Expired token verification, secret persistence
- `crates/waf-engine/tests/risk_seed_layer_e2e.rs` — Tor + ASN + whitelist file-driven scenarios
- `crates/waf-engine/tests/device_fp_identity_lru.rs` — eviction at capacity, conflict resolution

## Implementation Steps
1. Re-confirm baseline: `cargo llvm-cov -p waf-engine --summary-only | grep -E '(risk/|device_fp/)'`.
2. `store_trait.rs`: implement a tiny `NoopStore` in `#[cfg(test)]` (NOT a mock — a legitimate trivial impl) that uses every default method. Assert default behaviors.
3. `risk_scorer_decision_matrix.rs`: build table-driven test (`for case in CASES { ... }`) covering every combination of (score < allow / between / > challenge / > block) × (clean / has-contributor) × (seed-whitelist / seed-tor / seed-asn / no-seed). Use real `MemoryRiskStore`, real `RiskConfig`.
4. `risk_key_collision_merge.rs`: for each subset of {IP, FP, session} present, verify merged state = max(score) + union(contributors).
5. `risk_challenge_credit_outcomes.rs`:
   - Valid: issue token → verify within TTL → outcome Valid (-25 credit).
   - Invalid: tamper signature → outcome Invalid (+20).
   - Replay: verify same token twice → second is Replay (+30).
   - Expired: issue with past TTL → outcome Expired (+10).
   - Secret persist: write to tempdir, reload, verify same HMAC.
   - Secret generate: tempdir empty → generate, verify file mode 0600 on Unix.
6. `risk_seed_layer_e2e.rs`: write Tor list / ASN table / whitelist files to tempdir; reload; assert correct verdicts for each kind.
7. `device_fp_identity_lru.rs`: fill `MemoryIdentityStore` to capacity; insert one more; assert oldest evicted; concurrent insert from N tasks; assert no torn reads.
8. `device_fp/capture/tls.rs` inline: feed truncated ClientHello, missing extensions, oversized extension list — assert graceful error variants.

## Todo List
- [ ] Re-baseline `risk/` + `device_fp/` per-file
- [ ] `store/store_trait.rs` NoopStore + default-method tests
- [ ] `risk/key.rs` collision-merge inline tests
- [ ] `risk/scorer.rs` inline (every gate branch)
- [ ] `risk/seed/{mod,reload}.rs` inline mop-up
- [ ] `risk/challenge_credit/{mod,secret}.rs` inline mop-up
- [ ] `tests/risk_scorer_decision_matrix.rs` (~200 LOC, table-driven)
- [ ] `tests/risk_key_collision_merge.rs`
- [ ] `tests/risk_challenge_credit_outcomes.rs`
- [ ] `tests/risk_seed_layer_e2e.rs`
- [ ] `tests/device_fp_identity_lru.rs`
- [ ] `device_fp/capture/tls.rs` inline (malformed ClientHello variants)
- [ ] `device_fp/reload.rs` inline mop-up
- [ ] Combined `risk/` + `device_fp/` ≥ 95%
- [ ] No file > 200 LOC

## Success Criteria
- `risk/` ≥ 95%; `device_fp/` ≥ 97%.
- `scorer.rs` ≥ 90%; `key.rs` ≥ 95%; `challenge_credit/mod.rs` ≥ 92%.
- All existing FR-025 acceptance still passes.

## Risk Assessment
- **Low**: existing baseline strong; deltas are precision work.
- **Medium**: collision-merge logic in `key.rs` may surface latent bug if unequal-key blending was never properly tested. Treat any test failure here as a real bug, not a test mistake.

## Security Considerations
- Challenge-credit HMAC tests must use ephemeral secrets (never reuse).
- Replay tests must verify nonce store actually rejects — false-pass here would be a real security regression.
- Secret-file mode 0600 assertion is mandatory on Unix.

## Next Steps
- After this lands, `risk/` becomes the workspace coverage exemplar — link from CLAUDE.md as "how to test stateful subsystems."
