---
phase: 6
title: "Bench Coverage and Docs"
status: completed
priority: P2
effort: "0.5d"
dependencies: [5]
---

# Phase 6: Bench Coverage and Docs

## Overview

Production-readiness gates: Criterion bench (verify <5 µs hot-path budget), property-based + concurrency tests, ≥90% coverage gate in CI, doc updates. Closes the FR-011 deliverable.

## Requirements

- p99 hot-path overhead < 5 µs (recorder write + 4 classifier evals).
- Line coverage ≥ 90% on `device_fp/behavior/**` enforced in CI.
- `docs/codebase-summary.md` updated with the new module.
- Cluster-mode caveat documented (open question #2).

## Architecture

```
crates/waf-engine/
├── benches/
│   └── behavior_eval.rs        (Criterion bench)
├── tests/
│   ├── behavior_acceptance.rs  (extended from Phase 3-4)
│   └── behavior_property.rs    (proptest, NEW)
└── src/device_fp/behavior/...  (#[cfg(loom)] gated test in recorder.rs)
```

## Related Code Files

- **Create:**
  - `crates/waf-engine/benches/behavior_eval.rs`
  - `crates/waf-engine/tests/behavior_property.rs`
- **Modify:**
  - `crates/waf-engine/Cargo.toml` — add `criterion`, `proptest` to `[dev-dependencies]`; add `[[bench]]` entry; add `loom` to `[target.'cfg(loom)'.dev-dependencies]`.
  - `crates/waf-engine/src/device_fp/behavior/recorder.rs` — add `#[cfg(loom)]` interleaving test.
  - `.github/workflows/ci.yml` (or equivalent) — add `cargo llvm-cov --workspace --fail-under-lines 90 -- device_fp::behavior` step. Verify path against existing CI before editing.
  - `docs/codebase-summary.md` — new section under device-fingerprinting describing the `behavior/` submodule.
  - `docs/system-architecture.md` — if it has a per-request flow diagram, add the recorder/classifier nodes.

## Implementation Steps

1. **Bench:** `behavior_eval.rs` — bench `Recorder::record` solo, then `record + 4 classifier evals` end-to-end. Pin a hot `FpKey`. Target: `record` < 1 µs, full path < 5 µs at p99 on a quiet machine. Run on a representative dev box; record numbers in the journal at end.
2. **Property tests:** `behavior_property.rs` — `proptest` strategies for random `Sample` sequences:
   - classifier never panics on any sequence.
   - emitted `risk_delta ≤ configured max` for every classifier.
   - `samples.len() ≤ WINDOW` always after any sequence of records (window invariant).
   - idempotent: same input snapshot → same output (no internal mutation in classifiers).
3. **Concurrency:** `#[cfg(loom)]` test on `Recorder::record` with two interleaved threads over the same `FpKey` — verify no lost updates and final length consistent. Gate behind `cfg(loom)` so default `cargo test` skips it.
4. **Stress:** in `behavior_acceptance.rs`, add a 1000-task × 1000-insert tokio stress test asserting final actor count and no panics.
5. **Coverage:** `cargo llvm-cov --workspace --fail-under-lines 90 --html` locally, fix gaps. Wire into CI matrix. Branch coverage spot-check via `--show-missing-lines` for each provider.
6. **Docs:** update `docs/codebase-summary.md` (≤ 800 LOC limit per project rule — keep additions ≤ 50 lines):
   - module location and ownership.
   - signal table (provider → trigger → delta → FR ref).
   - "v1 = node-local state; cluster-mode TBD" caveat with link to research §10 question #2.
7. **Sanity sweep:** `cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace`. Run from a clean build.

## Success Criteria

- [ ] Criterion bench results recorded; full eval path < 5 µs at p99.
- [ ] Property tests pass; `cargo test --release behavior_property` < 30 s.
- [ ] `loom` test passes when run with `RUSTFLAGS=--cfg loom cargo test recorder_loom`.
- [ ] CI step `cargo llvm-cov --fail-under-lines 90` passes for `device_fp/behavior/**`.
- [ ] `docs/codebase-summary.md` updated; word count remains under project cap.
- [ ] `cargo fmt --all -- --check` clean (CI gate).
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [ ] All FR-011 ACs (4) verified via integration tests.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Bench < 5 µs unmet on slower CI hardware | Run bench locally first; if CI hardware variance, pin bench to a manual `cargo bench` run rather than CI-gated. |
| Coverage gate flakes on generated code | Exclude generated files via `.cargo/llvm-cov.toml` if needed; document. |
| `proptest` shrinks expose floating-point edge cases in `regularity` | Stabilize CV math (integer-scaled) in Phase 4 if needed. |
| `loom` exponential blowup | Keep loom test minimal: 2 threads, 1 key, 2 records each. |

## Security Considerations

- Document FR-011 risk-delta caps (sum ≤ 40 across all four providers) so risk-aggregator math has a known upper bound for behavior contribution.
- Note in docs: behavioral state is **per-node**; an attacker rotating across nodes dilutes the window. Cluster mode is a follow-up plan.

## Follow-up (out of scope, capture in journal)

- Cluster-mode behavioral state via Redis (open Q #2). Requires ~+1 RTT/req — needs perf budget review.
- CV threshold tuning post red-team or shadow traffic (open Q #4).
- WAF cookie issuance for stricter `missing_referer` session identity (open Q #3).
