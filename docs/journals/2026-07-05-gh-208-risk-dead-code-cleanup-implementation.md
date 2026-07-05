# 2026-07-05 — GH-208 risk dead-code cleanup implementation

Plan: `plans/260705-0958-gh-208-risk-dead-code-cleanup/` · Branch: `fix/gh-208-risk-dead-code-cleanup` (stacked on `fix/gh-207-waf-api-config-helpers-dedupe`).

## What shipped

Behavior-preserving cleanup of the risk module, four phases:

1. **RiskKeyBuilder deleted** from `risk/store/store_trait.rs` — zero call sites outside its own two tests; both tests deleted, imports trimmed (`IpAddr` moved into the test module, `SessionId` dropped). Grep confirms zero references workspace-wide.
2. **Test-only Scorer ctors deleted** — `Scorer::with_seed` and `Scorer::with_velocity_threshold` removed from `risk/scorer.rs`. In `tests/risk_scorer_extended.rs` the seed test migrated to `Scorer::new` + `set_seed` (renamed `set_seed_then_score_allows`); the velocity-ctor test deleted outright — velocity behavior is covered by `tests/tx_velocity_integration.rs`, and no production path sets a custom threshold (YAGNI: no setter added).
3. **`force_max` unified on `reclamp()`** in `risk/store/memory.rs` — `raw_score = 100; state.reclamp();` replaces the hand-set `clamped_score = 100`, so clamping now flows through the single invariant everywhere. Redis Lua script untouched (already consistent). Covered by store conformance suite.
4. **Comment sweep** — 87 plan/phase/FR-ID process tokens across 51 files in `risk/**` and `checks/ddos/**` rewritten to describe the actual behavior or invariant (e.g. "§3.3 of the plan" → the stated best-effort drop semantics; stale "GAP" notes in `per_fp.rs` restated truthfully against current code). Comment-only: no code lines changed. Acceptance grep returns zero hits.

## Validation

- `cargo test -p waf-engine --lib risk::` 253 passed (was 255; −2 deleted builder tests); conformance 5 passed; `risk_scorer_extended` 14 passed.
- `cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean.
- Full `cargo test --workspace --no-fail-fast` compared against the known docker-gated baseline (no docker socket on this host).

## Decisions / notes

- Dropped the plan's original claim that `UpdateResult.ipv4_updated/ipv6_updated` were dead — they have 7 live read sites; ownership of any change there stays with the geoip updater work.
- `reclamp()` verified semantically identical for raw=100 (clamp bounds are 0..=100; pin logic reads `pinned_until_ms`, set separately).
