---
phase: 6
title: "Canary Honeypot FR-028"
status: pending
priority: P1
effort: "1d"
dependencies: [1, 5]
---

# Phase 6: Canary Honeypot — FR-028

## Overview

Configured canary paths (e.g. `/admin-test`, `/api-debug`) that no legitimate user should hit. Any access:
1. `store.force_max(key, now)` — pins all three legs of the triple to score=100 with `pinned_until_ms = now + ban_ttl`.
2. Append peer IP to FR-008 dynamic blacklist via existing `BlockIpRepo`.
3. Decision short-circuits to `Block` regardless of threshold gate.

Mirrors FR-005 phase-5 `DynamicBanTable` semantics — confessed scanner gets banned for hours, not minutes.

## Why P6 After Detection Layers

Canary is a one-shot pin: when triggered, all subsequent layers are bypassed. Adding it last among action-emitting phases ensures the pin actually has detection layers to override. Also small surface — single file, ≤100 LoC.

## Requirements

**Functional:**
- `risk.canary.paths: [/admin-test, /api-debug]` — exact-match list (case-sensitive).
- On match: `force_max(key)` + `BlockIpRepo::add(ip, ttl=canary.ban_ttl_sec)`.
- `pinned_until_ms` floors `clamped_score=100` regardless of decay until pin expires.
- Decision: `force_max` → return `Block` BEFORE threshold gate runs (§3.7 brainstorm).
- Hot-reloadable canary path list (`ArcSwap<Vec<String>>`).

**Non-functional:**
- Canary check ≤ 5µs (single hash lookup — `HashSet<&str>` over canary paths).
- Pin lookup ≤ 5µs (already in RiskState read).

## Architecture

```rust
// risk/canary.rs (≤100 LoC)
pub struct CanaryLayer {
    paths: ArcSwap<HashSet<String>>,
}

impl CanaryLayer {
    pub fn check(&self, path: &str) -> bool {
        self.paths.load().contains(path)
    }
}

// In Scorer::evaluate, before all other layers (after seed whitelist):
if self.canary.check(req.path()) {
    self.store.force_max(&key, now).await?;
    self.blocklist.add(req.peer_ip(), self.cfg.canary.ban_ttl_sec).await?;
    return Ok(WafAction::Block);
}
```

### Pin Semantics (RiskState extension)

`RiskState.pinned_until_ms: Option<i64>` already added in P1. On read: if `pinned_until_ms.map_or(false, |until| now < until)` → `clamped_score = 100`. On `force_max`: set `clamped_score=100`, `pinned_until_ms = Some(now + ban_ttl_ms)`, append `Contributor { kind: Canary, delta: 100, ts_ms: now }`.

### Why `force_max` AND `BlockIpRepo`?

- `force_max` covers the scoring/decision path (challenge layers can still see score=100 over the pin window).
- `BlockIpRepo` is the existing FR-008 cluster-shared blacklist — used by other code paths that don't go through scorer (e.g. Pingora pre-routing). Belt + suspenders: fail-closed even if scorer is bypassed.

## Related Code Files

**Create:**
- `crates/waf-engine/src/risk/canary.rs`
- `crates/waf-engine/src/risk/tests/canary.rs`

**Modify:**
- `crates/waf-engine/src/risk/mod.rs` — `pub mod canary;`
- `crates/waf-engine/src/risk/config.rs` — `canary:` section (paths, ban_ttl_sec).
- `crates/waf-engine/src/risk/scorer.rs` — call canary check FIRST after seed whitelist; on hit short-circuit Block.
- `crates/waf-engine/src/risk/store/store_trait.rs` — verify `force_max` signature complete.
- `crates/waf-engine/src/risk/store/memory.rs` — implement `force_max` (sets all three indices' shared state).
- `crates/waf-engine/src/risk/reload.rs` — watch canary section.

## Implementation Steps

1. **`CanaryLayer` struct.** `ArcSwap<HashSet<String>>` over configured paths.
2. **Hot-reload.** On config reload, swap path set.
3. **Scorer integration.** Place check AFTER seed whitelist (so internal whitelist still wins) but BEFORE all other layers. On hit: `force_max + BlockIpRepo::add + return Block`.
4. **`force_max` impl (memory backend).** Acquire write lock on shared `RiskState`; set `clamped_score=100`, `raw_score=100*tier_mult/100`, `pinned_until_ms`, append Canary contributor. Single atomic write touches all three indices because they share the `Arc`.
5. **Pin floor on read.** In `MemoryRiskStore::read`, if pinned and current < pinned_until → return state with `clamped_score=100`.
6. **`BlockIpRepo` integration.** Reuse existing FR-008 handle (already DI'd into Scorer).
7. **Tests.**
   - `canary.rs`: GET `/admin-test` → state.clamped_score=100, BlockIpRepo contains peer IP, decision=Block.
   - Pin survives decay: `force_max` then advance time by 2× half_life → score still 100 (pinned).
   - Pin expires: advance time past `pinned_until_ms` → decay applies normally.
   - Hot-reload: add `/api-debug2` to canary list → next request to that path triggers pin.
8. **Compile gates.**

## Common Pitfalls

- **Canary path matched by partial substring** — exact match only; `/admin-test/something` should NOT trigger unless explicitly listed.
- **`force_max` not propagating to all three indices** — verify shared `Arc<RwLock>` invariant from P1 still holds.
- **Pin window too short** — default `ban_ttl_sec=3600` (1h); document trade-off in deployment-guide.
- **Forgot to add to BlockIpRepo** — other code paths may bypass scorer; belt+suspenders required.

## Success Criteria

- [ ] Canary path → score=100 + IP banned + Block decision.
- [ ] Pin persists through decay window.
- [ ] Pin expiry restores normal decay.
- [ ] Hot-reload of canary path list verified.
- [ ] Canary check p99 ≤ 5µs.
- [ ] No `.unwrap()` introduced.

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Legitimate ops accidentally hits canary path | Medium | Document path list; coordinate with ops team; alert on hit |
| Canary path leaks to attackers via response | Low | Standard 403/404 page (NOT a special canary error message) |
| Pin set on wrong actor (NAT'd large org) | Medium | Triple-key max means session/fp leg gives finer granularity; `force_max` only on the specific triple seen |
| `BlockIpRepo` unavailable during pin | Low | Score pin is independent; logged; retry path |

## Verify

```bash
cargo test -p waf-engine risk::canary
cargo test -p waf-engine risk::tests::canary
# Integration smoke
curl -sv http://localhost:16880/admin-test 2>&1 | head -20
# Expect: 403 Forbidden, X-WAF-Risk-Score: 100
# Verify subsequent request from same IP also blocked (BlockIpRepo)
curl -sv http://localhost:16880/ 2>&1 | head -5
```
