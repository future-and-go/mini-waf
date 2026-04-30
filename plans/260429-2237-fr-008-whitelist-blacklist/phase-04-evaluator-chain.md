# Phase 04 — Evaluator (Chain of Responsibility)

## Context Links
- Design: brainstorm §6 (decision pseudocode), §7 (audit fields)

## Overview
**Priority:** P0 · **Status:** complete · **Effort:** 0.5 d

Tie everything together. `evaluate(req, tier) -> AccessDecision`. Three stages run in fixed order: Host gate → Blacklist → Whitelist. **Chain of Responsibility** pattern — each stage may short-circuit; otherwise control falls through.

## Key Insights
- Order matters: Host **first** (cheapest deny), then blacklist (deny), then whitelist (allow). Short-circuit semantics give clean audit traces.
- `dry_run: true` does not change the decision returned to the gateway, but stamps `dry_run = true` on the `AccessDecision` so the Phase-0 filter can log "would-block" without actually blocking. Implementation: gateway treats `Block { dry_run: true, .. }` as `Continue` but emits the WARN log.
- `WhitelistMode` Strategy dispatch happens here, not in `AccessLists`.

## Requirements

### Functional
- `AccessDecision` enum:
  ```rust
  pub enum AccessDecision {
      Continue,                                                // run downstream
      BypassAll { matched_cidr: String },                      // skip phase-1+
      Block { reason: BlockReason, matched: String, dry_run: bool, status: u16 },
  }
  pub enum BlockReason { HostGate, IpBlacklist }
  ```
- Pseudocode (verbatim from brainstorm §6):
  ```
  fn evaluate(req, tier) -> AccessDecision:
      # 1. Host gate (deny-by-default IF list non-empty)
      if host_gate.disabled_for(tier) is false
         and not host_gate.is_allowed(tier, req.host):
          return Block { reason: HostGate, matched: req.host, dry_run, 403 }
      # 2. Blacklist
      if ip_blacklist.contains(req.client_ip):
          return Block { reason: IpBlacklist, matched: req.client_ip.to_string(), dry_run, 403 }
      # 3. Whitelist (per-tier mode)
      if ip_whitelist.contains(req.client_ip):
          match tier_modes[tier]:
              FullBypass    => BypassAll { matched_cidr: req.client_ip.to_string() }
              BlacklistOnly => Continue
      Continue
  ```
- Per-tier mode storage on `AccessLists`: `tier_modes: [WhitelistMode; 4]`, default `BlacklistOnly` (safer).

### Non-functional
- Single function ≤ 40 LoC. Branch-predictable, no allocation on the `Continue` happy path.

## Architecture

```
   ┌──────────────────────────── AccessLists ────────────────────────────┐
   │   ip_whitelist  ip_blacklist  host_gate  tier_modes[4]  dry_run     │
   └──────────────────────────────────────────────────────────────────────┘
                                  │ evaluate(ctx_view)
                                  ▼
        ┌───────────────────── evaluator.rs ──────────────────────┐
        │  HostGateStage ─► BlacklistStage ─► WhitelistStage      │  (CoR)
        └─────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                         AccessDecision (sum type)
```

The CoR is implemented as a hard-coded sequence (not a `Vec<Box<dyn Stage>>`) — KISS. The `Stage` trait is unnecessary at three stages. If we ever add a fourth (Tor in FR-042), revisit.

`ctx_view` is a borrowed snapshot:
```rust
pub struct AccessRequestView<'a> {
    pub client_ip: IpAddr,
    pub host: &'a str,
    pub tier: Tier,
}
```
This decouples evaluator from `pingora_http::RequestHeader` for unit-testability.

## Related Code Files

### Create
- `crates/waf-engine/src/access/evaluator.rs`

### Modify
- `crates/waf-engine/src/access/mod.rs` — `pub use evaluator::{AccessDecision, AccessRequestView, BlockReason};`
- `crates/waf-engine/src/access/config.rs` — `AccessLists::evaluate(&self, view: &AccessRequestView<'_>) -> AccessDecision` thin delegate.

## Implementation Steps

1. **`AccessDecision` + `BlockReason` + `AccessRequestView`** in `evaluator.rs`.
2. **`pub fn evaluate(lists: &AccessLists, view: &AccessRequestView<'_>) -> AccessDecision`** — direct CoR sequence per pseudocode.
3. **Inherent method on `AccessLists`** delegating to the free function (better discoverability for callers).
4. **Strategy enum dispatch**: `match lists.tier_modes[idx(view.tier)]`.
5. **Unit tests** (10 cases — minimum for AC coverage):
   - `t_continue_no_lists`: empty everything → `Continue`
   - `t_blacklist_v4_blocks`: bl `203.0.113.0/24`, ip `203.0.113.5` → `Block { IpBlacklist, ... }`
   - `t_blacklist_v6_blocks`: bl `2001:db8::/32`, ip `2001:db8::1` → `Block`
   - `t_whitelist_full_bypass`: wl `10.0.0.0/8`, mode `FullBypass`, ip `10.1.2.3` → `BypassAll`
   - `t_whitelist_blacklist_only`: wl `10.0.0.0/8`, mode `BlacklistOnly`, ip `10.1.2.3` → `Continue`
   - `t_blacklist_beats_whitelist`: ip in **both**, blacklist evaluated first → `Block`
   - `t_host_gate_pass`: critical=`{api.example.com}`, host `api.example.com` → `Continue`
   - `t_host_gate_block`: same gate, host `evil.com` → `Block { HostGate, ... }`
   - `t_host_gate_disabled`: medium=empty, host `evil.com` → `Continue`
   - `t_dry_run_stamp`: blacklist hit with `dry_run=true` → `Block { dry_run: true, .. }`
6. **Audit-log fields**: surface `access_decision` and `access_match` from `AccessDecision::Display` impl + a tiny `audit_fields()` helper returning `(reason_str, matched_str)`.

## Todo List
- [x] Define `AccessDecision`, `BlockReason`, `AccessRequestView`
- [x] Implement `evaluate()` per pseudocode
- [x] Implement `AccessLists::evaluate` delegate
- [x] Wire `tier_modes` and `dry_run` into `from_yaml_str`
- [x] 10 unit tests
- [x] `cargo clippy -p waf-engine -- -D warnings` clean

## Success Criteria
- 10 unit tests pass.
- Order rule (host → blacklist → whitelist) enforced by tests `t_blacklist_beats_whitelist` and a new `t_host_block_short_circuits_blacklist`.
- File ≤ 200 LoC.

## Common Pitfalls
- **Returning `Continue` on whitelist miss when blacklist already hit**: order matters — test it.
- **Forgetting `dry_run` propagation**: easy to drop the boolean. Tests must inspect the field, not just the discriminant.
- **`Block { status: u16 }` magic number**: accept `403` literally for now; if FR-002 introduces a per-tier block status later, plumb that through `tier_policy.block_status` — not in this phase.

## Risk Assessment
- Low. Pure logic, fully unit-testable.

## Security Considerations
- Blacklist evaluated **before** whitelist — a leaked whitelist IP cannot bypass an explicit blacklist entry.
- `dry_run` cannot be set per-request; only loaded from YAML — no injection vector.

## Next Steps
- Phase 05: hook the evaluator into the Pingora request pipeline.
