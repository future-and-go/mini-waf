---
title: "FR-008 Whitelist + Blacklist — Implementation"
description: "Phase-0 access-control gate: per-tier IP whitelist (Patricia trie), IP blacklist, per-tier Host whitelist, hot-reload via ArcSwap. Strategy + Registry + Chain-of-Responsibility patterns. ≥90% coverage gate."
status: pending
priority: P0
effort: 3d
branch: feat/fr-008
tags: [waf, gateway, fr-008, access-control, whitelist, blacklist, hot-reload]
created: 2026-04-29
blockedBy: []
blocks: []
---

## Source
Design (locked decisions D1–D11, AC, schema, pseudocode):
[`../reports/brainstorm-260429-2222-fr-008-whitelist-blacklist.md`](../reports/brainstorm-260429-2222-fr-008-whitelist-blacklist.md)

Requirements: [`../../analysis/requirements.md`](../../analysis/requirements.md) §3.1 FR-008.

Upstream dependencies (already shipped):
- FR-002 tier system: `crates/waf-common/src/tier.rs`, `crates/gateway/src/tiered/*`
- Pipeline traits: `crates/gateway/src/pipeline/{mod.rs,request_filter_chain.rs}`
- Hot-reload pattern reference: `crates/gateway/src/tiered/tier_config_watcher.rs`

## Scope

Close FR-008 acceptance: *IP/FQDN whitelist; threat-intel blacklist from file; Tor exit list, bad ASN.*

After scope review (brainstorm §1), Phase-1 ships **three** sub-features:

| Sub-feature | This plan? |
|---|---|
| IP/CIDR whitelist (v4 + v6) | ✅ |
| IP/CIDR blacklist (file)   | ✅ |
| Per-tier Host (FQDN) whitelist | ✅ |
| Tor exit list              | ❌ deferred → FR-042 |
| Bad ASN classification     | ❌ deferred → FR-007 |

**Non-goals:** Tor feed, ASN reputation, X-Forwarded-For trust-list rewriting (uses FR-007 ctx.client_ip when shipped — see §Open Questions Q1).

## Acceptance Criteria (8 cases — brainstorm §8)

| # | Case | Verified by |
|---|------|-------------|
| AC-01 | IPv4 blacklist hit → 403 + audit entry | `tests/access_blacklist_v4.rs` |
| AC-02 | IPv6 blacklist hit → 403 + audit entry | `tests/access_blacklist_v6.rs` |
| AC-03 | Longest-prefix wins (`10.0.0.0/8` allow vs `10.1.2.0/24` deny → deny) | unit |
| AC-04 | Empty whitelist / missing key → gate disabled (D4) | unit + integration |
| AC-05 | Host-gate hit/miss (per-tier strict) → pass / 403 | integration |
| AC-06 | Per-tier whitelist mode (`full_bypass` skips Phase-1+; `blacklist_only` continues to rules) | integration |
| AC-07 | Malformed YAML on hot-reload → keep previous lists, WARN log, no crash | integration |
| AC-08 | Hot-reload swap reflected in <1 s without dropping a request | integration |

Plus NFR gates from brainstorm §8:
- p99 lookup ≤ 2 µs at 10 000 entries (`cargo bench access_lookup`)
- Coverage ≥ **90 %** on `crates/waf-engine/src/access/**` (user override of brainstorm's 90 %)
- Zero clippy warnings, no `.unwrap()` outside `#[cfg(test)]`
- p99 total-latency overhead ±0.2 ms vs FR-003-only baseline

## Design Patterns Applied

| Pattern | Where | Why |
|---|---|---|
| **Strategy** | `WhitelistMode` enum (`FullBypass`, `BlacklistOnly`) dispatched per tier | Per-tier behaviour swap without `if`-ladders; trivial to add a third mode later |
| **Registry / Repository** | `AccessLists` aggregate (ip_table + host_gate + per-tier modes) behind `Arc<ArcSwap<AccessLists>>` | Single source of truth; hot-swappable atomically |
| **Chain of Responsibility** | `evaluate()` runs Host-gate → Blacklist → Whitelist in fixed order, each stage may short-circuit | Mirrors brainstorm pseudocode; clear audit trail |
| **Observer (Watcher)** | `notify::RecommendedWatcher` + SIGHUP → reload pipeline | Reuse FR-002/FR-003 reload pattern verbatim — zero new infra |
| **Builder** | `AccessLists::from_yaml(path)?` returns a fully-built immutable snapshot | Consumers never see partially-constructed state |
| **Adapter** | `ip_table::IpCidrTable` thin wrapper over `ip_network_table::IpNetworkTable<()>` | Isolates external crate; keeps swap-ability for future change |

## Module Layout

```
crates/waf-engine/src/access/
├── mod.rs              ── public API: AccessLists, AccessDecision, WhitelistMode
├── config.rs           ── YAML schema + parser (serde) + Builder
├── ip_table.rs         ── Adapter over ip_network_table::IpNetworkTable<()>
├── host_gate.rs        ── Per-tier Host whitelist (HashMap<Tier, HashSet<String>>)
├── evaluator.rs        ── Chain-of-responsibility evaluate() entry point
└── reload.rs           ── notify watcher + ArcSwap<Arc<AccessLists>>

crates/gateway/src/pipeline/access_phase.rs
                        ── Phase-0 RequestFilter wiring
```

New dep: `ip_network_table = "0.2"` in `crates/waf-engine/Cargo.toml`.

## Phases

| # | File | Owner files | Status | ACs |
|---|------|-------------|--------|-----|
| 01 | [phase-01-schema-and-types.md](phase-01-schema-and-types.md) | `access/{mod,config}.rs`, Cargo.toml | pending | AC-04 (parse) |
| 02 | [phase-02-ip-cidr-table.md](phase-02-ip-cidr-table.md) | `access/ip_table.rs` | pending | AC-01, 02, 03 |
| 03 | [phase-03-host-gate.md](phase-03-host-gate.md) | `access/host_gate.rs` | pending | AC-04, 05 |
| 04 | [phase-04-evaluator-chain.md](phase-04-evaluator-chain.md) | `access/evaluator.rs` | pending | AC-06 |
| 05 | [phase-05-pipeline-wiring.md](phase-05-pipeline-wiring.md) | `gateway/pipeline/access_phase.rs`, `proxy.rs`, `context.rs` | done (e2e deferred to phase-07) | AC-01, 05, 06 (e2e) |
| 06 | [phase-06-hot-reload-watcher.md](phase-06-hot-reload-watcher.md) | `access/reload.rs`, `proxy.rs` | pending | AC-07, 08 |
| 07 | [phase-07-tests-bench-coverage.md](phase-07-tests-bench-coverage.md) | `crates/waf-engine/tests/access_*`, `benches/access_lookup.rs`, `crates/gateway/tests/access_e2e_*` | pending | All (verification) |
| 08 | [phase-08-docs-and-sample-yaml.md](phase-08-docs-and-sample-yaml.md) | `docs/access-lists.md`, `rules/access-lists.yaml` | pending | docs |

## Key Dependencies

- FR-002 tier system (complete) — `RequestCtx.tier` populated upstream
- Pingora request_filter chain — `RequestFilterChain` already supports register-and-iterate
- `arc-swap` already in Cargo.toml — no new dep there
- `notify` already in Cargo.toml — re-used from FR-003

## Risks & Mitigations (lifted from brainstorm §7)

| Risk | Mitigation |
|---|---|
| Strict-gate misconfig locks out prod traffic | D4 (empty=disabled) enforced in unit tests; `dry_run: true` flag (brainstorm Q2 → in-scope) |
| Blacklist file grows unbounded | Soft cap 50 000 with WARN; hard reject > 500 000 with parse error |
| XFF spoofing → wrong client_ip | Use existing builder `peer_ip` until FR-007 lands; document in `docs/access-lists.md` §Caveats |
| Reload races hot traffic | ArcSwap pointer flip — covered by AC-08 |

## Success Criteria (consolidated)

1. All 8 ACs pass (`cargo test -p waf-engine access_`, `cargo test -p gateway access_e2e`)
2. `cargo bench -p waf-engine access_lookup` reports p99 ≤ 2 µs at 10 k entries
3. `cargo llvm-cov --package waf-engine --lcov` shows ≥ 90 % on `src/access/**`
4. `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
5. `cargo fmt --all -- --check` clean
6. Zero `.unwrap()` outside `#[cfg(test)]` (verified: `! grep -nR '\.unwrap()' crates/waf-engine/src/access/`)
7. Audit-log JSON contains `access_decision` + `access_match` fields
8. Hot-reload integration test reflects file change in < 1 s

## Open Questions

1. **FR-007 client_ip handover** — does FR-007 plan to populate `RequestCtx.client_ip` post-XFF validation, or do we land a small trusted-proxy check in phase-05? (Tracked in brainstorm §12 Q1.)
2. **`dry_run` flag** — confirm in-scope for phase-1 (brainstorm §12 Q2). This plan assumes **yes**, implemented in phase-04 evaluator.
3. **Cluster sync** — does `rules/access-lists.yaml` participate in `rules/sync-config.yaml`? Default: per-node static for now (brainstorm §12 Q4).
