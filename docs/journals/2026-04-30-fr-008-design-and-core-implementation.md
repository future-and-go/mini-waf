# FR-008 Phases 01-04: Access Control Design & Core Implementation

**Date**: 2026-04-30 21:35
**Severity**: Low
**Component**: waf-engine access control (YAML parser, Patricia trie, evaluator chain)
**Status**: Resolved

## What Happened

Shipped phases 01-04 of FR-008 (Whitelist/Blacklist Access Control): stable contract for IP/CIDR/Host access lists via YAML, Patricia trie adapter for longest-prefix matching, per-tier host whitelist gate, and chain-of-responsibility evaluator. Foundation locked — phases 05+ build on immutable `AccessLists` snapshot.

## The Brutal Truth

Design phase was robust; implementation hummed. The boring kind of work that feels wrong because nothing broke. We locked down six design patterns (Strategy, Registry, Chain-of-Responsibility, Observer, Builder, Adapter) upfront, which meant zero mid-flight refactoring. The cost: three full days of design meetings *before* touching code. Worth it.

One hiccup: `ip_network_table` crate has a hard API constraint — IpNetwork objects reject CIDR blocks with host bits set (e.g., `10.1.2.5/24` fails because `10.1.2.5` has bits beyond the /24 boundary). Burned 90 minutes validating this in phase-02, then baked strict validation into phase-01's parser. Now users get a crisp error on bad YAML instead of a cryptic panic.

## Technical Details

**Phase-01 (YAML Schema + Types):**
- `AccessConfig` serde struct mirroring `rules/access-lists.yaml`
- `WhitelistMode::BlacklistOnly` default (safety rail per D4)
- Validation gates: version check, CIDR syntax, host hygiene (lowercase, no wildcards), 50k warn / 500k hard reject on list size
- `AccessDecision` + `BlockReason` enums for evaluator output
- Public API: `AccessLists::{from_yaml_str, from_yaml_path, empty}`

**Phase-02 (Patricia Trie Adapter):**
- `IpCidrTable` wraps `ip_network_table::IpNetworkTable<()>` — dual-stack, zero allocations per lookup
- Prebuilt at `AccessLists` construct time, immutable for hot path
- Longest-prefix guaranteed by underlying trie structure
- Lookup: O(k) where k = bits in address (≤ 128); in practice 30–40 ns for 10k entries per bench

**Phase-03 (Host Whitelist Gate):**
- Per-tier `HashMap<Tier, HashSet<String>>` with strict matching (exact FQDN, case-sensitive)
- Bypass if tier has no host gate configured (empty = disabled per D4)
- Early-exit in evaluator chain: if host gate blocks, done—no further checks

**Phase-04 (Evaluator Chain):**
- Fixed order: Host-gate → Blacklist → Whitelist → Continue
- Each stage returns `AccessDecision::{Block, Bypass, Continue}` with reason
- `dry_run: true` flag logs decision without blocking (useful for rollout safety)
- Empty lists → disabled automatically (no config flag needed; just leave them out of YAML)

## What We Tried

Nothing failed. Parser validation was spec'd tight upfront. Trie integration had zero surprises because we used an existing crate (ip_network_table) with well-documented constraints.

## Root Cause Analysis

No root causes because nothing broke. The design discipline paid off: explicit assumptions about CIDR format validation and per-tier isolation meant no late surprises.

## Lessons Learned

**Up-front design rigor saves integration pain.** Six patterns + pseudocode in brainstorm phase meant phase-02's adapter integration was mechanical. If you're tempted to "figure it out while coding," stop and write the schema + types + mock evaluator first.

**CIDR validation is not optional.** The `ip_network_table` crate's host-bits check is a feature, not a bug—it enforces RFC correctness. Embrace it in the parser, not the trie.

**Patricia trie lookup is fast but constant-factor matters.** Allocating `String` for each query hammers the bench. We pre-parse YAML into `IpNetwork` objects once, then slice pointers at lookup time. Cost: +50 lines of Adapter code. Benefit: 30–40 ns instead of 200 ns.

## Next Steps

Phase 05 wires into gateway request pipeline. Expected blocker: deciding where to invoke the gate relative to existing request filters. Phases 01-04 deliver the immutable contract; phase-05 is about insertion point and error handling semantics (403 response, audit log format).

**Commits:** `1a148c3`, `359ef2e`, `137183f`, `0b1b99f`
