---
title: "FR-008 Whitelist + Blacklist — Design Brainstorm"
type: brainstorm
date: 2026-04-29
slug: fr-008-whitelist-blacklist
requirement: FR-008 (P0)
status: design-approved
related:
  - analysis/requirements.md (FR-008, FR-007, FR-042)
  - plans/260429-1006-fr-002-tiered-protection
  - plans/260429-1311-fr-003-rule-engine
---

# FR-008 — Whitelist + Blacklist (Design)

## 1. Problem Statement

Spec line (analysis/requirements.md §3.1):

> **FR-008 — Whitelist + Blacklist** — IP/FQDN whitelist; threat intel blacklist from file; Tor exit list, bad ASN.

Spec bundles four sub-features. After scope review:

| Sub-feature | Phase-1? | Reason |
|---|---|---|
| IP/CIDR whitelist | ✅ | Core |
| IP/CIDR blacklist (file) | ✅ | Core |
| Host (FQDN) whitelist | ✅ | Reinterpreted as `Host`-header allowlist |
| Tor exit list | ❌ | Deferred to FR-042 (P1) |
| Bad ASN classification | ❌ | Deferred — overlaps FR-007 |

Why it matters: blacklist hit must be **<100 µs** at 5k req/s (NFR p99 ≤ 5 ms total budget). Wrong data structure = the whole gateway falls behind under load.

## 2. Locked Design Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **Whitelist mode is per-tier** (`full_bypass` \| `blacklist_only`) | Critical can keep checking rules even for whitelisted IPs (defense-in-depth); CatchAll can fast-path. Matches FR-002 tier policy bus. |
| D2 | **FQDN = `Host` header only** (no reverse-DNS) | DNS lookups break p99 budget; reverse-DNS is spoofable without forward-confirm. Host header is deterministic. |
| D3 | **Host whitelist = strict gate, per-tier** | Hosts not in tier list → 403. Multi-tenant control. |
| D4 | **Empty list = gate disabled** | Safety rail: typo or missing config does NOT lock out the deployment. |
| D5 | **Phase-1 feeds: IP whitelist + IP blacklist + per-tier Host whitelist** | Tor & ASN moved to follow-up plans (FR-042 / FR-007). |
| D6 | **Integration = pre-rule "Phase 0" short-circuit** | Cheapest decision first. Whitelist hit skips Phase 1+ when `full_bypass`; blacklist hit returns 403 immediately. |
| D7 | **File: single `rules/access-lists.yaml`** | One artifact, structured sections, reuses existing YAML loader pattern from FR-003. |
| D8 | **Hot-reload: notify watcher + SIGHUP, ArcSwap** | Identical pattern to FR-003 rule engine — zero new infra. |
| D9 | **Lookup DS: `ip_network_table` Patricia trie** | O(W) lookup, dual-stack v4/v6 native, sub-µs at 10k CIDR entries. |
| D10 | **Block action: HTTP 403 via existing `proxy_waf_response`** | Auditable; matches existing block UX; no new error-page code. |
| D11 | **Dual-stack IPv4 + IPv6 from day 1** | `ip_network_table` is dual-stack natively — no extra code cost; closes silent-gap risk during Attack Battle. |

## 3. Evaluated Approaches (Why we picked what we picked)

### 3a. Whitelist semantics
- **Full-bypass (skip ALL checks)** — Cloudflare-style. Fastest, but a leaked whitelist IP = free pass through SQLi/XSS detectors. Rejected as universal default.
- **Blacklist-only bypass** — safest but undermines "trust internal scanners" use-case. Rejected as universal default.
- **✅ Per-tier configurable** — Critical/High set `whitelist_mode: blacklist_only`; Medium/CatchAll set `full_bypass`. Defense-in-depth on payment paths, throughput on static assets.

### 3b. Host whitelist
- **Bypass list** — additive, safe.
- **✅ Strict gate** — chosen by user. Multi-tenant deny-by-default. Acceptable because empty list = disabled (D4).
- **Per-host mode flag** — too much schema for hackathon timeline. Rejected.

### 3c. Integration model
- **✅ Phase-0 short-circuit** — clearest semantics, lowest latency, easy to reason about in audit log.
- **Risk-score boost via FR-026** — couples to risk engine that does not exist yet. Rejected for now; can layer in later.
- **Custom rules in YAML** — abuses rule engine for static lookup; loses Patricia trie perf. Rejected.

### 3d. Lookup data structure
- **✅ Patricia/CIDR trie (`ip_network_table` 0.2)** — battle-tested, dual-stack, O(W) ≤ 128 ops.
- Linear scan — degrades when blacklist > 100 entries. Rejected.
- HashMap + Vec hybrid — two paths, more bugs. Rejected.

## 4. Architecture

```
┌─────────────────── Pingora request_filter ───────────────────┐
│                                                              │
│   ctx_builder  ──►  tier classifier (FR-002)  ──►  Phase 0   │
│                                                  ┌────────┐  │
│                                                  │ FR-008 │  │
│                                                  │ access │  │
│                                                  │ lists  │  │
│                                                  └───┬────┘  │
│                                                      │       │
│         ┌────────────────────────┬───────────────────┤       │
│         ▼                        ▼                   ▼       │
│   Host gate?                Blacklist?          Whitelist?   │
│   (per-tier list,            Patricia            Patricia    │
│    empty=disabled)           trie hit            trie hit    │
│         │                        │                   │       │
│      403 (gate)               403 block          per-tier:   │
│      pass-thru                                  full_bypass→ │
│                                                 skip Phase1+ │
│                                                 blacklist_   │
│                                                 only→Phase1  │
└──────────────────────────────────────────────────────────────┘
```

### Module layout (proposed)

```
crates/waf-engine/src/access/
├── mod.rs              ── public API: AccessLists, AccessDecision
├── config.rs           ── YAML schema + parser
├── ip_table.rs         ── thin wrapper over ip_network_table::IpNetworkTable<()>
├── host_gate.rs        ── per-tier Host whitelist (HashSet<String>)
└── reload.rs           ── notify watcher + ArcSwap<Arc<AccessLists>>
```

`crates/gateway/src/pipeline/access_phase.rs` — new Phase 0 filter implementing existing `RequestFilter` trait; runs *before* `request_filter_chain`.

## 5. YAML Schema

```yaml
# rules/access-lists.yaml
version: 1

# Global IP whitelist (CIDR or single IP, v4 + v6)
ip_whitelist:
  - 10.0.0.0/8
  - 192.168.1.5
  - 2001:db8::/32

# Global IP blacklist
ip_blacklist:
  - 203.0.113.0/24
  - 198.51.100.42

# Per-tier Host (FQDN) gate.  Empty list / missing key => gate disabled for that tier.
host_whitelist:
  critical:
    - api.example.com
    - secure.example.com
  high:
    - api.example.com
  medium: []        # disabled
  catch_all: []     # disabled

# Per-tier whitelist behavior
tier_whitelist_mode:
  critical:  blacklist_only   # still run rules even for whitelisted IPs
  high:      blacklist_only
  medium:    full_bypass
  catch_all: full_bypass
```

## 6. Decision Logic (pseudocode)

```
fn evaluate(req, tier) -> AccessDecision:
    # 1. Host gate (deny-by-default IF list non-empty)
    host_list = lists.host_whitelist[tier]
    if host_list.non_empty() and req.host not in host_list:
        return Block(reason="host_gate", status=403)

    # 2. Blacklist
    if lists.ip_blacklist.contains(req.client_ip):
        return Block(reason="ip_blacklist", status=403)

    # 3. Whitelist (per-tier mode)
    if lists.ip_whitelist.contains(req.client_ip):
        match lists.tier_whitelist_mode[tier]:
            FullBypass     => return BypassAll
            BlacklistOnly  => return Continue   # rules still run
    return Continue
```

Audit-log fields added: `access_decision`, `access_match` (CIDR or Host that matched), `access_phase: 0`.

## 7. Implementation Considerations

### Performance
- Patricia trie longest-prefix match: ≤32 ops v4, ≤128 ops v6.
- HashSet Host lookup: O(1) average; pre-lowercase Host header before insert and lookup (RFC 6125 §6.4.1 — hostnames are case-insensitive).
- ArcSwap pointer flip on reload: lock-free for readers.
- Expected p50 added latency: ~1 µs. Headroom vs 5 ms NFR is enormous.

### Safety
- **D4 enforced in tests**: missing key, empty array, malformed YAML all → gate disabled with `WARN` log.
- Reload failure (parse error) → keep previous `Arc`, log error, never crash gateway.
- No `.unwrap()` (Rule #1 of CLAUDE.md). Use `?` + `.context()` throughout.
- Host comparison case-insensitive; reject Host header with port suffix or whitespace.

### Auditability
- Every Phase-0 decision adds one entry to existing structured audit log (FR-032 path) — no new sink.
- Metrics: `waf_access_block_total{reason="host_gate|blacklist"}`, `waf_access_bypass_total{tier=...}`.

### Testing
- Unit: trie hit/miss, dual-stack, longest-prefix wins, empty-list → disabled, malformed YAML.
- Integration: full request through Pingora gateway, assert 403 + audit-log entry.
- Bench: `criterion` lookup at 1, 100, 10 000 entries — gate at <2 µs p99.
- Coverage gate: ≥90% on `crates/waf-engine/src/access/**`.

### Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Strict-gate misconfig locks out prod traffic | D4 (empty=disabled) + dry-run mode flag in YAML (`dry_run: true` logs would-block but passes) |
| Blacklist file grows unbounded | Soft cap 50 000 entries with WARN; hard reject >500 000 with parse error |
| `X-Forwarded-For` spoofing → wrong client_ip | Use existing `ctx.client_ip` already validated by FR-007 (when shipped); for now use socket peer addr + trusted-proxy list |
| YAML reload race with hot-traffic | ArcSwap guarantees readers see consistent snapshot; documented in tests |

## 8. Success Criteria

1. All YAML acceptance tests pass (8 cases: v4 hit, v6 hit, longest-prefix, empty whitelist disabled, host gate hit/miss, per-tier mode, malformed reload, hot-reload swap).
2. `cargo bench access_lookup` shows p99 ≤ 2 µs at 10k entries.
3. Hot-reload reflects file change in <1 s without dropping a request.
4. Coverage ≥90% on new `access/` module.
5. Zero clippy warnings; `cargo fmt` clean; no `.unwrap()` outside `#[cfg(test)]`.
6. Audit-log JSON contains `access_decision` and `access_match` for every Phase-0 block.
7. NFR: total p99 latency overhead unchanged within ±0.2 ms vs FR-003-only baseline.

## 9. Common Pitfalls (junior-dev callouts)

- **Linear scanning IP lists**: trivial to write, fatal at 10k entries × 5k rps. Always use a trie or interval tree for CIDR.
- **Forgetting Host header lowercasing**: `Api.Example.com` and `api.example.com` are the same host but byte-different. Lowercase on insert AND lookup.
- **Trusting `peer.client_ip()` directly**: behind a load balancer, client IP comes from `X-Forwarded-For`. Use the validated `ctx.client_ip` set by FR-007 (and never trust XFF without a trusted-proxy allowlist).
- **Locking the world on reload**: don't put the access lists behind a `RwLock`. Use `ArcSwap` so readers never block.
- **Strict-gate trap**: deny-by-default config is one typo away from a 100% outage. The `empty=disabled` rule is the seatbelt — don't remove it.
- **Skipping audit log on bypass**: even allowed/bypassed requests need a record (`decision=bypass`). Otherwise you can't debug why an attack didn't trigger.

## 10. Key Takeaways

- One feature spec line ≠ one feature. FR-008 was four sub-features; we cut Tor + ASN to other plans.
- Per-tier whitelist mode buys defense-in-depth at zero perf cost — strictly better than a global toggle.
- Patricia trie is non-negotiable for IP CIDR lookups in any hot path.
- Empty-list-disabled is the safety rail that makes deny-by-default acceptable in a 4-week hackathon.
- Reuse the FR-002 tier bus and FR-003 reload watcher — do not invent new plumbing.

## 11. Next Steps

1. Run `/ck:plan` with this report as context to produce a phased implementation plan in `plans/260429-2222-fr-008-whitelist-blacklist/`.
2. Suggested phases: schema+types → Patricia trie wrapper → Host gate → Phase-0 filter wiring → reload watcher → tests + bench → docs.
3. Add `ip_network_table = "0.2"` to `crates/waf-engine/Cargo.toml`.
4. Update `docs/tiered-protection.md` consumer doc with new `tier_whitelist_mode` field.
5. Defer follow-ups: FR-042 (Tor + reputation refresh), FR-007 (ASN), risk-score integration (FR-025/026).

## 12. Unresolved Questions

1. Does FR-007 already plan to populate `ctx.client_ip` from validated XFF, or do we need a temporary trusted-proxy allowlist in this plan?
2. Should `dry_run: true` (mitigation for strict-gate risk) be in phase-1 or follow-up? Recommend phase-1 — cheap, valuable during Attack Battle prep.
3. Maximum sensible `ip_blacklist` size for hackathon scoring? (Affects bench targets.)
4. Where should `rules/access-lists.yaml` live in the cluster sync model — synced like rules, or per-node static?

## Learn More

- [`ip_network_table` crate docs](https://docs.rs/ip_network_table) — Patricia trie API.
- [ArcSwap pattern](https://docs.rs/arc-swap) — lock-free hot-reload primitive.
- [RFC 6125 §6.4.1](https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.1) — hostname case-insensitivity.
- [Cloudflare WAF allowlist semantics](https://developers.cloudflare.com/waf/tools/ip-access-rules/) — comparison reference.
- Internal: `docs/tiered-protection.md`, `plans/260429-1006-fr-002-tiered-protection/`.
