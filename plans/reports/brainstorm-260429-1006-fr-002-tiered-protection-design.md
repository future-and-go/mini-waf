---
title: "FR-002 Tiered Protection — Design"
date: 2026-04-29
type: brainstorm
fr: FR-002
deps: [FR-001]
consumers: [FR-005, FR-006, FR-009, FR-027]
status: design-approved
---

# FR-002 Tiered Protection — Design

## 1. Problem

Spec AC: "4 tiers: **CRITICAL / HIGH / MEDIUM / CATCH-ALL** with **distinct policies per tier**."

Decoded: FR-002 is the *policy bus* downstream features (FR-005 fail-mode, FR-006 challenge thresholds, FR-009 cache TTL, FR-027 risk cutoffs) read from. So FR-002 = (a) **classifier** (request → tier) + (b) **policy registry** (tier → policy).

## 2. Constraints

- Rust, single binary, hot-reload (FR-031 spirit), ≤5ms p99 overhead.
- Codebase already uses Strategy pattern in `crates/gateway/src/policies/` and Check pipeline in `crates/waf-engine/`.
- TOML config in `configs/default.toml` is the canonical app-config surface.

## 3. Decisions (locked w/ user)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Classifier inputs = path + host + method + header | Flexibility for hackathon attack scenarios; cheap to support. |
| D2 | Storage = TOML in `configs/default.toml` (`[tiered_protection]`) | Single binary, single config; reuses existing loader & file watcher. |
| D3 | Pattern = **Strategy + Registry** (`Arc<TierPolicyRegistry>` w/ `ArcSwap`) | Mirrors `policies/` module; hot-swap atomic; consumers stay decoupled. |
| D4 | Hot-reload from day one | Cheap upfront; expensive retrofit; FR-031 will need it anyway. |
| D5 | `Tier` = closed enum (4 variants) | Spec fixes the four. YAGNI on 5th tier. |

## 4. Architecture

```
                ┌───────────────────────────────────────┐
HTTP request →  │  TierClassifier (priority-sorted)     │  → Tier
                │   match path | host | method | header │
                └────────────────┬──────────────────────┘
                                 ▼
                    RequestCtx { tier: Tier, ... }
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
  FR-005 DDoS              FR-009 Cache              FR-006 Challenge
  reads .fail_mode         reads .cache_policy       reads .risk_thresholds
        │                        │                        │
        └────────── Arc<TierPolicyRegistry> (ArcSwap) ────┘
                            ▲
                            │ on file change
                  configs/default.toml watcher
```

## 5. Module Layout

```
crates/waf-common/src/
  tier.rs                       # Tier enum, TierPolicy, TierClassifierRule (data types)

crates/gateway/src/tiered/
  mod.rs                        # public TieredProtectionService façade
  tier_classifier.rs            # priority-ordered matchers
  tier_policy_registry.rs       # ArcSwap<HashMap<Tier, TierPolicy>>
  tier_config_watcher.rs        # notify-based reload
```

Wire into `ctx_builder/` so `RequestCtx.tier` is set before any downstream check runs.

## 6. Data Model

```rust
// waf-common::tier
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier { Critical, High, Medium, CatchAll }

#[derive(Clone, Debug, Deserialize)]
pub struct TierPolicy {
    pub fail_mode: FailMode,            // Close | Open
    pub ddos_threshold_rps: u32,
    pub cache_policy: CachePolicy,      // NoCache | ShortTtl{ttl} | Aggressive{ttl} | Default{ttl}
    pub risk_thresholds: RiskThresholds, // allow / challenge / block cutoffs
}

#[derive(Clone, Debug, Deserialize)]
pub struct TierClassifierRule {
    pub priority: u32,                  // higher wins
    pub tier: Tier,
    pub host:    Option<HostMatch>,     // exact | suffix | regex (compiled once)
    pub path:    Option<PathMatch>,     // exact | prefix | regex
    pub method:  Option<Vec<Method>>,
    pub headers: Option<Vec<HeaderMatch>>, // (name, exact-value) — MVP
}
```

## 7. TOML Schema (snippet)

```toml
[tiered_protection]
default_tier = "catch_all"

[[tiered_protection.classifier_rules]]
priority = 100
tier     = "critical"
path     = { kind = "exact",  value = "/login" }
method   = ["POST"]

[[tiered_protection.classifier_rules]]
priority = 90
tier     = "high"
path     = { kind = "prefix", value = "/api/" }

[tiered_protection.policies.critical]
fail_mode            = "close"
ddos_threshold_rps   = 50
cache_policy         = { mode = "no_cache" }
risk_thresholds      = { allow = 20, challenge = 50, block = 70 }

# … same shape for high / medium / catch_all
```

**Validation at load:** all 4 tiers MUST have policies (`Tier::iter()` cross-check) — fail-fast on startup if missing.

## 8. Hot-Reload Mechanics

1. `notify` watcher on `configs/default.toml` (already used by rules system — reuse pattern).
2. On change → parse → validate → build new `Arc<HashMap<Tier, TierPolicy>>` → `ArcSwap::store`.
3. Readers do `arcswap.load()` → cheap `Arc::clone`. Per-request cost = 1 atomic load.
4. On parse/validation failure → keep old config, emit `tracing::warn!`. Never panic.

## 9. Patterns Applied (the "extensibility" ask)

| Pattern | Where | What it buys |
|---------|-------|--------------|
| **Strategy** | `CachePolicy`, `FailMode` enums | Each tier carries its own behavior knob; consumers branch on data not type. |
| **Registry** | `TierPolicyRegistry` | Single lookup point; new consumers (FR-006, FR-009, …) just inject the registry. |
| **Façade** | `TieredProtectionService` | One injection point in gateway; classifier+registry hidden. |
| **ArcSwap** | Hot-reload | Lock-free atomic swap; readers never block. |
| **Builder/validator** | `TierConfig::validate()` | All-tiers-present + regex-compile errors caught before swap. |

## 10. Acceptance Criteria Mapping

| AC | Implementation | Verification |
|----|----------------|--------------|
| 4 tiers | `Tier` enum (Critical/High/Medium/CatchAll) | Compile-time exhaustive match. |
| Distinct policies | `TierPolicy` struct + 4 entries required | `validate()` rejects missing tier. |
| Per-tier classifier | `TierClassifier` priority-sorted | Unit tests: each tier reachable by ≥1 rule. |
| Default fallback | `default_tier = catch_all` | Test: unmatched request → CatchAll. |
| Adapt/scale | ArcSwap hot-reload + TOML | Integration test: edit file → next request sees new policy. |

## 11. Test Plan

- **Unit** — classifier priority ordering, host/path/method/header matchers, default fallback, validation rejects missing tier.
- **Unit** — ArcSwap atomic swap doesn't tear in-flight reads (concurrent loom or quickcheck-style).
- **Integration** — `POST /login` → `RequestCtx.tier == Critical`; `GET /static/x.css` → `Medium`; `GET /unknown` → `CatchAll`.
- **Integration** — touch config file, sleep 50ms, assert new policy active without restart.
- **Bench** — classifier hot-path < 50µs for 50-rule config (well within 5ms budget).

## 12. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Regex on hot-path = slow | Pre-compile at load; cap regex count; aho-corasick for prefix sets if scale demands. |
| Header matcher combinatorial blow-up | MVP = exact (name,value) list. Add regex later only if needed. |
| Hot-reload race on partial parse | ArcSwap = atomic; never publish partially-built registry. |
| Tier not set before consumer reads | Set in `ctx_builder` (first stage); panic-free `Option<Tier>` with `unwrap_or(CatchAll)` defensively. |
| Config drift across cluster nodes | Out of scope for FR-002; FR-044 (config sync) handles it. Note for later. |

## 13. Implementation Phases (for /ck:plan)

1. **Types + TOML schema** — `waf-common::tier`, serde, `validate()`.
2. **Classifier** — matchers (host/path/method/header), priority sort, unit tests.
3. **Registry + ArcSwap** — load, store, lookup; integration with config loader.
4. **Watcher** — `notify` + atomic swap; reuse rules-watcher infra.
5. **Wire-in** — `ctx_builder` populates `RequestCtx.tier`; expose registry as `Arc<…>` to gateway.
6. **Tests + bench + docs** — unit, integration, criterion bench, downstream-consumer guide.

Estimated effort: 2–3 dev-days incl. tests.

## 14. Out of Scope

- Per-tier challenge implementation → FR-006.
- Per-tier cache implementation → FR-009.
- Per-tier DDoS thresholds enforcement → FR-005.
- Cross-cluster config sync → FR-044.
- Admin-UI editing → later phase if FR-031 scope expands.

## 15. Unresolved Questions

1. Header matcher semantics — case-insensitive name (HTTP standard) but case-sensitive value? Confirm.
2. Should `RequestCtx.tier` be `Tier` or `Option<Tier>`? Leaning `Tier` w/ default = CatchAll for callsite simplicity.
3. Regex flavor for path/host matchers — `regex` crate (no backtracking) vs `fancy-regex`? `regex` preferred for DoS resistance.
4. Should classifier rules also live in TOML, or split into separate `rules/tiers.yaml` for ops convenience? Currently TOML per D2 — revisit if rule count > 50.
