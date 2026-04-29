# Tiered Protection (FR-002) — Consumer Guide

Single reference for FR-005 / FR-006 / FR-009 / FR-027 implementers.

---

## 1. Overview

FR-002 provides a two-part **policy bus**:

1. **Classifier** — maps every incoming request to one of four tiers (Critical / High / Medium / CatchAll) using priority-sorted rules that match on path, host, method, and headers.
2. **Registry** — holds a per-tier `TierPolicy` struct that downstream features read. The registry is hot-reloadable via `ArcSwap`; readers never block.

Every request arriving at the gateway has `ctx.tier` and `ctx.tier_policy` set before Phase 1 runs.

---

## 2. Tier Semantics

| Tier | Typical traffic | Default posture |
|------|----------------|-----------------|
| `Critical` | Login, payment, auth endpoints | Fail-close; lowest DDoS threshold; no caching |
| `High` | API surfaces, internal microservices | Fail-close; moderate thresholds; short TTL cache |
| `Medium` | Authenticated user pages, asset paths | Fail-open; higher thresholds; normal cache TTL |
| `CatchAll` | Everything else (default fallback) | Fail-open; permissive thresholds; aggressive caching |

The **default tier** (when no rule matches) is `CatchAll`. Override `default_tier` in TOML if a stricter posture is needed.

---

## 3. Reading the Policy in Your Check

```rust
use waf_common::tier::{CachePolicy, FailMode};

// ctx: &RequestCtx — already populated by ctx_builder before Phase 1.
let policy = ctx.tier_policy.clone(); // Arc<TierPolicy> — cheap clone

match policy.fail_mode {
    FailMode::Close => {
        // Hard-block on any check error — default for Critical/High.
    }
    FailMode::Open => {
        // Allow through on check error — default for Medium/CatchAll.
    }
}
```

`ctx.tier` is `waf_common::tier::Tier` — a `Copy` enum, safe to match exhaustively:

```rust
use waf_common::tier::Tier;

match ctx.tier {
    Tier::Critical => { /* strictest path */ }
    Tier::High     => { /* elevated path  */ }
    Tier::Medium   => { /* standard path  */ }
    Tier::CatchAll => { /* permissive path */ }
}
```

---

## 4. TOML Schema

```toml
[tiered_protection]
default_tier = "catch_all"          # catch_all | medium | high | critical

# Classifier rules — evaluated highest priority first. All conditions AND.
[[tiered_protection.classifier_rules]]
priority = 100
tier     = "critical"
path     = { kind = "exact",  value = "/login" }
method   = ["POST"]

[[tiered_protection.classifier_rules]]
priority = 90
tier     = "high"
path     = { kind = "prefix", value = "/api/" }

[[tiered_protection.classifier_rules]]
priority = 80
tier     = "high"
host     = { kind = "suffix", value = ".internal.example.com" }

[[tiered_protection.classifier_rules]]
priority = 70
tier     = "medium"
path     = { kind = "regex", value = "^/users/\\d+$" }

# Per-tier policies — ALL FOUR must be present or startup fails.
[tiered_protection.policies.critical]
fail_mode            = "close"        # close | open
ddos_threshold_rps   = 50
cache_policy         = { mode = "no_cache" }
risk_thresholds      = { allow = 10, challenge = 40, block = 70 }

[tiered_protection.policies.high]
fail_mode            = "close"
ddos_threshold_rps   = 200
cache_policy         = { mode = "short_ttl", ttl_seconds = 30 }
risk_thresholds      = { allow = 20, challenge = 50, block = 80 }

[tiered_protection.policies.medium]
fail_mode            = "open"
ddos_threshold_rps   = 1000
cache_policy         = { mode = "default", ttl_seconds = 300 }
risk_thresholds      = { allow = 30, challenge = 60, block = 85 }

[tiered_protection.policies.catch_all]
fail_mode            = "open"
ddos_threshold_rps   = 4294967295    # effectively unlimited
cache_policy         = { mode = "aggressive", ttl_seconds = 3600 }
risk_thresholds      = { allow = 35, challenge = 65, block = 90 }
```

### Matcher kinds

| Field | Kinds | Notes |
|-------|-------|-------|
| `path` | `exact`, `prefix`, `regex` | Regex uses the `regex` crate (no backtracking) |
| `host` | `exact`, `suffix`, `regex` | Host is lowercased before matching |
| `method` | array of HTTP verbs | `["GET", "POST", …]` |
| `headers` | `[{ name, value }]` | Exact name + value match (name case-insensitive) |

### `cache_policy` modes

| Mode | TOML | Effect |
|------|------|--------|
| `NoCache` | `{ mode = "no_cache" }` | No response caching |
| `ShortTtl` | `{ mode = "short_ttl", ttl_seconds = N }` | Cache with short TTL |
| `Default` | `{ mode = "default", ttl_seconds = N }` | Standard TTL caching |
| `Aggressive` | `{ mode = "aggressive", ttl_seconds = N }` | Long TTL, maximize cache hits |

---

## 5. Hot-Reload Semantics

- The file watcher monitors `configs/default.toml` from a background thread.
- On change: parse → validate → compile → `ArcSwap::store`. Old snapshot kept alive until all in-flight readers drop their `Arc`.
- On parse/validate failure: **old config retained**, a `tracing::warn!` is emitted. The gateway never restarts.
- Debounce window: `DEFAULT_DEBOUNCE_MS` (200 ms) after the last file event before reloading — covers editor save bursts.
- Per-request cost: one relaxed atomic load (`ArcSwap::load_full`). No lock contention under any load.

**Guarantee for readers**: `registry.classify()` always returns a (classifier, policy) pair from the **same snapshot** — no torn reads during a swap.

---

## 6. For FR-005 (DDoS Rate Limiting) Implementers

Read `ddos_threshold_rps` per-tier to vary the sliding-window limit:

```rust
let threshold = ctx.tier_policy.ddos_threshold_rps;
// Apply threshold to your per-IP counter for this request.
```

Critical tier carries the smallest threshold (e.g., 50 rps), CatchAll the largest.

---

## 7. For FR-006 (Challenge / Risk Scoring) Implementers

Read `risk_thresholds` to decide allow / challenge / block:

```rust
use waf_common::tier::RiskThresholds;

let RiskThresholds { allow, challenge, block } = ctx.tier_policy.risk_thresholds;
// score: u32 produced by your risk scorer
if score < allow {
    // pass
} else if score < challenge {
    // issue CAPTCHA / JS challenge
} else if score < block {
    // elevated challenge
} else {
    // block
}
```

---

## 8. For FR-009 (Cache Policy) Implementers

Branch on the `CachePolicy` enum variant:

```rust
use waf_common::tier::CachePolicy;

match &*ctx.tier_policy.cache_policy {
    CachePolicy::NoCache => { /* skip cache lookup and storage */ }
    CachePolicy::ShortTtl { ttl_seconds } => { /* cache with short TTL */ }
    CachePolicy::Default  { ttl_seconds } => { /* normal TTL cache */ }
    CachePolicy::Aggressive { ttl_seconds } => { /* long TTL, maximise hits */ }
}
```

Note: `cache_policy` is not a `Copy` type — clone or match by reference.

---

## 9. Adding a New Field to `TierPolicy`

1. Add the field to `waf_common::tier::TierPolicy` with a sensible `Default` impl.
2. Add `serde(default)` so existing TOML files without the field don't fail validation.
3. Update the TOML schema in this doc (§4) and in `docs/system-architecture.md`.
4. Add a `validate()` check in `TierConfig::validate()` if the field has invariants.
5. Update the hot-reload integration test (`crates/gateway/tests/tier_e2e.rs`) to cover the new field.
6. Announce the new field in `../../CHANGELOG.md`.

**Do not** add FR-specific fields to `TierPolicy` directly — keep it a shared policy struct. For FR-private state, carry it in the FR's own config and look up by `ctx.tier`.
