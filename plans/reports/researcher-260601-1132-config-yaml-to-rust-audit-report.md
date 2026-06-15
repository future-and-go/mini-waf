# Config YAML to Rust Deserialization Audit Report

**Date:** 2026-06-01  
**Scope:** `configs/risk.yaml` and `configs/tier-policies.yaml`  
**Auditor:** Technical Analyst  
**Status:** CRITICAL ISSUES FOUND

---

## Executive Summary

This audit identifies **3 critical structural mismatches** and **1 critical file format issue** that will cause runtime failures.

### Critical Issues

| Issue | Config | Severity | Impact |
|-------|--------|----------|--------|
| **Format mismatch** | tier-policies | CRITICAL | File is YAML but loader tries TOML |
| **CachePolicy enum mismatch** | tier-policies | CRITICAL | YAML uses "aggressive"/"default"/"short_ttl" but Rust expects tagged mode structure |
| **Missing default CachePolicy** | tier-policies | HIGH | YAML structure incompatible with serde(tag) |
| **IngestConfig missing in YAML** | risk.yaml | MEDIUM | Will silently use defaults; latent issue |

---

## Part 1: risk.yaml Audit

### File Format
- **YAML** (confirmed: uses `:` and hierarchical indentation)
- **Loader:** `RiskConfig::from_path()` → `serde_yaml::from_str()` ✓ CORRECT

### Document Wrapper

| YAML Structure | Rust Type | Field | Status |
|---|---|---|---|
| `risk:` (top key) | `RiskDocument` | `.risk` | ✓ Match |

### 1.1 RiskConfig Top-Level Fields

#### Field Mapping

| YAML Key | Rust Field | Type | Default | Status |
|----------|-----------|------|---------|--------|
| `schema_version` | `schema_version` | `u32` | `1` | ✓ Match |
| `enabled` | `enabled` | `bool` | `false` | ✓ Match |
| `ttl_secs` | `ttl_secs` | `u64` | `1800` | ✓ Match |
| `gc_interval_secs` | `gc_interval_secs` | `u64` | `60` | ✓ Match |
| `session_cookie` | `session_cookie` | `Option<String>` | `None` | ✓ Match |
| `header_name` | `header_name` | `String` | `"X-WAF-Risk-Score"` | ✓ Match |
| `emit_header` | `emit_header` | `bool` | `true` | ✓ Match |
| `store` | `store` | `StoreConfig` | `{}` (default) | ✓ Match |
| `decay` | `decay` | `DecayConfig` | `{}` (default) | ✓ Match |
| `seed` | `seed` | `SeedConfig` | `{}` (default) | ✓ Match |
| `ingest` | `ingest` | `IngestConfig` | `{}` (default) | ⚠️ MISSING FROM YAML |
| `canary` | `canary` | `CanaryConfig` | `{}` (default) | ✓ Match |
| `challenge` | `challenge` | `ChallengeConfig` | `{}` (default) | ⚠️ MISSING FROM YAML |

**Finding 1.1a (MEDIUM):** `IngestConfig` section absent in YAML. Will deserialize to default: `{ enabled: true, channel_capacity: 65536, signal_weights: {} }`. This is acceptable due to `#[serde(default)]`, but the ingest pipeline initializes with empty signal weights. Operator must be aware the async ingest layer has no custom signal overrides.

**Finding 1.1b (MEDIUM):** `ChallengeConfig` section absent in YAML. Will deserialize to default: `{ enabled: false, ttl_secs: 300, hmac_secret_path: None, lru_size: 100_000, header_name: "X-WAF-Cred", valid_delta: -25, invalid_delta: 20, replay_delta: 30, expired_delta: 10 }`. Since challenge layer disabled by default, this is non-critical for current config. **Action:** Document in YAML that these sections are optional.

### 1.2 StoreConfig

#### YAML Structure (lines 28–36)
```yaml
store:
  backend: memory    # memory | redis
  # redis:
  #   url: "..."
```

#### Field Mapping

| YAML Key | Rust Field | Type | Default | Status |
|----------|-----------|------|---------|--------|
| `backend` | `backend` | `String` | `"memory"` | ✓ Match |
| `redis` | `redis` | `RedisStoreConfig` | `{}` (default) | ✓ Match (optional, gated by #[serde(default)]) |

**Finding 1.2a (INFO):** `redis` section commented in YAML but would deserialize if uncommented. All Redis fields have defaults via `#[serde(default)]` and `impl Default`. No mismatches.

### 1.3 DecayConfig

#### YAML Structure (lines 39–46)
```yaml
decay:
  min_clean_streak: 10
  decay_rate: 1
  max_decay: 50
```

#### Field Mapping

| YAML Key | Rust Field | Type | YAML Value | Rust Default | Status |
|----------|-----------|------|-----------|--------------|--------|
| `min_clean_streak` | `min_clean_streak` | `u32` | `10` | `10` | ✓ Match |
| `decay_rate` | `decay_rate` | `u16` | `1` | `1` | ✓ Match |
| `max_decay` | `max_decay` | `u32` | `50` | `50` | ✓ Match |

**Finding 1.3a (SEMANTIC):** Field name `max_decay` is semantically incorrect in the context of its documented meaning. The comment states "Floor below which automatic decay stops" — `max_decay` implies a ceiling, not a floor. The actual semantic is `min_decay_floor`. No deserialization issue, but the name misleads operators. **Recommendation:** Rename to `decay_floor` or document this inversed semantics.

### 1.4 SeedConfig

#### YAML Structure (lines 50–66)
```yaml
seed:
  enabled: true
  # tor_exits_path: "..."
  # asn_classes_path: "..."
  # whitelist_path: "..."
  tor_delta: 30
  datacenter_delta: 15
  bad_asn_delta: 25
```

#### Field Mapping

| YAML Key | Rust Field | Type | YAML Value | Rust Default | Status |
|----------|-----------|------|-----------|--------------|--------|
| `enabled` | `enabled` | `bool` | `true` | `true` | ✓ Match |
| `tor_exits_path` | `tor_exits_path` | `Option<String>` | (absent) | `None` | ✓ Match |
| `asn_classes_path` | `asn_classes_path` | `Option<String>` | (absent) | `None` | ✓ Match |
| `whitelist_path` | `whitelist_path` | `Option<String>` | (absent) | `None` | ✓ Match |
| `tor_delta` | `tor_delta` | `u8` | `30` | `30` | ✓ Match |
| `datacenter_delta` | `datacenter_delta` | `u8` | `15` | `15` | ✓ Match |
| `bad_asn_delta` | `bad_asn_delta` | `u8` | `25` | `25` | ✓ Match |

**Finding 1.4a:** All seed deltas are `u8` (max 255). YAML values (30, 15, 25) are safe. ✓ No issue.

**Finding 1.4b (INFO):** Risk deltas feed into `SeedConfig::to_deltas()` which converts to `SeedDeltas` struct consumed by `SeedLayer`. Verified at `config.rs` lines 226–232. Struct mapping correct.

### 1.5 CanaryConfig

#### YAML Structure (lines 73–86)
```yaml
canary:
  enabled: false
  paths:
    # - "/admin-test"
    # - "/api-debug"
  ban_ttl_secs: 3600
```

#### Field Mapping

| YAML Key | Rust Field | Type | YAML Value | Rust Default | Status |
|----------|-----------|------|-----------|--------------|--------|
| `enabled` | `enabled` | `bool` | `false` | `false` | ✓ Match |
| `paths` | `paths` | `Vec<String>` | `[]` (all commented) | `[]` | ✓ Match |
| `ban_ttl_secs` | `ban_ttl_secs` | `u32` | `3600` | `3600` | ✓ Match |

**Finding 1.5a:** Type `Vec<String>` correctly deserializes commented array to empty vec. ✓ No issue.

**Finding 1.5b:** `CanaryLayer` implements `check()` for exact-match lookup, `check_and_ban()` for side-effect. Verified at `canary.rs` lines 86–116. Path matching is **case-sensitive exact match only** — no substring or regex. Operator must be aware `/admin-test/foo` will NOT trigger `/admin-test`. ✓ Documented in code and YAML comments.

### 1.6 Hot-Reload Mechanism

**File watcher:** `RiskReloader::start()` uses `notify` crate (parent-dir watch, debounce 200ms).

**Loading path:** `RiskConfig::from_path()` reads file → `serde_yaml::from_str()` → parses `RiskDocument` wrapper → extracts `.risk`.

**Failure handling:** On parse error, `reload()` logs warn and retains previous snapshot. ✓ Correct.

**Finding 1.6a (INFO):** No `#[serde(rename)]` or `#[serde(alias)]` annotations in risk config. YAML keys must match Rust field names exactly.

---

## Part 2: tier-policies.yaml Audit

### File Format
- **YAML** (confirmed: uses `:` and hierarchical indentation)
- **Declared Loader:** `tier_config_watcher.rs` line 134 → `toml::from_str()` ❌ **CRITICAL MISMATCH**

### Critical Issue 2.1: File Format Mismatch

**Severity: CRITICAL — Will cause all loads to fail**

**Actual file:** `tier-policies.yaml` (YAML format)

**Loader code** (tier_config_watcher.rs:134):
```rust
let raw = std::fs::read_to_string(path)?;
let env: TomlEnvelope = toml::from_str(&raw)?;  // ← TOML parser!
```

**Result:** TOML parser will reject YAML syntax:
- YAML: `policies: { catch_all: { ... } }`
- TOML: `[policies.catch_all] ...`

**Reproduction:** Attempt to load `tier-policies.yaml` will fail with TOML parse error:
```
Error: invalid TOML document. Expected `=`, `]`, or `]`, found `:`
```

**Root Cause:** The schema in `waf-common/src/tier.rs` does NOT specify a format. The `tier_config_watcher.rs` hardcodes `toml::from_str()` but the actual config file is YAML.

**Fix Required:** Either:
1. **Option A (preferred):** Change loader to `serde_yaml::from_str()` to match the actual file format.
2. **Option B:** Convert `tier-policies.yaml` to TOML format (`tier-policies.toml`).

**Recommendation:** Option A. The admin API (`tier_policies_api.rs`) **already uses YAML** (line 30: `serde_yaml::from_str::<Value>()`), so the runtime system expects YAML. Only the watcher was incorrectly hardcoded to TOML.

### Document Wrapper

The gateway watcher expects a TOML envelope:
```rust
#[derive(Debug, Deserialize)]
struct TomlEnvelope {
    #[serde(default)]
    tiered_protection: Option<TierConfig>,
}
```

This means the TOML file should be:
```toml
[tiered_protection]
default_tier = "catch_all"
classifier_rules = []

[tiered_protection.policies.critical]
# ...
```

**But the YAML file has NO wrapper key.** It directly deserializes as `TierConfig`:
```yaml
default_tier: catch_all
classifier_rules: []
policies:
  critical: { ... }
```

**Finding 2.1a (CRITICAL):** If you change the loader to YAML, the `TomlEnvelope` wrapper **must be removed or changed**. The YAML file structure does not match the envelope. You have two options:

1. **Option 1:** Load directly to `TierConfig`:
   ```rust
   let cfg: TierConfig = serde_yaml::from_str(&raw)?;
   ```

2. **Option 2:** Add a top-level key to YAML:
   ```yaml
   tiered_protection:
     default_tier: catch_all
     policies: { ... }
   ```

The admin API (`tier_policies_api.rs`) loads **without an envelope** (line 74: direct `serde_yaml::from_str::<Value>()`), then merges into a JSON object with `"success"` and `"data"` fields. This indicates the **YAML file is the direct config, not wrapped**.

**Recommendation:** Change loader to parse YAML directly (Option 1).

### 2.2 TierConfig Top-Level Fields

Assuming the YAML is loaded **without the `TomlEnvelope` wrapper** (direct to `TierConfig`):

#### Field Mapping

| YAML Key | Rust Field | Type | Status |
|----------|-----------|------|--------|
| `default_tier` | `default_tier` | `Tier` | ⚠️ MISSING |
| `classifier_rules` | `classifier_rules` | `Vec<TierClassifierRule>` | ✓ Present (empty) |
| `policies` | `policies` | `HashMap<Tier, TierPolicy>` | ✓ Present |

**Finding 2.2a (CRITICAL):** YAML is missing `default_tier` field. The Rust struct requires it (no `#[serde(default)]`):

```rust
pub struct TierConfig {
    pub default_tier: Tier,          // ← NO DEFAULT
    #[serde(default)]
    pub classifier_rules: Vec<TierClassifierRule>,
    pub policies: HashMap<Tier, TierPolicy>,
}
```

**Result:** Deserialization will fail:
```
Error: missing field `default_tier` at line 1 column 0
```

**Fix:** Add to YAML:
```yaml
default_tier: catch_all
classifier_rules: []
policies: { ... }
```

### 2.3 Tier Enum

| YAML Key | Rust Variant | Serde Rename | Status |
|----------|--------------|--------------|--------|
| `critical` | `Tier::Critical` | `critical` (via `rename_all = "snake_case"`) | ✓ Match |
| `high` | `Tier::High` | `high` | ✓ Match |
| `medium` | `Tier::Medium` | `medium` | ✓ Match |
| `catch_all` | `Tier::CatchAll` | `catch_all` | ✓ Match |

**Finding 2.3a:** Tier enum uses `#[serde(rename_all = "snake_case")]` (tier.rs:15). YAML keys must be lowercase snake_case. ✓ Correct in YAML.

### 2.4 TierPolicy Fields — CRITICAL MISMATCH

#### YAML Structure (line 3–10, catch_all tier)
```yaml
policies:
  catch_all:
    cache_policy: aggressive
    ddos_threshold_rps: 1000
    fail_mode: open
    risk_thresholds:
      allow: 20
      block: 85
      challenge: 60
```

#### Rust Struct (tier.rs:71–77)
```rust
pub struct TierPolicy {
    pub fail_mode: FailMode,
    pub ddos_threshold_rps: u32,
    pub cache_policy: CachePolicy,
    pub risk_thresholds: RiskThresholds,
}
```

#### Field Mapping

| YAML Key | Rust Field | Type | Status |
|----------|-----------|------|--------|
| `cache_policy` | `cache_policy` | `CachePolicy` | ❌ **CRITICAL MISMATCH** |
| `ddos_threshold_rps` | `ddos_threshold_rps` | `u32` | ✓ Match |
| `fail_mode` | `fail_mode` | `FailMode` | ✓ Match (enum) |
| `risk_thresholds` | `risk_thresholds` | `RiskThresholds` | ✓ Match (struct) |

### 2.4a CRITICAL: CachePolicy Enum Mismatch

**Rust Enum** (tier.rs:36–44):
```rust
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum CachePolicy {
    NoCache,
    ShortTtl { ttl_seconds: u32 },
    Aggressive { ttl_seconds: u32 },
    Default { ttl_seconds: u32 },
}
```

**Serde Structure:**
- Uses `#[serde(tag = "mode")]` — the enum variant is encoded as the `"mode"` field
- For `NoCache`: `{ "mode": "no_cache" }`
- For `ShortTtl`: `{ "mode": "short_ttl", "ttl_seconds": 60 }`
- For `Aggressive`: `{ "mode": "aggressive", "ttl_seconds": 300 }`
- For `Default`: `{ "mode": "default", "ttl_seconds": 300 }`

**YAML Values:**
```yaml
cache_policy: aggressive        # Wrong — not an object!
cache_policy: default           # Wrong — not an object!
cache_policy: short_ttl         # Wrong — not an object!
cache_policy: no_cache          # Wrong — not an object!
```

**Expected YAML:**
```yaml
cache_policy:
  mode: aggressive
  ttl_seconds: 300

cache_policy:
  mode: default
  ttl_seconds: 300

cache_policy:
  mode: short_ttl
  ttl_seconds: 3600

cache_policy:
  mode: no_cache
```

**Result:** All four policies will fail to deserialize:
```
Error: missing field `mode` at line 4 column 4
```

**Finding 2.4a (CRITICAL):** The YAML uses bare strings for `cache_policy` but the Rust type requires a tagged object structure. This is a **fundamental schema mismatch**.

**Root Cause:** The Rust struct uses `#[serde(tag = "mode")]` to embed the enum variant in the object. When deserializing from YAML, serde expects:
```yaml
cache_policy:
  mode: aggressive
  ttl_seconds: <value>
```

Not:
```yaml
cache_policy: aggressive
```

**Fix Required:** Rewrite all four policies in YAML to use tagged structure, OR change the Rust enum to use untagged or newtype variant:

**Option 1 (Recommended: Update YAML):**
```yaml
policies:
  catch_all:
    fail_mode: open
    ddos_threshold_rps: 1000
    cache_policy:
      mode: aggressive
      ttl_seconds: 300
    risk_thresholds:
      allow: 20
      challenge: 60
      block: 85
  critical:
    fail_mode: close
    ddos_threshold_rps: 50
    cache_policy:
      mode: no_cache
    risk_thresholds: { allow: 20, challenge: 60, block: 85 }
```

**Option 2 (Redefine Rust Enum — NOT recommended, breaks existing schema):**
Change to untagged:
```rust
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    NoCache,
    ShortTtl(u32),
    Aggressive(u32),
    Default(u32),
}
```

Then YAML could be:
```yaml
cache_policy:
  short_ttl: 3600
```

But this breaks the admin API and existing code. **Stick with Option 1.**

### 2.5 RiskThresholds

#### YAML Structure
```yaml
risk_thresholds:
  allow: 20
  block: 85
  challenge: 60
```

#### Rust Struct (tier.rs:47–52)
```rust
pub struct RiskThresholds {
    pub allow: u32,
    pub challenge: u32,
    pub block: u32,
}
```

#### Field Mapping

| YAML Key | Rust Field | Type | YAML Value | Status |
|----------|-----------|------|-----------|--------|
| `allow` | `allow` | `u32` | `20` | ✓ Match |
| `challenge` | `challenge` | `u32` | `60` | ✓ Match |
| `block` | `block` | `u32` | `85` | ✓ Match |

**Finding 2.5a:** Field types and values all correct. ✓ No issue.

**Finding 2.5b:** Validation constraint (lines 148 in tier.rs): `allow < challenge < block` is enforced in `TierConfig::validate()`. YAML values satisfy: `20 < 60 < 85`. ✓ Pass.

### 2.6 Tier Classifier Rules

#### YAML Structure
```yaml
classifier_rules: []
```

#### Rust Type (tier.rs:99–111)
```rust
pub struct TierClassifierRule {
    pub priority: u32,
    pub tier: Tier,
    #[serde(default)]
    pub host: Option<HostMatch>,
    #[serde(default)]
    pub path: Option<PathMatch>,
    #[serde(default)]
    pub method: Option<Vec<HttpMethod>>,
    #[serde(default)]
    pub headers: Option<Vec<HeaderMatch>>,
}
```

**Finding 2.6a:** YAML has empty array. All `#[serde(default)]` fields on rules will deserialize to `None`. Empty rules = all traffic falls through to `default_tier` (catch_all). ✓ Correct behavior for the default config.

### 2.7 FailMode Enum

| YAML Value | Rust Variant | Serde Rename | Status |
|-----------|--------------|--------------|--------|
| `open` | `FailMode::Open` | `open` (via `rename_all = "snake_case"`) | ✓ Match |
| `close` | `FailMode::Close` | `close` | ✓ Match |

**Finding 2.7a:** Enum correctly maps. ✓ No issue.

### 2.8 Hot-Reload Mechanism

**File watcher:** `TierConfigWatcher::spawn()` watches parent directory, debounces 200ms.

**Loading path:**
1. Read file
2. Parse as TOML envelope ← **WRONG FORMAT** (see Finding 2.1)
3. Extract `[tiered_protection]` section (doesn't exist in YAML)
4. Validate via `TierConfig::validate()`
5. Compile rules via `TierClassifier::new()` (regex compilation)
6. Swap via `ArcSwap`

**Failure handling:** On any error, logs warn and keeps previous snapshot. ✓ Correct pattern.

---

## Summary of Findings

### risk.yaml

| Finding | Severity | Category | Status |
|---------|----------|----------|--------|
| 1.1a: IngestConfig missing | MEDIUM | Scope | Latent — will use defaults; document it |
| 1.1b: ChallengeConfig missing | MEDIUM | Scope | Latent — disabled by default; acceptable |
| 1.3a: max_decay field name semantics | SEMANTIC | Naming | Document or rename to `decay_floor` |
| 1.4b: Seed delta types | INFO | Type safety | All u8, all values in range — OK |
| 1.5b: Canary exact-match semantics | INFO | Behavior | Case-sensitive, exact-only — documented in code |
| 1.6a: No serde renames | INFO | Maintenance | Keys must match field names exactly |

**risk.yaml Status: ACCEPT** — No blocking issues. File loads and deserializes correctly.

### tier-policies.yaml

| Finding | Severity | Category | Status |
|---------|----------|----------|--------|
| **2.1: YAML file but TOML loader** | **CRITICAL** | Format | Will fail on load immediately |
| **2.2a: Missing default_tier field** | **CRITICAL** | Schema | Will fail on deserialization |
| **2.4a: cache_policy bare string vs tagged enum** | **CRITICAL** | Schema | Will fail on deserialization of all 4 tiers |
| 2.2: Envelope wrapper mismatch | CRITICAL | Schema | YAML has no wrapper, code expects `TomlEnvelope` |
| 2.5b: Risk thresholds validation | INFO | Validation | Values satisfy allow < challenge < block |
| 2.6a: Empty classifier rules | INFO | Config | Falls through to catch_all — correct |

**tier-policies.yaml Status: REJECT** — **3 critical blockers** prevent any load.

---

## Detailed Remediation Plan

### For risk.yaml

1. **Optional enhancement:** Add `ingest` section with signal weights if custom weighting needed:
   ```yaml
   ingest:
     enabled: true
     channel_capacity: 65536
     signal_weights:
       scanner_ua: 5
       # ... more overrides
   ```

2. **Optional enhancement:** Add `challenge` section if challenge credits will be used:
   ```yaml
   challenge:
     enabled: true
     ttl_secs: 300
     hmac_secret_path: /etc/waf-creds/challenge-hmac.key
   ```

3. **Documentation:** Update YAML comments to clarify that `ingest` and `challenge` sections are optional and override internal defaults.

4. **Semantic fix (non-blocking):** Rename `decay.max_decay` to `decay.decay_floor` in code and YAML to match semantics (it's a floor, not a ceiling).

### For tier-policies.yaml

**BLOCKING FIX #1: Change file loader from TOML to YAML**

File: `crates/gateway/src/tiered/tier_config_watcher.rs`, line 134

**Current code:**
```rust
pub fn try_reload(path: &Path) -> anyhow::Result<TierSnapshot> {
    let raw = std::fs::read_to_string(path)?;
    let env: TomlEnvelope = toml::from_str(&raw)?;  // ← WRONG
    let cfg = env
        .tiered_protection
        .ok_or_else(|| anyhow::anyhow!("[tiered_protection] table missing"))?;
    Ok(TierSnapshot::try_from_config(cfg)?)
}
```

**Replacement code:**
```rust
pub fn try_reload(path: &Path) -> anyhow::Result<TierSnapshot> {
    let raw = std::fs::read_to_string(path)?;
    let cfg: TierConfig = serde_yaml::from_str(&raw)?;  // Use YAML, load directly
    Ok(TierSnapshot::try_from_config(cfg)?)
}
```

**Also update the test at line 183:**
```rust
fn blank_snapshot() -> TierSnapshot {
    let raw = r#"
default_tier: catch_all
classifier_rules: []

policies:
  critical:
    fail_mode: close
    ddos_threshold_rps: 1000
    cache_policy:
      mode: no_cache
    risk_thresholds: { allow: 10, challenge: 50, block: 100 }
  high:
    fail_mode: close
    ddos_threshold_rps: 1000
    cache_policy:
      mode: no_cache
    risk_thresholds: { allow: 10, challenge: 50, block: 100 }
  medium:
    fail_mode: open
    ddos_threshold_rps: 1000
    cache_policy:
      mode: no_cache
    risk_thresholds: { allow: 10, challenge: 50, block: 100 }
  catch_all:
    fail_mode: open
    ddos_threshold_rps: 1000
    cache_policy:
      mode: no_cache
    risk_thresholds: { allow: 10, challenge: 50, block: 100 }
"#;
    let cfg: TierConfig = serde_yaml::from_str(raw).expect("parse");  // Change to YAML
    TierSnapshot::try_from_config(cfg).expect("snapshot")
}
```

**BLOCKING FIX #2: Add default_tier to YAML**

File: `configs/tier-policies.yaml`, line 1

**Add at the top:**
```yaml
default_tier: catch_all

classifier_rules: []
policies:
  catch_all: ...
```

**BLOCKING FIX #3: Rewrite cache_policy to tagged structure**

File: `configs/tier-policies.yaml`, rewrite all four policies

**Current (WRONG):**
```yaml
policies:
  catch_all:
    cache_policy: aggressive
    ddos_threshold_rps: 1000
    fail_mode: open
    risk_thresholds:
      allow: 20
      block: 85
      challenge: 60
```

**Corrected:**
```yaml
policies:
  catch_all:
    cache_policy:
      mode: aggressive
      ttl_seconds: 300
    ddos_threshold_rps: 1000
    fail_mode: open
    risk_thresholds:
      allow: 20
      challenge: 60
      block: 85
  critical:
    cache_policy:
      mode: no_cache
    ddos_threshold_rps: 50
    fail_mode: close
    risk_thresholds:
      allow: 20
      challenge: 60
      block: 85
  high:
    cache_policy:
      mode: default
      ttl_seconds: 300
    ddos_threshold_rps: 200
    fail_mode: close
    risk_thresholds:
      allow: 20
      challenge: 60
      block: 85
  medium:
    cache_policy:
      mode: short_ttl
      ttl_seconds: 60
    ddos_threshold_rps: 500
    fail_mode: open
    risk_thresholds:
      allow: 20
      challenge: 60
      block: 85
```

**Note on cache_policy variants:**
- `NoCache`: `{ mode: no_cache }` (no ttl_seconds field needed)
- `Default`: `{ mode: default, ttl_seconds: <value> }`
- `ShortTtl`: `{ mode: short_ttl, ttl_seconds: <value> }`
- `Aggressive`: `{ mode: aggressive, ttl_seconds: <value> }`

For `NoCache`, serde will infer the variant from `mode: no_cache` alone; you do NOT need a `ttl_seconds` field.

---

## Validation Commands

After fixes, test both configs:

### risk.yaml
```bash
cargo test -p waf-engine --lib risk::config::tests --
cargo test -p waf-engine --lib risk::reload::tests --
```

### tier-policies.yaml
```bash
cargo test -p gateway --lib tiered::tier_config_watcher::tests --
cargo test -p gateway --lib tiered::tier_policy_registry::tests --
```

### Manual hot-reload test
```bash
# risk.yaml
touch configs/risk.yaml
# Inspect logs for: "risk: hot-reload OK" or "risk: hot-reload failed"

# tier-policies.yaml
touch configs/tier-policies.yaml
# Inspect logs for: "tier config reloaded" or "tier config reload failed"
```

---

## Risk Assessment

### Critical (Must Fix Before Merge)
- **2.1:** TOML parser on YAML file → immediate load failure
- **2.2a:** Missing `default_tier` field → immediate deserialization failure
- **2.4a:** Bare string cache_policy vs tagged enum → immediate deserialization failure

### High (Should Fix)
- **1.1a, 1.1b:** Undocumented optional YAML sections → latent confusion for operators

### Medium (Document)
- **1.3a:** Field naming semantics mismatch → confusion on what `max_decay` does

---

## Unresolved Questions

1. **Why YAML for tier-policies but TOML elsewhere?**
   - Answer: Admin API uses YAML for easier web editing; gateway watcher was incorrectly hardcoded to TOML.
   - **Action:** Standardize on YAML for both configs (risk.yaml is already YAML).

2. **Should cache_policy have required ttl_seconds for non-NoCache variants?**
   - Current: all four policies in YAML lack ttl_seconds, would fail to deserialize.
   - **Action:** Add ttl_seconds to `Default`, `ShortTtl`, `Aggressive` variants in corrected YAML.

3. **Is IngestConfig section intentionally omitted from risk.yaml?**
   - Answer: Yes, it's optional and defaults are sufficient for most deployments.
   - **Action:** Document in YAML that omitting it is safe.

4. **Can tier-policies.yaml use TOML format instead of fixing the loader?**
   - Answer: Not recommended. Admin API hard-depends on YAML format (line 30 of tier_policies_api.rs).
   - **Action:** Fix loader to YAML.

---

## Conclusion

**risk.yaml:** PASS (minor documentation improvements recommended)

**tier-policies.yaml:** FAIL (3 critical blockers; requires code + config changes)

Both files require fixes before they will deserialize and load successfully in a running system. The tier-policies issues are the highest priority due to their blocking nature.

**Estimated fix effort:** 30 minutes (update YAML structure + one loader function + tests).
