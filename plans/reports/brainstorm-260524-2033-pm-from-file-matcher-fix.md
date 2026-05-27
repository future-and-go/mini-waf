# Brainstorm: `pm_from_file` / `contains_any` Silent-Fail Fix

**Date:** 2026-05-24
**Status:** Design approved, ready for plan
**Severity:** Critical (security posture lie — rules appear enforced, are inert)

---

## Problem Statement

CRS-930130 ("Restricted File Access Attempt", path-based block of `/.env`, `.htpasswd`, etc.) is configured with `enabled: true, action: block` but **does not enforce at runtime**. Root-cause trace:

1. YAML parser (`custom_rule_yaml.rs:170`) routes `pm_from_file` / `contains_any` / `detect_sqli` / `detect_xss` into `specialised_op` field, leaves `conditions` empty.
2. Engine (`engine.rs:584`) sees `specialised_op` and dispatches to `eval_specialised()`.
3. `eval_specialised()` (`engine.rs:1120`) only implements `DetectSqli` / `DetectXss`. **`PmFromFile` and `ContainsAny` hit the `_ => return false` catch-all** — silently no-op.

**Blast radius (verified):**
- `rules/owasp-crs/lfi.yaml` — CRS-930120, 930121, 930130, 930140 (`pm_from_file`)
- `rules/owasp-crs/xss.yaml`, `php-injection.yaml` (`contains_any`)
- `tools/modsec2yaml.py` converts ModSecurity `@pm` → `contains_any`, so any migrated ModSec rule is also inert.

Pattern data file `restricted-files.data` is **never opened** anywhere in the engine.

Worst failure mode: the system **reports correct security coverage while delivering none**.

## Architectural Root Cause

Dual dispatch path: same operators (`DetectSqli`, `DetectXss`) live in **both** the `Matcher` enum (engine.rs:894) AND in `specialised_op` (engine.rs:584). Adding a new "specialised" operator requires wiring in two places. `pm_from_file` and `contains_any` were wired into the parser side only — runtime side forgotten. **Type system did not prevent it.**

## Decisions (locked)

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Option C — unify into `Matcher` enum**, drop `specialised_op` field entirely | Eliminates silent-fail by construction. Single dispatch path. No vtable cost. |
| 2 | **CRS-compatible semantics** — case-insensitive substring multi-pattern + URL-decode retry | Matches OWASP CRS upstream `@pmFromFile` / `@pm` behaviour. Catches `/%2Eenv`, `/.ENV`. |
| 3 | **YAML-only scope** — no DB rules use these operators today | Skips DB migration step; if DB ever gets such rules, same compile path applies automatically. |
| 4 | **Hot reload on `.data` file change** — rebuild referencing rules | Operators edit threat lists without restart. Requires reverse-index `data_path → rule_ids`. |

## Design Pattern

**"Compile to a uniform executable artifact at load time. Make invalid states unrepresentable."**

The parser's only allowed output is a `Matcher` that is itself executable. If we cannot build one (file missing, parse error, size cap), the rule is **rejected at load** with a structured error. Same contract as the existing `Matcher::Regex(Regex)` — pre-compiled, fails loudly if invalid.

## Target Architecture

### Type changes

```rust
// crates/waf-engine/src/rules/engine.rs
enum Matcher {
    // existing variants ...
    Eq(String), Contains(String), Regex(Regex), Glob(GlobMatcher), Cidr(IpNet), ...
    DetectSqli, DetectXss,
    // NEW:
    PatternSet(Arc<AhoCorasick>),    // pm_from_file: loaded data file
    PatternList(Arc<AhoCorasick>),   // contains_any: inline list literal
}

// REMOVED:
struct CustomRule {
    // pub specialised_op: Option<Operator>,   ← delete
}
```

`Matcher::matches(fstr, ctx_ip)` gains two arms:
```rust
Self::PatternSet(ac) | Self::PatternList(ac) => ac.is_match(fstr),
```

### Compilation path

`custom_rule_yaml.rs::build_rule()`:
- For `pm_from_file`: resolve data file path → load → build `AhoCorasick` → push `Condition { field, operator: PmFromFile, value: ConditionValue::AhoCorasick(Arc<_>) }`.
- For `contains_any`: read inline list from `value:` → build `AhoCorasick` from literals → same shape.
- For `detect_sqli` / `detect_xss`: push `Condition { field, operator: DetectSqli|DetectXss, value: Unit }`. **Stop routing them through `specialised_op`.**

`engine.rs::compile_condition()` gains:
```rust
(Operator::PmFromFile, ConditionValue::AhoCorasick(ac)) => Matcher::PatternSet(ac.clone()),
(Operator::ContainsAny, ConditionValue::AhoCorasick(ac)) => Matcher::PatternList(ac.clone()),
```
The existing `_ => bail!` becomes the only refusal site. No silent paths remain.

### Multi-field semantics (preserve current behaviour)

`eval_specialised` currently scans path → query → body → headers when `pattern_field == "all"`. Move that loop into the standard evaluator as a per-condition pre-step keyed off `ConditionField::All` (or similar), so the new matchers inherit it. **Required to preserve sqli/xss behaviour when moving them out of `specialised_op`.**

### Data file resolver (security-critical)

```rust
fn resolve_data_path(yaml_path: &Path, value: &str) -> Result<PathBuf> {
    if value.contains("..") || Path::new(value).is_absolute() {
        bail!("data file value must be a relative filename, no path traversal: {value}");
    }
    let candidate = yaml_path.parent()?.join("data").join(value).canonicalize()?;
    // assert canonicalised path is under rules_dir
    if !candidate.starts_with(rules_dir_canonical()?) {
        bail!("data file resolves outside rules_dir: {candidate:?}");
    }
    Ok(candidate)
}
```

### Data file cache (dedupe)

```rust
struct DataFileRegistry {
    cache: parking_lot::Mutex<HashMap<PathBuf, CachedAc>>,
}
struct CachedAc { mtime: SystemTime, size: u64, ac: Arc<AhoCorasick> }
```

- N rules referencing same file → 1 automaton in memory.
- On reload: compare mtime + size; rebuild on change.
- Reverse-index `HashMap<PathBuf, Vec<RuleId>>` for hot-reload-on-data-change.

### Hot reload extension

`hot_reload.rs` already watches `rules_dir` recursively. Add:
- On event for `*.data` path: look up `data_path → rule_ids`, mark those rules for recompile (full rules reload is acceptable v1 — file count is small).
- Debounce already exists; reuse.

### Load-time validation (loud failure)

Production-grade contract:
```rust
enum RuleLoadStatus { Loaded(CompiledRule), Failed { rule_id: String, reason: String } }
```
- Failed rules surface in admin UI with red badge + `reason`.
- Startup logs structured error: `rule_load_failed{rule_id, file, reason}`.
- Metrics: `rules_loaded_total{result="failed", reason="missing_data_file"}` etc.
- **Never silently disable.** A WAF that lies about coverage is worse than a WAF with a broken rule it tells you about.

### Resource bounds

- Max `.data` file size: 10 MB (configurable).
- Max patterns per file: 100,000.
- AhoCorasick build over budget → rule load fails with `reason: "data_file_too_large"`.

### Build options (AC)

```rust
AhoCorasickBuilder::new()
    .ascii_case_insensitive(true)
    .match_kind(MatchKind::LeftmostFirst)
    .build(patterns)?
```

Mirrors `checks/sensitive.rs` idiom in this repo. Strip lines that are empty after trim, or start with `#`.

### URL-decode evasion

Reuse existing `detect_with_decode()` helper. Apply to `PatternSet` / `PatternList` matches when the field is a request-path-style field (`path`, `query`, `cookies`, headers). Body bytes already get a decode pass in caller.

### Observability

| Metric | Labels |
|--------|--------|
| `waf_rules_loaded_total` | `result`, `reason` |
| `waf_rule_fire_total` | `rule_id`, `host_code` |
| `waf_pattern_file_bytes` | `path` (hashed) |
| `waf_pattern_file_patterns` | `path` (hashed) |
| `waf_data_file_reloads_total` | `path` (hashed) |

Tracing span on rule fire: `rule_id`, `matched_field`, `match` (truncated 64 chars).

## Phased Plan

### Phase 0 — Failing regression test

- Integration test: load `rules/owasp-crs/lfi.yaml`, build engine, send request with `ctx.path = "/.env"` → assert `DetectionResult { rule_id: "CRS-930130", action: Block }`.
- Parametrise across `.env`, `.envrc`, `.htpasswd`, `/%2Eenv` (URL-decode case).
- Test MUST FAIL on `main` (pinning the bug); becomes regression guard after fix.
- Same for `contains_any` against `xss.yaml` / `php-injection.yaml` patterns.

### Phase 1 — Implement matchers + unify dispatch

- Add `Matcher::PatternSet` / `PatternList` variants.
- Implement `resolve_data_path` with traversal guards.
- Implement `DataFileRegistry` with mtime cache.
- YAML compiler emits `Condition` for all four ops; **delete `specialised_op` field, `eval_specialised` function, and engine.rs:584 dispatch branch**.
- Move multi-field scan (`"all"` semantics) into generic evaluator.
- Resource caps enforced at build time.

### Phase 2 — Load-time validation + admin UI surfacing

- Refactor rule load to return `RuleLoadStatus`.
- Admin UI rule list: add `LoadFailed` state with reason tooltip.
- Startup audit log: one-shot summary of all rule loads (count loaded / failed / per-reason breakdown).

### Phase 3 — Hot reload of `.data` files

- Reverse-index `data_path → rule_ids` built during load.
- Watcher dispatches on `.data` events to a "selective recompile" path (v1: trigger full rules reload via existing mechanism is acceptable; v2: per-rule rebuild).
- Test: write to `restricted-files.data` at runtime, expect referencing rules to pick up changes within debounce window.

### Phase 4 — Observability + retro-audit

- Wire metrics listed above to the existing Prometheus registry.
- Tracing spans on rule fire.
- Startup retro-audit: log every rule that was previously inert (`pm_from_file`/`contains_any` count), so operators see the coverage gap they were running with.

### Phase 5 — Regression matrix

- Parameterised tests:
  - Every `pm_from_file` rule in `rules/owasp-crs/*.yaml` × ≥3 representative paths from its data file → 403.
  - Every `contains_any` rule × ≥2 representative payloads → 403.
  - Negative cases: paths NOT in data file → pass-through.
  - Encoding bypass cases: `%2E` for `.`, mixed case, leading whitespace.

## Risk Analysis

| Risk | Severity | Mitigation |
|------|----------|------------|
| Existing `detect_sqli` / `detect_xss` rules behave differently after moving out of `eval_specialised` | High | Phase 0 must include regression tests for current sqli/xss behaviour BEFORE refactor. No green light to merge unless both old and new behaviours match. |
| `"all"` multi-field semantics regression when moved | High | Dedicated test fixtures for each field permutation. Snapshot current behaviour first. |
| Data file path traversal via crafted `value:` | Medium | Resolver rejects absolute paths and `..`. Canonicalise + assert `starts_with(rules_dir)`. |
| Large data file OOM on load | Medium | Hard 10 MB cap, 100k pattern cap. Fail rule, don't fail process. |
| Hot reload thrash on rapid edits | Low | Existing debounce already applied at watcher level. |
| AC build cost at scale | Low | Dedupe by file path; N rules × 1 file = 1 build. |
| ConditionValue enum bloat (new `AhoCorasick` variant) | Low | Arc-wrapped so size_of stays small. |

## Out of Scope (YAGNI)

- New operator types beyond fixing the existing four.
- Performance tuning beyond Aho-Corasick (already optimal for this use case).
- Paranoia-level filtering changes.
- Admin UI rule editor changes (only the status display gains a state).
- Per-pattern allowlist for false-positive suppression (revisit if/when real FP arises).

## Success Criteria

1. `curl -H "Host: <configured-host>" http://<waf>/.env` returns **403** with rule `CRS-930130` in audit log.
2. Same for `/%2Eenv`, `/.ENV`, `/path/with/.envrc`.
3. All existing sqli/xss rule tests still pass after the refactor (no behavioural drift).
4. Modifying `restricted-files.data` at runtime is reflected in rule behaviour within one debounce window, no restart.
5. A YAML rule with a missing data file fails loudly at startup (log + admin UI) and **does not** silently disable.
6. `cargo fmt --all -- --check` and `cargo check` clean. No new `unwrap`/`expect` in production paths (per Seven Iron Rules).
7. Phase 0 regression tests stay green on CI.

## Unresolved Questions

- Admin UI: does the rule-status surface already have a non-binary state (loaded / loaded-but-inert / failed)? If not, that's a small frontend addition — confirm scope with whoever owns admin UI.
- Should `.data` files be allowed under `<rules_dir>/custom/data/` (user-authored rules), or restricted to vendored CRS subtree only? Affects resolver policy.
- Retro-audit logging — log once at startup, or also emit a Prometheus gauge so dashboards can alarm? Recommend both.
