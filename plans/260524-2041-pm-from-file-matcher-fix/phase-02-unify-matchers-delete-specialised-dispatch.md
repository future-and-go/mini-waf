---
phase: 2
title: "Unify Matchers & Delete Specialised Dispatch"
status: pending
priority: P1
effort: "1d"
dependencies: [1]
---

# Phase 2: Unify Matchers & Delete Specialised Dispatch

## Overview

The structural fix. Apply the **"Compile to a uniform executable artifact"** design pattern: every operator must produce a `Matcher` variant or be rejected at load time. Delete `specialised_op` field, delete `eval_specialised()`, delete the `engine.rs:584` branch. By construction, no operator can be silently ignored.

This phase turns Phase 1's pinning tests green WITHOUT regressing the snapshot tests.

## Requirements

- Add `Matcher::PatternSet(Arc<AhoCorasick>)` and `Matcher::PatternList(Arc<AhoCorasick>)` variants.
- `Matcher::matches()` dispatches them via `ac.is_match(fstr)`.
- YAML compiler in `formats/custom_rule_yaml.rs` emits a normal `Condition` for all four operators (`pm_from_file`, `contains_any`, `detect_sqli`, `detect_xss`) — no longer routes through `specialised_op`.
- `CustomRule.specialised_op` field DELETED.
- `engine.rs:584` `eval_specialised` branch DELETED.
- `eval_specialised()` function DELETED.
- Multi-field scan (`pattern_field == "all"` → path/query/body/headers) moves into the generic evaluator as a per-condition pre-step, preserving current behaviour for sqli/xss.
- Data file resolver with path-traversal guard.
- `DataFileRegistry` caches `AhoCorasick` by canonicalised path + mtime + size.
- All Phase 1 snapshot tests still green. All Phase 1 pinning tests now green.

## Architecture

### Type changes

```rust
// crates/waf-engine/src/rules/engine.rs
enum Matcher {
    // ... existing variants ...
    DetectSqli, DetectXss,
    PatternSet(Arc<AhoCorasick>),   // pm_from_file
    PatternList(Arc<AhoCorasick>),  // contains_any
}

// CustomRule.specialised_op: REMOVED
```

`ConditionValue` gains one variant (Arc-wrapped to keep enum size flat):

```rust
enum ConditionValue {
    // ... existing ...
    AhoCorasick(Arc<AhoCorasick>),
}
```

### Dispatch (single path)

```rust
impl Matcher {
    pub fn matches(&self, fstr: &str, ctx_ip: IpAddr) -> bool {
        match self {
            // ... existing arms ...
            Self::DetectSqli => libinjection::sqli(fstr).is_some(),  // unchanged semantics
            Self::DetectXss => libinjection::xss(fstr),              // unchanged semantics
            Self::PatternSet(ac) | Self::PatternList(ac) => ac.is_match(fstr),
        }
    }
}
```

### Multi-field semantics

`pattern_field == "all"` currently lives in `eval_specialised`. Move into evaluator:

```rust
// Pseudocode — placement: where compile_condition's matcher is invoked
fn eval_condition(cond: &CompiledCondition, ctx: &RequestCtx) -> bool {
    if cond.field == ConditionField::All {
        // scan path, query, body, headers — return on first hit
        return iter_all_fields(ctx).any(|f| cond.matcher.matches(f, ctx.ip));
    }
    let field_str = resolve_field(&cond.field, ctx);
    cond.matcher.matches(field_str, ctx.ip)
}
```

URL-decode retry: reuse existing `detect_with_decode()` from sqli/xss path. Apply on `PatternSet`/`PatternList` when field is path/query/cookie/header (NOT body — body already decoded upstream).

### Compilation path

`formats/custom_rule_yaml.rs::build_rule()`:

```rust
match op_str {
    "pm_from_file" => {
        let ac = data_registry.load_or_get(&resolve_data_path(yaml_path, &value)?)?;
        push_condition(Condition {
            field: ConditionField::All,  // or parsed pattern_field
            operator: Operator::PmFromFile,
            value: ConditionValue::AhoCorasick(ac),
        });
    }
    "contains_any" => {
        let patterns = parse_inline_list(&value)?;
        let ac = build_ac(&patterns)?;
        push_condition(Condition {
            field: ...,
            operator: Operator::ContainsAny,
            value: ConditionValue::AhoCorasick(Arc::new(ac)),
        });
    }
    "detect_sqli" => push_condition(Condition { operator: DetectSqli, value: Unit, ... }),
    "detect_xss" => push_condition(Condition { operator: DetectXss, value: Unit, ... }),
    // ... others unchanged ...
}
```

`engine.rs::compile_condition()` adds:

```rust
(Operator::PmFromFile, V::AhoCorasick(ac)) => Matcher::PatternSet(ac.clone()),
(Operator::ContainsAny, V::AhoCorasick(ac)) => Matcher::PatternList(ac.clone()),
```

The existing `_ => bail!("unsupported operator/value combination")` is the ONLY refusal site. The current explicit `(PmFromFile | ContainsAny, _) => bail!(...handled by specialised module)` at `engine.rs:941` gets DELETED.

### Data file resolver (security-critical)

```rust
// crates/waf-engine/src/rules/data_file_resolver.rs (new module)
pub fn resolve_data_path(yaml_path: &Path, value: &str, rules_root: &Path) -> Result<PathBuf> {
    if value.contains("..") || Path::new(value).is_absolute() {
        bail!("data file value must be relative filename: {value}");
    }
    let candidate = yaml_path
        .parent()
        .ok_or_else(|| anyhow!("yaml has no parent: {yaml_path:?}"))?
        .join("data")
        .join(value)
        .canonicalize()
        .with_context(|| format!("data file not found: {value}"))?;
    let root_canonical = rules_root.canonicalize()?;
    if !candidate.starts_with(&root_canonical) {
        bail!("data file resolves outside rules_dir: {candidate:?}");
    }
    Ok(candidate)
}
```

### Data file registry

```rust
// crates/waf-engine/src/rules/data_file_registry.rs (new module)
pub struct DataFileRegistry {
    cache: parking_lot::Mutex<HashMap<PathBuf, CachedAc>>,
    reverse_index: parking_lot::Mutex<HashMap<PathBuf, HashSet<String>>>, // data_path -> rule_ids
}

struct CachedAc { mtime: SystemTime, size: u64, ac: Arc<AhoCorasick> }

const MAX_DATA_FILE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_PATTERNS: usize = 100_000;

impl DataFileRegistry {
    pub fn load_or_get(&self, path: &Path) -> Result<Arc<AhoCorasick>> {
        let meta = fs::metadata(path)?;
        if meta.len() > MAX_DATA_FILE_BYTES { bail!("data_file_too_large"); }
        let mut cache = self.cache.lock();
        if let Some(c) = cache.get(path) {
            if c.mtime == meta.modified()? && c.size == meta.len() {
                return Ok(c.ac.clone());
            }
        }
        let patterns = read_patterns(path)?;
        if patterns.len() > MAX_PATTERNS { bail!("too_many_patterns"); }
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(&patterns)?;
        let arc = Arc::new(ac);
        cache.insert(path.to_owned(), CachedAc { mtime: meta.modified()?, size: meta.len(), ac: arc.clone() });
        Ok(arc)
    }

    pub fn register_rule(&self, path: &Path, rule_id: &str) {
        self.reverse_index.lock()
            .entry(path.to_owned())
            .or_default()
            .insert(rule_id.to_owned());
    }
}

fn read_patterns(path: &Path) -> Result<Vec<String>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect())
}
```

Mirror idiom from `crates/waf-engine/src/checks/sensitive.rs:51` (`AhoCorasickBuilder` + `ascii_case_insensitive` + `MatchKind::LeftmostFirst`).

## Related Code Files

- **Modify:**
  - `crates/waf-engine/src/rules/engine.rs` (lines 263, 422, 584, 725, 880-953, 1120, multiple `specialised_op: None` constructor sites)
  - `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs` (lines 160-202, 246-258 — delete `is_specialised_operator`, route all four ops through condition path)
  - `crates/waf-engine/src/rules/registry.rs` / `manager.rs` (wire `DataFileRegistry` into rule loader)
- **Create:**
  - `crates/waf-engine/src/rules/data_file_resolver.rs`
  - `crates/waf-engine/src/rules/data_file_registry.rs`
- **Delete (within files):**
  - `eval_specialised()` function (engine.rs:1120)
  - `CustomRule.specialised_op` field (engine.rs:263)
  - `is_specialised_operator()` function (custom_rule_yaml.rs:255)
  - The `(PmFromFile | ContainsAny, _) => bail!` arm (engine.rs:941)

## Implementation Steps

1. **Add modules without breaking anything.** Create `data_file_resolver.rs` and `data_file_registry.rs`. Wire them into `mod.rs`. `cargo check` clean. No behaviour change yet.

2. **Add `ConditionValue::AhoCorasick` variant.** Update all `match` sites in `engine.rs` to handle it (most will be `_ => bail!` — fine). `cargo check` clean.

3. **Add `Matcher::PatternSet` / `PatternList` variants + matches() arms.** `cargo check` clean. Snapshot tests still green (no path uses these yet).

4. **Add the `compile_condition` arms** for `(PmFromFile, AhoCorasick)` and `(ContainsAny, AhoCorasick)`. Leave existing `(PmFromFile | ContainsAny, _) => bail!` arm in place for now — both arms coexist.

5. **Move multi-field `"all"` semantics out of `eval_specialised`** into the generic condition evaluator. Snapshot tests must stay green at this step. Run `cargo test sqli_xss_behavior_snapshot`.

6. **Switch YAML parser routing** in `custom_rule_yaml.rs`: stop populating `specialised_op`; emit `Condition` for all four operators. Both code paths exist briefly — old `specialised_op` field is set to `None` everywhere, new conditions carry the work.

7. **Run full test suite.** Phase 1 pinning tests should now turn GREEN. Phase 1 snapshot tests stay GREEN. Existing tests stay GREEN.

8. **Delete the dual path.** Now that all rules flow through `Condition`:
   - Delete `eval_specialised()` (engine.rs:1120-end-of-fn).
   - Delete `engine.rs:584` dispatch branch.
   - Delete `CustomRule.specialised_op` field and every `specialised_op: None` constructor.
   - Delete `is_specialised_operator()` from `custom_rule_yaml.rs`.
   - Delete the `(PmFromFile | ContainsAny, _) => bail!` arm at engine.rs:941 — it's now unreachable because the `(op, V::AhoCorasick)` arms handle these.

9. **`cargo check` + `cargo fmt --all` + full test suite.** Every test green. No `unwrap` / `expect` introduced in production code.

10. **URL-decode coverage.** Apply `detect_with_decode()` wrap to `PatternSet`/`PatternList` for path/query/cookie/header fields. Re-run `pm_from_file_pinning` — `/%2Eenv` case must now pass.

## Success Criteria

- [ ] Phase 1 pinning tests turn green (was red).
- [ ] Phase 1 snapshot tests stay green (no DetectSqli/DetectXss drift).
- [ ] `cargo grep -n "specialised_op\|eval_specialised\|is_specialised_operator"` returns ZERO matches in `crates/waf-engine/src/`.
- [ ] `cargo check -p waf-engine` clean, zero warnings.
- [ ] `cargo test -p waf-engine` all green.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] No new `.unwrap()` / `.expect()` in production code (grep diff).
- [ ] Data file path traversal test: rule with `value: "../../etc/passwd"` is REJECTED at load with structured error.

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| `DetectSqli`/`DetectXss` semantic drift when leaving `eval_specialised` | **High** | Phase 1 snapshot test suite is the gate. Don't merge until snapshot green. |
| `"all"` field semantics regress (path → query → body → header order) | **High** | Mirror exact iteration order from current `eval_specialised`. Add explicit test per field. |
| Data-file path traversal via crafted YAML | Medium | Resolver rejects `..` and absolute paths; canonicalise + `starts_with(rules_root)` check. Add negative tests. |
| OOM on large `.data` file | Medium | 10 MB cap + 100k pattern cap. Rule load fails with reason; process survives. |
| `ConditionValue` enum bloat | Low | Arc-wrapped. `size_of::<ConditionValue>()` regression test (optional). |
| Hidden caller of `eval_specialised` outside engine.rs | Low | `cargo check` would catch missing symbol. Grep before delete to confirm. |

## Out of Scope

- Admin UI changes (Phase 3).
- Hot reload of `.data` files (Phase 4).
- New Prometheus metrics (Phase 5).
- New operators beyond the fix.
