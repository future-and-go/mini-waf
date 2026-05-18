# Prediction Report: YAML Rule Format Consolidation

**Proposal:** Consolidate Registry Rules and CustomRule into unified `custom_rule_v1` format  
**Source:** `plans/reports/brainstorm-260516-2224-yaml-format-consolidation.md`

---

## Verdict: CAUTION

Proceed with modifications. Core approach is sound, but pattern evaluation against all fields has performance implications requiring optimization.

---

## Agreements (all personas align)

1. **Format consolidation is correct** — Maintaining two incompatible YAML formats creates technical debt and silent data loss
2. **CustomRule v1 is right target** — Version discriminator (`kind:`) provides forward compatibility, nested boolean logic is more powerful
3. **Big-bang migration is acceptable** — 84 files is manageable; incremental migration adds complexity without benefit
4. **`deny_unknown_fields` is essential** — Prevents future schema drift that caused this issue
5. **Pre-compile regex at load time** — Already done in CompiledRule; pattern field should follow same path

---

## Conflicts & Resolutions

| Topic | Architect | Security | Performance | UX/DX | Devil's Advocate | Resolution |
|-------|-----------|----------|-------------|-------|------------------|------------|
| Pattern matches "all fields" | Implicit behavior is confusing | Attack surface: unintended matches on headers | **Critical**: 5+ field checks per request is expensive | Simple to understand for rule authors | Why not require explicit field targeting? | **Add `pattern_fields` option** with sensible default (path+query+body) |
| Adding pattern to CustomRule | Creates two paradigms (pattern vs conditions) | Pattern is simpler = fewer config mistakes | Pattern evaluation is O(1) per field vs tree traversal | Pattern is familiar from Registry format | Just convert patterns to regex conditions | **Keep pattern** — backward compat matters; document as "legacy shorthand" |
| Migration script as Rust binary | Overkill for one-time script | Rust guarantees type safety during conversion | N/A | Python/bash would be faster to write | Just write a jq/yq script | **Use Rust** — can reuse existing serde types, compile-time validation |
| Delete Registry parser immediately | Clean break, single source of truth | Reduces attack surface (less code) | N/A | Abrupt for users mid-migration | Keep both for 1 release cycle | **Delete after migration** — add deprecation log if loaded |

---

## Individual Persona Analysis

### Architect

**Assessment:** APPROVE with changes

**Strengths:**
- Discriminated union pattern (`kind:`) is industry best practice for schema evolution
- Evaluation precedence (match_tree → conditions → pattern) is clearly defined
- Single source of truth reduces maintenance burden

**Concerns:**
1. **Dual matching paradigm**: Pattern field + conditions creates API surface ambiguity
   - Mitigation: Document pattern as "legacy shorthand for regex condition on body+query+path"
2. **No field targeting for pattern**: Implicit "match all" violates explicit-is-better principle
   - Mitigation: Add `pattern_fields: ["body", "query", "path"]` with default

**Recommendation:** Add explicit `pattern_fields` configuration

### Security

**Assessment:** APPROVE with mandatory changes

**Strengths:**
- `deny_unknown_fields` prevents future silent data loss
- Version discriminator blocks injection of future schema fields
- Regex pre-compilation at load time prevents ReDoS during request processing

**Concerns:**
1. **ReDoS via pattern expansion**: Matching complex regex against body + headers + cookies multiplies attack surface
   - Mitigation: Limit pattern check to path+query+body (not headers/cookies)
   - Mitigation: Add regex complexity check at load time (flag catastrophic backtracking)
2. **Migration data loss**: Silent field drops during conversion could remove security rules
   - Mitigation: Validate rule count AND pattern content before/after migration
3. **Header matching unintended**: Pattern `10\..*` meant for SSRF could match `X-Request-Id: abc10.xyz`
   - Mitigation: Default `pattern_fields` excludes headers

**Recommendation:** Mandatory regex complexity check + exclude headers from default pattern_fields

### Performance

**Assessment:** CAUTION — requires optimization

**Strengths:**
- Pattern evaluation is last resort (after match_tree/conditions)
- Pre-compiled regex avoids per-request compilation
- Existing CompiledRule pattern for pattern field

**Critical Concerns:**
1. **5+ field checks per pattern match**: Path + query + body + headers + cookies
   ```
   // Proposed — O(n) where n = total bytes in all fields
   pattern.is_match(&req.path)                           // ~100 bytes
       || pattern.is_match(&req.query)                   // ~500 bytes  
       || pattern.is_match(&req.body)                    // ~10KB typical
       || req.headers.iter().any(|(_, v)| pattern.is_match(v))  // ~2KB, 20+ iterations
       || req.cookies.values().any(|v| pattern.is_match(v))     // ~500 bytes
   ```
   - **Worst case**: 84 rules × 5 field categories × large body = significant overhead
   
2. **Short-circuit order matters**: Check smallest fields first (path → query → cookies → headers → body)

3. **Body matching is expensive**: Most SSRF/injection patterns target body; checking path/headers first is wasted work

**Recommendations:**
1. Default `pattern_fields: ["body", "query", "path"]` — exclude headers/cookies
2. If body-only matching needed, add `pattern_fields: ["body"]` option
3. Consider `pattern_scan_limit: 65536` to cap bytes scanned per field

### UX/DX (Developer Experience)

**Assessment:** APPROVE

**Strengths:**
- Single format is easier to learn and document
- Keeps familiar subdirectory organization (`rules/custom/advanced/`)
- Pattern field provides backward compatibility for simple rules
- Paranoia as metadata-only simplifies understanding

**Concerns:**
1. **Learning curve**: Existing Registry users need to learn `kind: custom_rule_v1` syntax
   - Mitigation: Provide migration guide in README
2. **Error messages**: "rule has no match logic, always matching" warning unclear
   - Mitigation: Improve to "rule {id} has no pattern, conditions, or match_tree — it will match all requests"

**Recommendation:** Improve error messages; add migration examples to README

### Devil's Advocate

**Assessment:** CHALLENGE the approach

**Alternative 1: Just fix the Registry parser**
- The wrapper `{version, rules: [...]}` issue is a 5-line parser fix
- Add missing fields to YamlRule struct (paranoia, field, operator, value)
- Keep both parsers, no migration needed
- **Counter:** This perpetuates two formats; technical debt compounds

**Alternative 2: Deprecate pattern entirely**
- Force explicit conditions: `conditions: [{field: body, operator: regex, value: "..."}]`
- Pattern field is syntactic sugar that obscures what's being matched
- **Counter:** Breaks 84+ existing rules; migration script becomes complex

**Alternative 3: Pattern → auto-convert to condition at parse time**
- Parse `pattern: X` as `conditions: [{field: body, operator: regex, value: X}]`
- No runtime pattern evaluation needed; conditions path handles it
- **Counter:** Loss of "match all fields" behavior some rules may rely on

**Verdict:** Alternatives have merit but consolidation is cleaner long-term. Proceed with pattern optimization.

---

## Risk Summary

| Risk | Severity | Mitigation |
|------|----------|------------|
| Pattern matches unintended fields (headers/cookies) | High | Add `pattern_fields` option; default to body+query+path |
| ReDoS from complex patterns on large bodies | Medium | Add regex complexity check at load time |
| Rule logic changes during migration | Medium | Integration tests comparing old vs new behavior |
| Performance regression from pattern-all-fields | Medium | Short-circuit evaluation; field targeting |
| Migration data loss (silent field drops) | Low | Rule count validation; content diff review |
| Breaking existing deployments | Low | Deprecation log before parser deletion |

---

## Recommendations

### Mandatory (address before proceeding)

1. **Add `pattern_fields` option to CustomRule** — Default `["body", "query", "path"]`, allow override per-rule
   ```yaml
   pattern: "10\\..*"
   pattern_fields: ["body"]  # Only check body, not all fields
   ```

2. **Add regex complexity check at load time** — Reject patterns with catastrophic backtracking potential
   ```rust
   fn validate_pattern(pattern: &str) -> Result<()> {
       let _ = Regex::new(pattern)?;  // Syntax check
       // TODO: Add complexity heuristic (nested quantifiers, excessive alternation)
       Ok(())
   }
   ```

3. **Optimize short-circuit order** — Smallest fields first
   ```rust
   pattern.is_match(&req.path)
       || pattern.is_match(req.query.as_deref().unwrap_or(""))
       || req.cookies.values().any(|v| pattern.is_match(v))
       || pattern.is_match(req.body.as_deref().unwrap_or(""))
   ```

### Recommended (address in P1-P2)

4. **Improve warning message** — "rule {id} has no pattern, conditions, or match_tree — matches all requests"

5. **Add deprecation log for Registry parser** — Log warn if yaml.rs parser is used, then delete in next release

6. **Add migration validation script** — Compare rule count AND pattern content before/after

### Optional (P3/future)

7. **Pattern scan limit** — `pattern_scan_limit: 65536` caps bytes scanned per field

8. **Auto-convert pattern → condition at parse time** — Removes runtime pattern evaluation path

---

## Updated Implementation Phases

### P0 (Immediate) — 3 days
1. Extend `YamlCustomRule` struct with new fields (pattern, category, severity, paranoia, tags, metadata, reference)
2. **NEW: Add `pattern_fields: Vec<String>` with default `["body", "query", "path"]`**
3. Extend `CustomRule` struct and `from_yaml()` mapping
4. **NEW: Add regex complexity check in `compile_rule()`**
5. Add pattern evaluation to `eval_custom_rule()` with optimized short-circuit order
6. Add `#[serde(deny_unknown_fields)]`

### P1 (Migration) — 2 days
7. Write migration script (`scripts/migrate_yaml_rules.rs`)
8. Run migration on `rules/advanced/` and `rules/owasp-crs/`
9. Move migrated files to `rules/custom/advanced/`, `rules/custom/owasp-crs/`
10. **NEW: Run validation script (rule count + pattern content comparison)**

### P2 (Cleanup) — 1 day
11. Add deprecation warn log to `formats/yaml.rs`
12. Update `rules/README.md` with unified schema docs
13. Add integration test loading all YAML files

### P3 (Deletion) — Next release
14. Delete `formats/yaml.rs` and `formats/json.rs`
15. Update `formats/mod.rs` exports

---

## Appendix: Pattern Fields Implementation

```rust
// YamlCustomRule addition
#[serde(default = "default_pattern_fields")]
pattern_fields: Vec<String>,

fn default_pattern_fields() -> Vec<String> {
    vec!["body".to_string(), "query".to_string(), "path".to_string()]
}

// engine.rs — pattern_matches_request with field targeting
fn pattern_matches_request(&self, pattern: &Regex, fields: &[String], req: &RequestCtx) -> bool {
    for field in fields {
        let matched = match field.as_str() {
            "path" => pattern.is_match(&req.path),
            "query" => pattern.is_match(req.query.as_deref().unwrap_or("")),
            "body" => pattern.is_match(req.body.as_deref().unwrap_or("")),
            "cookies" => req.cookies.values().any(|v| pattern.is_match(v)),
            "headers" => req.headers.iter().any(|(_, v)| pattern.is_match(v)),
            _ => false,
        };
        if matched {
            return true;
        }
    }
    false
}
```
