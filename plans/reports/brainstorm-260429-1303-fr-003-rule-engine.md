# Brainstorm Report — FR-003 Rule Engine Completion

**Date:** 2026-04-29
**Branch:** feat/fr-002 (next: feat/fr-003)
**Source:** `analysis/requirements.md` §3.1 FR-003
**Target:** `crates/waf-engine/src/rules/engine.rs` + `formats/yaml.rs` + `RequestCtx`

---

## 1. Problem Statement

FR-003 acceptance: *Match by IP, Path, Header, Payload, Cookie; regex, wildcard, exact match, AND/OR.*

Current engine covers most criteria but has 4 gaps:

| Gap | Current | Required |
|---|---|---|
| Wildcard operator | absent | glob (`*.png`, `/api/*/users`) |
| Cookie field | whole header string | per-cookie name lookup |
| Regex | recompiled per request | pre-compiled at load |
| AND/OR nesting | flat only | nested groups (user-selected scope) |

---

## 2. Approaches Considered

### A. Minimum-viable (rejected by user)
Wildcard + cookie-by-name + pre-compile. Flat AND/OR retained.
- Pro: 1 day, low risk.
- Con: rules like `(country=CN AND ua~bot) OR ip in blacklist` need two separate rules.

### B. AC + nested AND/OR groups (CHOSEN)
Adds `ConditionNode` recursive enum on top of A.
- Pro: expressive, single rule per intent, future-proof for FR-023 scoping.
- Con: ~+0.5 day, schema migration for DB JSON column.

### C. AC + full-body matching (rejected)
Stream/buffer entire body. Risk: NFR p99<=5ms, memory blowup. YAGNI for hackathon.

---

## 3. Recommended Design

### 3.1 New crate dep
`globset = "0.4"` — already pulled transitively by `ignore`; add direct dep.

### 3.2 Schema changes (`engine.rs`)

```rust
// NEW: recursive condition tree
pub enum ConditionNode {
    Leaf(Condition),
    And(Vec<ConditionNode>),
    Or(Vec<ConditionNode>),
    Not(Box<ConditionNode>),   // free with the recursion
}

// Cookie field becomes name-aware
pub enum ConditionField {
    // ...existing variants...
    Cookie(Option<String>),    // None => whole cookie header (back-compat)
    // ...
}

// Wildcard joins the operator family
pub enum Operator {
    // ...existing...
    Wildcard,                  // value compiled as GlobMatcher
}

// Compiled rule (stored in cache, not DB)
pub struct CompiledRule {
    pub meta: CustomRule,                 // existing fields
    pub root: CompiledNode,               // tree of compiled conditions
}

pub enum CompiledNode {
    Leaf(CompiledCondition),
    And(Vec<CompiledNode>),
    Or(Vec<CompiledNode>),
    Not(Box<CompiledNode>),
}

pub struct CompiledCondition {
    pub field: ConditionField,
    pub matcher: Matcher,                 // pre-compiled
}

pub enum Matcher {
    Eq(String), Ne(String),
    Contains(String), NotContains(String),
    StartsWith(String), EndsWith(String),
    Regex(regex::Regex),                  // compiled once
    Glob(globset::GlobMatcher),           // compiled once
    InList(ahash::HashSet<String>),       // O(1) lookup
    NotInList(ahash::HashSet<String>),
    Cidr(ipnet::IpNet),
    Gt(i64), Lt(i64), Gte(i64), Lte(i64),
}
```

### 3.3 Backward compat (DB + YAML)
- DB `conditions` JSON: detect old flat array vs new tree by shape — old `[Condition,...]` wrapped as `And([Leaf,...])` by `from_db_rule()`.
- YAML supports both:
  ```yaml
  # old (still works)
  condition_op: and
  conditions: [{field: path, op: starts_with, value: /admin}]

  # new
  match:
    or:
      - {field: ip, op: cidr_match, value: 10.0.0.0/8}
      - and:
          - {field: cookie, name: session, op: eq, value: bad}
          - {field: path, op: wildcard, value: "/api/*/admin"}
  ```

### 3.4 RequestCtx augmentation (`waf-common`)
Parse cookies once at ctx build:
```rust
pub struct RequestCtx {
    // ...existing...
    pub cookies: HashMap<String, String>,   // parsed from "cookie" header
}
```
Avoids re-splitting `cookie:` header per condition.

### 3.5 Field-value lookup
Replace `field_value()` String allocation with `Cow<'_, str>` to skip clone for headers/path.

---

## 4. Files Touched

| File | Change |
|---|---|
| `crates/waf-engine/src/rules/engine.rs` | New types, compile step, eval recursion, tests |
| `crates/waf-engine/src/rules/formats/yaml.rs` | Parse new `match:` tree |
| `crates/waf-engine/src/rules/formats/json.rs` | Same for JSON |
| `crates/waf-engine/src/rules/manager.rs` | Call `compile_rule()` before insert |
| `crates/waf-common/src/lib.rs` | `RequestCtx.cookies` field |
| `crates/waf-engine/Cargo.toml` | + `globset = "0.4"` |
| `rules/custom/*.yaml` | Sample rules using wildcard/nested |
| `crates/waf-engine/tests/rule_engine_acceptance.rs` | NEW: AC test per matrix |

Est. total: ~600 LoC delta (mostly the recursive eval + tests).

---

## 5. Acceptance Test Matrix (each as a test case)

| # | Field | Operator | Sample value | Expected |
|---|---|---|---|---|
| 1 | ip | cidr_match | 10.0.0.0/8 | match 10.1.2.3 |
| 2 | path | exact (eq) | /login | match /login only |
| 3 | path | wildcard | /api/*/admin | match /api/v1/admin, miss /api/admin |
| 4 | path | regex | `^/user/\d+$` | match /user/42 |
| 5 | header(x-foo) | contains | bar | match `X-Foo: foobar` |
| 6 | cookie(session) | eq | abc | match `Cookie: session=abc; other=x` |
| 7 | body | contains | `<script>` | match payload preview |
| 8 | nested AND/OR | — | `(ip OR cookie) AND wildcard` | per truth table |

---

## 6. Risks & Mitigation

| Risk | Mitigation |
|---|---|
| Schema migration breaks existing DB rules | Wrap legacy flat arrays as implicit `And` in `from_db_rule()` — no DB migration needed |
| Pre-compile cost on hot-reload spike | Compile errors logged, rule skipped (not crash); `swap_from` keeps old set live until new ready |
| Glob semantics surprise users | Document syntax in `rules/README.md`; reject empty/`**`-only patterns |
| Cookie parser allocations | Parse once into `RequestCtx.cookies`; share via `Arc` if needed |

---

## 7. Success Criteria

1. All 8 AC test cases pass.
2. `cargo bench` rule_eval shows regex eval ≥ 5x faster (no recompile).
3. Existing DB rules continue to evaluate identically (regression test).
4. Hot-reload still sub-second on 1k rule file.
5. p99 added latency from rules engine ≤ 0.5ms at 5k req/s (NFR proxy).

---

## 8. Out of Scope (deferred)

- Full body streaming match (FR-020 territory).
- Per-route/IP/session/fingerprint scoping (FR-023 — separate plan).
- Risk score deltas per rule (FR-022 / FR-026 — separate plan).
- TOML format (FR-022 — YAML covers it for now).

---

## 9. Next Step

If approved → invoke `/ck:plan` to produce phased implementation plan in
`plans/260429-1303-fr-003-rule-engine/` with phases:

1. Schema + compile step (no behavior change yet).
2. Wildcard operator + globset dep.
3. Cookie-by-name + RequestCtx.cookies.
4. Nested AND/OR + YAML/JSON parsers.
5. AC test suite + bench.
6. Docs + sample rules.

---

## Unresolved Questions

1. Should `Matcher::Regex` support `RegexSet` for batched evaluation when many rules share field? (perf bonus, not AC)
2. Cookie name matching — case-sensitive (RFC 6265) or relaxed? Default proposal: **case-sensitive** per RFC.
3. Glob path matching — should `*` cross `/` boundaries? Default proposal: **no** (use `**` for that), matching `globset` defaults.
