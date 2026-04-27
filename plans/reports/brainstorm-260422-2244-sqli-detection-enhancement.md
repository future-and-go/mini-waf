# Brainstorm — SQLi Detection Enhancement

Date: 2026-04-22
Outcome: Approved for planning

## Problem Statement
Deliver SQL-injection detection meeting these acceptance criteria: classic, blind, time-based, UNION-based — across URL params, headers, JSON body.

## Reality Check
Existing checker at `crates/waf-engine/src/checks/sql_injection.rs` already covers UNION, time-based (SLEEP/BENCHMARK/WAITFOR/pg_sleep), tautology, stacked queries, comment injection, hex literals, INFORMATION_SCHEMA enum, LOAD_FILE / INTO OUTFILE. Applied to path, query, cookie, body — with recursive URL decoding.

Overlap vs criteria: ~70%. Real gaps: boolean-blind patterns, JSON-body parse awareness, header coverage beyond cookie, per-parameter attribution.

## Decision
**Enhance, not rewrite.** Surgical additions to existing module.

## Design Summary

### 1. Pattern additions (boolean-blind + error-based)
- `(AND|OR) N=N` tautology
- `substring/substr/mid/ascii/length/hex/bin(` — blind extraction
- `if(cond, a, b)` — conditional blind
- `@@version/datadir/hostname/tmpdir` — fingerprint
- `cast(x as ...)`, `convert(x using ...)`, `exp(~(...))` — error-based

### 2. JSON body walker
- Trigger on `Content-Type: application/json`
- `serde_json::from_slice` → walk tree → regex on each string leaf
- Fallback to raw-byte scan on parse failure
- Cap: 256 KB parsed; beyond → raw scan only

### 3. Header scanning
All headers by default. New `SqliScanConfig` struct:
- `scan_headers: bool` (default true)
- `header_denylist: Vec<String>` (default: `content-length`, `content-type`, `host`)
- `header_allowlist: Vec<String>` (if non-empty, overrides denylist)
- `header_scan_cap: usize` (default 4096 bytes per header value)

Hot-reloadable via `ArcSwap`, same pattern as masking plan (`260422-logging-sensitive-data-masking`).

### 4. Per-parameter attribution
Parse `ctx.query` via `form_urlencoded`. Report `detail: "... detected in query param 'id'"` instead of `"... detected in query"`.

### 5. Modularization (file-size rule — 200-line cap)
- `sql_injection.rs` — `SqlInjectionCheck` + Check impl + dispatch
- `sql_injection_patterns.rs` — `RegexSet` + descriptions (pure data)
- `sql_injection_scanners.rs` — `scan_headers`, `scan_json_body`, `scan_query_params`

### 6. Interaction with logging-masking plan
SQLi detection runs on raw `RequestCtx` BEFORE masking. Masking only affects persisted `attack_logs` rows. No pipeline conflict.

### 7. Performance SLO (new acceptance criterion)
- p99 added latency < 500 µs per request vs baseline
- Criterion benchmark in `crates/waf-engine/benches/sql_injection.rs`
- Representative corpus: 100 clean requests + 50 malicious; verify allow-fast-path unchanged

## Alternatives Rejected

| Option | Why rejected |
|--------|--------------|
| libinjection FFI | C dependency, maintenance cost, no measurable accuracy gain over curated regex |
| Full AST via sqlparser-rs | ~10 ms/request parse cost — 200× regex; killing inline WAF latency |
| ML-based classifier | YAGNI; regex + tuning hits 95% real traffic; model lifecycle adds ops burden |
| Differential-response blind detection | Stateful, memory-heavy, latency impact. Not viable inline |

## Risks & Mitigations
- **False positives** on legitimate header values (JWT `==` padding, `Referer` with `select=` params) → per-header denylist + size cap + `LogOnly` action for tuning window before enforcement
- **Regex CPU compounding** → anchor patterns, non-greedy, RegexSet (single DFA pass); benchmark gates merge
- **JSON bomb / deep nesting** → cap parse size to 256 KB, serde_json has recursion limit built-in
- **Evasion via JSON unicode escapes** → cheap unescape pre-pass before regex

## Acceptance Criteria (Final)
1. Classic SQLi: tautology, comment, stacked — detected in URL params, headers, JSON body
2. Blind SQLi: boolean-blind pattern + extraction functions — detected in all three locations
3. Time-based: SLEEP/BENCHMARK/WAITFOR/pg_sleep — detected in all three
4. UNION-based: `UNION SELECT` — detected in all three
5. Header allowlist/denylist hot-reloadable via admin API
6. p99 latency add < 500 µs; bench committed to repo
7. Zero regression in existing passing tests

## Out of Scope (v1)
- NoSQL / GraphQL injection
- Differential-response blind detection
- ML-based classification
- DB schema changes

## Success Metrics
- All acceptance criteria covered by unit tests (20+ cases)
- Integration test end-to-end through engine
- Bench p99 < 500 µs on workstation-class hardware
- No clippy warnings, no fmt drift
- Manual OWASP CRS SQLi sample file passes detection

## Next Steps
Invoke `/ck-plan` with this report as context to generate phased plan. Phase structure proposed:
1. Pattern additions + modularization
2. JSON body walker + query param splitter
3. Header scanning + `SqliScanConfig` + hot-reload
4. Benchmark harness + acceptance tests

## Open Questions
- Confirm `url::form_urlencoded` is already a transitive workspace dep — grep `cargo tree` before planning phase 02
- Decide: global `SqliScanConfig` vs per-host override? (Recommend global v1 to match existing `defense_config.sqli` toggle granularity)
- Bench hardware baseline: CI runner vs dev workstation? (Proposed: dev workstation with documented CPU model)
