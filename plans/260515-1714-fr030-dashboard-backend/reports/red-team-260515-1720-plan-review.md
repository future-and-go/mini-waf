# Red-Team Review: FR-030 Dashboard Backend Plan

**Reviewer:** code-reviewer (adversarial mode)
**Date:** 2026-05-15
**Plan dir:** `plans/260515-1714-fr030-dashboard-backend/`
**Scope:** plan.md + phases 01-05 vs. actual repo HEAD.

## Verdict

**NO_GO** — must be revised before phase 2 starts.

The plan has two SHOWSTOPPER correctness bugs and several blocking risks. The "DRY refactor" as written will **silently change the existing dashboard's category strings** (FE will break) and the new `get_stats_overview` filtered subquery cannot compile against Postgres as written. The proposed `0009` migration is also factually incompatible with current data because the prefix list in the plan doesn't match the production CASE expression.

These are not nitpicks: phase 2 step 1 would land code that changes user-visible response shape AND fails at runtime. Block phase 2 until the critical findings below are corrected.

---

## Critical Findings (must fix before phase 2)

### F1. Migration `0009_category_function.sql` does NOT mirror the existing CASE expression — backward compat will silently break the frontend

**File:** `phase-02-storage-layer.md` step 1 (lines 91-133)
**Ground truth:** `crates/waf-storage/src/repo.rs:987-1108` (two existing inline CASEs).

The plan asserts "all 28 branches mirrored." It is **not 28**, and the prefixes do not match. Concrete drift detected:

| Plan migration says | Production code actually says |
|---|---|
| `WHEN 'PATH-%' THEN 'path_traversal'` | `WHEN 'TRAV-%' THEN 'path-traversal'` |
| `WHEN 'SCAN-%' THEN 'scanner'` | `WHEN 'SCAN-%' THEN 'scanner'` ✓ |
| `WHEN 'BOT-%' THEN 'bot'` | `WHEN 'BOT-%' THEN 'bot'` ✓ |
| `WHEN 'CCDDOS-%' THEN 'cc_ddos'`, `WHEN 'DDOS-%' THEN 'cc_ddos'` | `WHEN 'CC-%' THEN 'cc-ddos'` (NOT `CCDDOS`, NOT `DDOS`) |
| `WHEN 'OWASP-%' THEN 'owasp_crs'`, `WHEN 'CRS-%' THEN 'owasp_crs'` | `WHEN 'CRS-RESP%' THEN 'data-leakage'`, `WHEN 'CRS-%' THEN 'owasp-crs'`, and 7 specific `OWASP-94x/93x/91x` lines mapping to `sqli/xss/lfi/rfi/rce/php-injection/scanner` — none of which the plan includes. |
| `'auth'`, `'brute_force'`, `'geo_block'`, `'ip_block'`, `'user_agent'`, `'method_block'`, `'header_anomaly'`, `'protocol'`, `'size_limit'`, `'rate_limit'`, `'csrf'`, `'xxe'`, `'ssrf'`, `'deserialization'` | **None of these exist in production code.** Inventing them is a violation of the plan's own rule: "existing is source of truth — never invent new categories." |
| Missing in plan | Production has: `ADV-SSRF` → `ssrf`, `ADV-SSTI` → `ssti`, `ADV-%` → `advanced`, `CRS-RESP` → `data-leakage`, `API-MASS` → `mass-assignment`, `API-%` → `api-security`, `MODSEC-RESP` → `web-shell`, `MODSEC-%` → `modsecurity`, `CVE-%` → `cve`, `GEO-%` → `geo-blocking`, `IP-%` → `ip-rule`, `URL-%` → `url-rule`, `SENS-%` → `sensitive-data`, `HOTLINK-%` → `anti-hotlink`. |
| Hyphen vs underscore | Production uses **hyphen**: `path-traversal`, `cc-ddos`, `owasp-crs`. Plan uses **underscore**: `path_traversal`, `cc_ddos`, `owasp_crs`. |

**Consequence:** Even if the migration is written, the frontend pie chart category labels will silently change from `"path-traversal"` → `"path_traversal"`, the actual `TRAV-001` rule (`crates/waf-engine/src/checks/dir_traversal.rs:102`) will fall through to `'other'`, etc. This is a hard backward-compatibility break that the planner's "Validation Gate Q4" claims to prevent but does not.

**Fix:** Phase 2 step 1 MUST be rewritten:
1. Copy the EXACT 30-branch list from `repo.rs:989-1020` (category_breakdown) verbatim. The recent_events CASE at `repo.rs:1073-1104` is identical — sanity-diff them line for line.
2. Use HYPHENS in category strings (`path-traversal`, `cc-ddos`, `owasp-crs`).
3. Keep prefix ORDER identical (`CRS-RESP%` must precede `CRS-%`, `ADV-SSRF%` must precede `ADV-%`, etc.) — order matters because LIKE matches first-wins.
4. The Validation Gate Q2 ("acceptable?") must include "verified prefix list matches production byte-for-byte" — current gate doesn't check this.

### F2. `get_stats_overview` filter SQL will not compile at runtime — wrong cast

**File:** `phase-02-storage-layer.md` step 4 (lines 294-311)

```sql
WHERE ... AND ($1::BIGINT IS NULL OR created_at >= NOW() - ($1 || ' hours')::INTERVAL)
```

With `$1` bound to `Option<i64>`, sqlx will send `BIGINT` (`int8`). Postgres does **not** implicitly coerce `bigint || text` — you get `ERROR: operator does not exist: bigint || text`. Two ways this blows up:

1. If `$1` is `NULL`, the short-circuit may or may not skip the second branch evaluation. Postgres can still try to type-check the whole expression at parse time, and even at execute time `Option::None` typically renders as `NULL::bigint`, which still doesn't help `||`.
2. The existing pattern (`repo.rs:1161`) is `make_interval(hours => $1::int)` — **use that**.

**Fix:**

```sql
WHERE ... AND ($1::BIGINT IS NULL
               OR created_at >= NOW() - make_interval(hours => $1::int))
```

This consistency also avoids the rough mismatch between heatmap query (`$1::INTERVAL` cast on a `format!("{} hours", ...)` string) and overview query (`make_interval`). Use ONE pattern everywhere.

### F3. Heatmap CTEs are correlated incorrectly — `category_list` is fetched but never enforced when an event has a rule_id outside top-12

**File:** `phase-02-storage-layer.md` step 3 (lines 199-235)

The query computes `category_list` (top-12 categories) but the final SELECT filters with:
```sql
AND category_of(se.rule_id) IN (SELECT category FROM category_list)
```

This silently DROPS events whose category is outside top-12 instead of bucketing them as `'other'`. The researcher's recommendation (researcher-heatmap-data-model.md §Q4) explicitly says "include all categories + rollup tail as `other`":

> Logic uses `CASE WHEN category IN (top12) THEN category ELSE 'other' END`.

The plan's implementation DROPS the tail. `total_events` returned in metadata will therefore not equal sum-of-cells — and the dashboard will show inconsistent totals. Worse, it changes per call (top-12 set varies).

**Fix:** Either
- (a) Replace the `IN (...)` filter with `CASE WHEN category_of(rule_id) IN (...) THEN category_of(rule_id) ELSE 'other' END` and remove the filter, OR
- (b) Document that `total_events` represents only the in-top-12 subset and add a separate `total_events_all` metadata field. Option (a) is what the researcher specified.

Either way the plan must be explicit.

### F4. Heatmap query has unbound `$1::INTERVAL` cast — passing `"24 hours"` from Rust works, but the **NULL-safe filter pattern is missing**

**File:** `phase-02-storage-layer.md` step 3 (lines 199-235)

`HeatmapFilter.hours` is `i64` (non-optional, clamped 1..=720). So the bind is always a populated string. OK so far. But the new endpoint allows `hours` query param to be absent (→ default 24). What about `host_code=&action=` (empty strings)? Axum `Query<EndpointsQuery>` will likely deserialize an empty string as `Some("")`, not `None`. Then the SQL `($2::TEXT IS NULL OR host_code = $2)` becomes `host_code = ''`, which matches nothing. So `GET /api/stats/endpoints?host_code=` would silently return empty.

**Fix:**
- In `stats_endpoints` and `stats_overview` handlers, normalize empty strings to `None` *before* building the filter. Or use `serde` `deserialize_with` to map `""` → `None`. Phase 3 must specify which.

### F5. `get_stats_overview` total_requests / total_blocked computation is anchored to `attack_logs` which **has no `host_code` filter applied** in the plan's filter rewrite

**File:** `phase-02-storage-layer.md` step 4 list "1. total_requests (count over `attack_logs` or `security_events` — match existing)"

Looking at production code (`repo.rs:883-900`):
- `total_blocked_logs` counts `attack_logs.action='block'`
- `total_blocked_events` counts `security_events.action='block'`
- `total_allowed` counts `attack_logs.action='allow'` (note: `attack_logs` only!)
- `total_requests = total_blocked + total_allowed`

Now if `StatsFilter { host_code: Some("h1") }` arrives, the plan says "thread filter through all 10 subqueries." But `attack_logs` and `security_events` have **divergent schema/semantics**:
- `attack_logs.client_ip` is `INET`, `security_events.client_ip` is `TEXT`.
- `attack_logs` action set might differ from `security_events`.
- Some subqueries are on `attack_logs`, some on `security_events`.

Threading `host_code` is OK (both have it as TEXT), but threading `action` to `attack_logs` may be technically fine yet semantically inconsistent. The plan does not list which subqueries are on which table, and the planner says "match existing" — but "existing" is the current code that has NO filtering. The risk: a host filter applied to `security_events` but not consistently to `attack_logs` produces nonsensical totals (e.g., `total_blocked` filtered by host but `total_allowed` not filtered).

**Fix:** Phase 2 step 4 must enumerate each of the 10 subqueries and say:
- Which table?
- Which filter columns apply?
- Does each subquery use `make_interval(hours => $1::int)` for `created_at` filtering?

The current "apply same 3-bind pattern to every subquery" is hand-wavy. Without this the refactor will silently produce wrong aggregates under any non-default filter.

### F6. The recent_events query uses `LIMIT 20` — with filters, this still applies; **frontend will get fewer recent events than expected when filtering**

**File:** `phase-02-storage-layer.md` step 4

`recent_events` (`repo.rs:1062-1109`) returns the last 20 events. If we filter `?host_code=h1` and h1 has fewer than 20 recent events, the response shrinks. Is that the desired behavior? Probably yes (the user asked for h1 only), but the plan does not explicitly call this out, and the snapshot test in phase 4 won't catch it (snapshot test is for *no params* call only).

**Fix:** Phase 4 add an explicit test: `overview_host_filter_returns_subset_of_recent_events`.

### F7. Validation gate Q3 ("Docker test pattern unchanged") is wrong about CI

**File:** `phase-01-brainstorm-redteam-validate.md` step 3, Q3.

The validation gate claims testcontainers is the CI pattern. **It is not.** Looking at `.github/workflows/coverage.yml:22-35` — CI uses a `postgres` SERVICE, not testcontainers. Testcontainers requires `docker.sock` mounted into the runner, which the coverage workflow doesn't expose.

Why this matters: phase 4 says "all tests run via testcontainers". The new test files (`repo_endpoint_heatmap.rs`, `handler_stats_endpoints.rs`, etc.) will spin testcontainers locally and pass — but on CI, `cargo llvm-cov` calls `cargo test` which will try to start `postgres:16-alpine` containers, and may or may not work depending on the runner's docker config. The existing `crates/waf-storage/tests/common/mod.rs` does use testcontainers and these tests presumably already work on CI, but the coverage workflow has a separate Postgres service running on port 5432 — there's a fixture conflict to investigate.

**Fix:**
- Phase 1 gate Q3 must be re-answered with an actual look at `.github/workflows/coverage.yml`.
- Phase 4 step 6 must confirm CI runs testcontainer-based tests by either:
  (a) Adding a CI step that exposes docker.sock to the workflow runner, OR
  (b) Switching the tests to use the existing CI postgres service via `DATABASE_URL` env var.
- If neither works the 90% coverage target is unmeasurable on CI for new code.

### F8. Coverage gate "90% on new code" has no automated CI enforcement

**File:** `phase-04-tests-90pct.md` step 7

The coverage workflow (`.github/scripts/coverage-check.sh`) enforces a per-crate FLOOR (78% for `waf-api`, 82% for `waf-storage`). It does NOT have a "new code only" filter. The plan says "Confirm ≥90%" via "manual inspection of `coverage/html/index.html`" — this is honor-system. CI cannot reject a PR that adds new low-coverage code as long as the per-crate floor still holds.

**Fix:** Either:
- (a) Add `--fail-under-lines=90` to the new test commands (but this measures whole crate, not new code), OR
- (b) Use `cargo llvm-cov --fail-under-files 90 --include-files 'crates/waf-storage/src/repo.rs,crates/waf-api/src/stats.rs'` (verify llvm-cov supports this), OR
- (c) Add a CI step that runs `cargo llvm-cov --json` and parses per-file coverage with a script that fails if any of the 5 listed files is <90%. This is a 30-line bash script.

Without one of these the 90% gate is purely aspirational and the rules.md mandate is unfulfilled.

---

## Important Findings (fix before phase 4)

### I1. Phase 4 backward-compat test is too weak: "all original keys present" doesn't catch value-shape drift

**File:** `phase-04-tests-90pct.md` step 5 "Backward-compat snapshot for test #1"

The plan asserts "structural equality via `serde_json::Value` field-by-field" but only checks **key presence**, not value types. If a refactor turns `top_ips: Vec<TopEntry>` into `top_ips: Vec<{ ip: String, count: i64 }>` (slightly different keys inside elements), the outer key still exists.

**Fix:** Test must assert each value's TYPE (e.g., `assert!(v["top_ips"].is_array())`, `assert!(v["top_ips"][0]["key"].is_string())`, `assert!(v["top_ips"][0]["count"].is_i64())`). Also assert `total_requests`, `total_blocked`, `block_rate` types because the handler computes `block_rate` and `total_requests_live`. Also assert `block_rate` falls in `0.0..=1.0`. The plan currently makes no statement about value types.

### I2. Phase 2 risks committing `let mut total: i64 = 0;` + saturating_add — clippy will flag

**File:** `phase-02-storage-layer.md` step 3

`saturating_add` on `i64` accumulator is fine but clippy's `arithmetic_side_effects` allow this. However the `paths.len() as i64` and `cats.len() as i64` casts (`as` cast from `usize` to `i64`) will trigger `clippy::cast_possible_wrap` and `clippy::cast_sign_loss` warnings. CI runs `-D warnings`.

**Fix:** Use `i64::try_from(paths.len()).unwrap_or(i64::MAX)` (Iron Rule #7 allows `.unwrap_or`). Plan phase 5 step 2 lists this as a "common offender" but only as a clippy fix-up — should be in the original phase 2 implementation guidance.

### I3. Heatmap query depends on functional indexes that may NOT exist

**File:** `phase-02-storage-layer.md` step 3

The `category_of(se.rule_id) IN (SELECT ...)` subquery requires recomputing `category_of(rule_id)` per row, then matching against the CTE set. At 1M+ rows in `security_events`, **this is a sequential scan** unless there's an expression index `idx_security_events_category ON security_events (category_of(rule_id))`. There isn't. The researcher claimed "no new index needed" — that's true for the path/host/action/created_at predicates, but NOT true once `category_of()` enters the WHERE clause.

Postgres CAN inline an `IMMUTABLE` PLPGSQL function, but `category_of()` is declared `LANGUAGE plpgsql IMMUTABLE` — and plpgsql functions are **NOT inlined** by Postgres. Only `LANGUAGE SQL IMMUTABLE` functions get inlined. The researcher's claim "0 overhead vs CASE" is WRONG.

**Fix:** Rewrite the function as `LANGUAGE SQL`:
```sql
CREATE OR REPLACE FUNCTION category_of(rule_id TEXT) RETURNS TEXT
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE AS $$
SELECT CASE WHEN $1 LIKE 'SQLI-%' THEN 'sqli' ... END;
$$;
```
- `LANGUAGE SQL IMMUTABLE` → planner inlines, identical to CASE.
- `STRICT` → returns NULL on NULL input (which the plan's NULL-handling table relies on). Wait — the plan's redteam #6 says `category_of(NULL)` returns `'other'`. With `STRICT`, it would return `NULL`. Pick one and be consistent.

Either way, **drop the plpgsql wrapper**; it defeats inlining and likely doubles the heatmap query cost.

### I4. Auth-required test (`endpoints_requires_auth`) — phase 4 lists it but doesn't specify the 401 wire format

**File:** `phase-04-tests-90pct.md` step 4 test #5

`assert resp.status() == 401` is necessary but not sufficient. The current auth middleware may return 403 instead of 401 depending on token state. Phase 4 must specify the exact status code (verify against `crates/waf-api/src/middleware.rs::require_auth`).

### I5. `clamp_hours_default` vs `clamp_hours_optional` — naming creates a footgun

**File:** `phase-03-api-layer.md` step 1

Two helpers differing only in suffix is the kind of name pair that produces wrong-helper-called bugs. The "optional" version returns `Option<i64>` and the "default" version returns `i64`. The compiler will catch swap mistakes only because of the return type. KISS suggests:

```rust
fn clamp_hours(h: i64) -> i64 { h.clamp(1, 720) }
// Caller decides defaulting:
clamp_hours(q.hours.unwrap_or(24))     // for endpoints
q.hours.map(clamp_hours)               // for overview
```

That's one helper with no naming ambiguity.

### I6. Phase 5 squash strategy assumes single commit from start — fallback is inadequate

**File:** `phase-05-pr-ci-hardening.md` step 5

Plan says: "If incremental commits exist, squash via `git rebase -i origin/main`" then immediately notes "NEVER use `-i` rebase in tools — for the human." This is contradictory and effectively says: do interactive rebase manually. CI runs on PR HEAD only, so squash-on-merge would also work — but the plan says "exactly 1 commit at PR open time."

**Fix:** Either (a) commit only once from the start (real plan), OR (b) use `git reset --soft origin/main && git commit -m '...'` which doesn't require `-i`. Plan should pick (b) and document it as the canonical squash.

### I7. Phase 4 coverage test for plpgsql function

**File:** `phase-04-tests-90pct.md` Risk Assessment

"Coverage tool flaky on plpgsql function" is acknowledged but the mitigation is wrong. `cargo llvm-cov` measures Rust line coverage; SQL/plpgsql is invisible to it. The function will count as "covered" only because Rust code that calls it executes. Functional coverage of the 28+ branches requires a separate explicit test (which `repo_category_function.rs` provides — good).

If I3 is accepted and the function becomes `LANGUAGE SQL`, this concern goes away.

### I8. `rules.md` rules not actually fact-checked

**File:** `phase-05-pr-ci-hardening.md` Context Links cite "`rules.md` line 9", "`rules.md` line 3"

I could not locate a `rules.md` at the repo root or in any path the plan references. Search results show only:
- `crates/waf-engine/src/checks/dir_traversal.rs` (no rules.md mention)
- `plans/.../research/...` (no rules.md)

The plan's references to specific line numbers in `rules.md` therefore cannot be verified. If `rules.md` is the user-injected prompt content (as per the hook system reminder), it's ephemeral and shouldn't be cited by file:line.

**Fix:** Either commit the rules.md to the repo or use stable references (e.g., reference the user request directly: "user instruction: PR in English, ...").

---

## Nitpicks (defer if time-pressed)

### N1. Inconsistent metadata field naming

Phase 2 returns `EndpointHeatmap { ..., generated_at: DateTime<Utc> }` (Rust field) but phase 3 serializes as `"timestamp": heatmap.generated_at`. Two names for one thing. Pick one (`generated_at` is conventional in this codebase per existing types). The serde rename happens in the handler `json!` — fine but invites drift.

### N2. `HeatmapFilter` and `StatsFilter` are nearly identical — could be one type

Phase 2 step 2 declares both. The only differences: `hours` is `i64` (required) vs `Option<i64>`. A single struct with `Option<i64>` plus a `with_default_hours(h: i64)` adapter would reduce code. YAGNI argument says keep separate; OK. Note as understood non-issue.

### N3. The PR description in phase 5 is 80 lines, exceeds the "≤60 lines" non-functional req

**File:** `phase-05-pr-ci-hardening.md` step 7 vs requirement line 41

Self-contradiction. Either tighten the body or raise the requirement to "≤90 lines."

### N4. Plan mentions "FR-030 = endpoint heatmap + attack type chart + top attacker IPs"

User's task statement includes "top attacker IPs" as part of FR-030. The plan covers heatmap + filtered overview but **does not call out top attacker IPs as a new deliverable**. The existing `get_stats_overview` already returns `top_ips` — does FR-030 want a new dedicated endpoint, or is reusing `top_ips` from overview sufficient? Plan doesn't say.

**Action:** Re-read `analysis/requirements.md:69-72` and confirm whether top-attacker-IPs needs a separate endpoint or is fulfilled by the filtered overview.

### N5. Migration filename style differs

Existing migrations are named like `0008_add_geo_info_to_attack_logs.sql` (snake_case, descriptive verb). The plan's `0009_category_function.sql` is OK but `0009_add_category_function.sql` matches existing style better. Pure cosmetic.

### N6. `Vec<HeatmapCell>` ordering not stable

Phase 2 step 3 SQL ends `ORDER BY se.path, count DESC`. Two cells with same path + same count have nondeterministic order, which fails snapshot tests if the FE expects deterministic order. Add `, category ASC` as tiebreak.

---

## Backward-compat verification gaps

1. **No frontend code reference.** Plan says the frontend at `web/admin-panel/src/pages/dashboard/index.tsx` depends on the JSON shape — but the plan never grep-verifies which fields are actually consumed. A field could be removed silently if FE doesn't use it; safer to know.
2. **No live curl/screenshot baseline.** Before refactor, capture the current `/api/stats/overview` response into `plans/.../reports/overview-baseline.json` and diff against post-refactor. Plan describes this idea in phase 4 ("snapshot") but doesn't make the capture a phase 0 step.
3. **No version-bumping check.** Frontend has no compile-time contract with backend (loose JSON). The only protection is the snapshot test. Plan should explicitly note "frontend has zero typed contract — backend changes can only be caught by snapshot test."
4. **Backward-compat snapshot test asserts key presence only** (see I1). Strengthen to type-checks.
5. **Empty-string handling on `host_code=` / `action=`** (see F4). No test specified.

---

## Acknowledged Risks That Are Acceptable

1. **Per-test container spin-up cost (3-5s)** — already the project's standard; not blocking.
2. **240 cells max heatmap response (~50KB)** — bounded; reasonable.
3. **`hours.clamp(1, 720)` silently changes user-supplied values** — matches existing `stats_timeseries` behavior; consistent.
4. **Migration is additive (`CREATE OR REPLACE FUNCTION`)** — idempotent; safe to re-run. ✓
5. **Coverage floor existing 78%/82% remains enforced** — CI catches regressions in pre-existing code paths, just not specifically 90% on new lines (see F8).
6. **`StatsFilter::default()` = all-None → current behavior** — sound API design; correctly preserves backward compat IF the refactor is byte-equivalent (F1, F5 must be fixed first).

---

## Unresolved questions (still)

The planner flagged 4 questions. Assessment:

1. **"Should overview filters apply to attack_logs subqueries or only security_events?"** — NOT explicitly flagged by planner but should be. See F5 above. **Resolve before phase 2.**

2. **"What about empty-string query params?"** — Not flagged. See F4. **Resolve before phase 3.**

3. **"Should `category_of(NULL)` return `'other'` or `NULL`?"** — Plan inconsistent: redteam #6 says `'other'`, but plpgsql function has no STRICT, which means NULL input passes through and the inner CASE returns `'other'`. If we switch to `LANGUAGE SQL STRICT` (per I3), behavior flips to `NULL`. **Resolve as part of I3.**

4. **"Does FR-030 require a dedicated top-attackers endpoint or reuse `top_ips`?"** — See N4. **Re-confirm requirement before declaring scope complete.**

5. **"What is the actual CASE branch count and exact strings?"** — Plan says 28; actual is ~30 with hyphens not underscores and including `OWASP-94x/93x/91x` sub-prefixes. **Must be fixed in F1.**

6. **"How will CI enforce 90% on new code?"** — F8 above. **Either accept honor-system (and update success metric wording) or implement script.**

7. **"Will tests run on CI postgres SERVICE vs spawning testcontainers?"** — F7. **Must resolve before phase 4.**

---

## Recommended actions before phase 2 starts

1. Update phase 2 step 1 with the EXACT 30-branch CASE from `repo.rs:989-1020`, with hyphens, preserving order. (F1)
2. Change `category_of` to `LANGUAGE SQL IMMUTABLE PARALLEL SAFE` (decide STRICT or not). (I3, question 3)
3. Replace `($1 || ' hours')::INTERVAL` with `make_interval(hours => $1::int)` everywhere. (F2)
4. Specify `CASE WHEN category IN (top12) THEN category ELSE 'other' END` rollup for the heatmap. (F3)
5. Specify empty-string-to-None handling for query params. (F4)
6. Enumerate the 10 subqueries by table and which filters apply. (F5)
7. Replace the dual `clamp_hours_*` helpers with one + caller-side default. (I5)
8. Add explicit per-file 90% coverage gate (script or `--fail-under-files`). (F8)
9. Audit `.github/workflows/coverage.yml` vs phase 4 step 6 test plan. (F7)
10. Tighten the backward-compat snapshot test to check value types, not just key presence. (I1)
11. Confirm FR-030 scope re top attacker IPs. (N4)

---

**Status:** DONE_WITH_CONCERNS
**Verdict:** NO_GO
**Critical findings count:** 8 (F1-F8); 8 important (I1-I8); 6 nitpicks (N1-N6)
