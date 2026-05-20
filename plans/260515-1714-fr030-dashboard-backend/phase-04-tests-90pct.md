---
phase: 4
title: Tests-90pct
status: completed
effort: 3h
priority: P1
depends_on:
  - 3
---

# Phase 4: Tests — ≥90% Coverage on New Code

## Context Links

- Research: `research/researcher-existing-stats-backend.md` §Q4, §Q5, §Q11 (testcontainers pattern, fixture, coverage tool).
- Existing: `crates/waf-storage/tests/common/mod.rs:1-50` (`start_postgres()` fixture).
- Existing: `crates/waf-api/tests/common/mod.rs:56-122` (`start_test_server()` fixture).
- Existing: `crates/waf-storage/tests/repo_security_events.rs` (test style template).
- Existing: `crates/waf-api/tests/handler_stats_logs.rs` (handler test style template).

## Overview

Two test suites, **real Postgres via testcontainers**, no mocks:

1. **Storage tests** (`crates/waf-storage/tests/`) — verify `category_of()` migration function + `get_endpoint_heatmap()` + filtered `get_stats_overview()`.
2. **API tests** (`crates/waf-api/tests/`) — verify HTTP handlers (success, empty, clamp, auth, backward compat).

Coverage target: **≥90% line coverage on NEW code only**. Use `cargo llvm-cov` (researcher 1 §Q11).

## Key Insights

- Existing crate floors: `waf-api` 78%, `waf-storage` 82%. New code must exceed these — target 90%+.
- Per-file fixture spawns fresh Postgres container (researcher 1 §Q4) — tests parallel-safe within crate.
- Migration 0009 runs as part of fixture setup → `category_of()` available in tests automatically.
- Backward-compat assertion: capture a pre-refactor JSON snapshot of `/api/stats/overview` from a seeded DB, then assert post-refactor (with `StatsFilter::default()`) yields same keys + same values.

## Requirements

### Functional

- Every CASE branch in `category_of()` covered by a unit assertion.
- `get_endpoint_heatmap` covered: empty, single event, multi-event multi-path multi-category, filters (host/action/hours), top-20 truncation, NULL rule_id excluded.
- `get_stats_overview(&StatsFilter::default())` returns same row counts as pre-refactor for a seeded dataset.
- `/api/stats/endpoints` covered: happy path, empty, clamp, auth-required.
- `/api/stats/overview` covered: no-params backward compat + each filter.

### Non-Functional

- Coverage ≥90% measured by `cargo llvm-cov` on the new code paths.
- All tests pass in Docker — no host-Rust assumption.

## Architecture

Test layout (mirrors existing pattern):

```
crates/waf-storage/tests/
├── common/mod.rs                          (existing — extend with insert_event helper)
├── repo_endpoint_heatmap.rs               (NEW — 13 test cases)
├── repo_stats_overview_filters.rs         (NEW — 6 cases)
└── repo_category_function.rs              (NEW — 30-branch + ordering)

crates/waf-api/tests/
├── common/mod.rs                          (existing — extend: seed_one_of_each, fetch helpers)
├── handler_stats_endpoints.rs             (NEW — 7 cases)
├── handler_stats_overview_filters.rs      (NEW — 6 cases incl. F4 empty-string)
└── stats_overview_backward_compat.rs      (NEW — I4 dedicated regression guard)
```

## Related Code Files

**Create:**
- `crates/waf-storage/tests/repo_endpoint_heatmap.rs`
- `crates/waf-storage/tests/repo_stats_overview_filters.rs`
- `crates/waf-storage/tests/repo_category_function.rs`
- `crates/waf-api/tests/handler_stats_endpoints.rs`
- `crates/waf-api/tests/handler_stats_overview_filters.rs`
- `crates/waf-api/tests/stats_overview_backward_compat.rs` (I4 dedicated guard)

**Modify:**
- `crates/waf-api/tests/common/mod.rs` — add `seed_one_of_each(&db)`, `fetch(&s, path)` helpers (additive).
- `crates/waf-storage/tests/common/mod.rs` — add `insert_event(...)` helper (additive).
- `crates/waf-api/tests/handler_stats_logs.rs` — only if call sites broke after `stats_overview` accepts `Query<OverviewQuery>` (Axum extracts default empty struct for missing query string; existing tests likely unaffected — verify by running them after phase 3).
- `.github/workflows/coverage.yml` — see phase 5; raise crate floors after green tests.

## Implementation Steps

### Step 1 — `repo_category_function.rs` (30 real branches + NULL + fallback + ORDERING)

**Cases must match `migrations/0009_category_function.sql` verbatim.** Each WHEN clause needs at least one positive case; longer-prefix clauses need a case proving they fire BEFORE their shorter relative (e.g. `CRS-RESP-X` → `data-leakage` NOT `owasp-crs`).

```rust
#[tokio::test(flavor = "multi_thread")]
async fn category_of_covers_all_prefixes() {
    let fx = start_postgres().await;
    // 30 prefixes from repo.rs:990-1019 + fallback cases.
    // Order asserts longer prefixes win over shorter (CRS-RESP > CRS-, etc.).
    let cases: &[(Option<&str>, &str)] = &[
        (Some("SQLI-001"),         "sqli"),
        (Some("XSS-42"),           "xss"),
        (Some("RCE-X"),            "rce"),
        (Some("TRAV-1"),           "path-traversal"),
        (Some("SCAN-1"),           "scanner"),
        (Some("BOT-1"),            "bot"),
        (Some("CC-DDOS-1"),        "cc-ddos"),
        // ADV ordering: longer SSRF/SSTI MUST fire before generic ADV-*
        (Some("ADV-SSRF-001"),     "ssrf"),
        (Some("ADV-SSTI-001"),     "ssti"),
        (Some("ADV-OTHER-1"),      "advanced"),
        // CRS ordering: CRS-RESP MUST fire before CRS-
        (Some("CRS-RESP-1"),       "data-leakage"),
        (Some("CRS-942100"),       "owasp-crs"),
        // API ordering
        (Some("API-MASS-1"),       "mass-assignment"),
        (Some("API-OTHER-1"),      "api-security"),
        // MODSEC ordering
        (Some("MODSEC-RESP-1"),    "web-shell"),
        (Some("MODSEC-OTHER-1"),   "modsecurity"),
        (Some("CVE-2024-1234"),    "cve"),
        (Some("GEO-VN"),           "geo-blocking"),
        (Some("CUSTOM-1"),         "custom"),
        (Some("IP-1"),             "ip-rule"),
        (Some("URL-1"),            "url-rule"),
        (Some("SENS-1"),           "sensitive-data"),
        (Some("HOTLINK-1"),        "anti-hotlink"),
        (Some("OWASP-942100"),     "sqli"),
        (Some("OWASP-941100"),     "xss"),
        (Some("OWASP-930100"),     "lfi"),
        (Some("OWASP-931100"),     "rfi"),
        (Some("OWASP-932100"),     "rce"),
        (Some("OWASP-933100"),     "php-injection"),
        (Some("OWASP-913100"),     "scanner"),
        // Fallback
        (Some("OWASP-999999"),     "other"),
        (Some("UNKNOWN-X"),        "other"),
        (Some(""),                 "other"),
        (None,                     "other"),
    ];
    for (rule_id, want) in cases {
        let row: (String,) = sqlx::query_as("SELECT category_of($1)")
            .bind(*rule_id)
            .fetch_one(fx.db.pool()).await
            .expect("query"); // #[cfg(test)] context
        assert_eq!(&row.0, want, "rule_id={:?}", rule_id);
    }
}
```

**Note:** `fx.db.pool()` — confirm `Database` exposes a public `pool()` accessor; if not, add a `#[cfg(test)] pub fn pool(&self) -> &PgPool` accessor in `waf-storage/src/db.rs` (test-only).

### Step 2 — `repo_endpoint_heatmap.rs`

Test cases (each `#[tokio::test(flavor = "multi_thread")]` with fresh fixture):

| # | Test | Setup | Assert |
|---|------|-------|--------|
| 1 | `heatmap_empty_db` | no events | `cells.is_empty()`, `total_events == 0` |
| 2 | `heatmap_single_event` | 1 event path=/a rule_id=SQLI-1 | `cells.len() == 1`, cell `{path:"/a",category:"sqli",count:1}` |
| 3 | `heatmap_multi_path_multi_cat` | 5 paths × 3 cats × varying counts | sparse cells == non-zero pairs |
| 4 | `heatmap_filters_by_host_code` | events on h1+h2, filter h1 | only h1 cells returned |
| 5 | `heatmap_filters_by_action` | events action=block+log, filter block | only block cells |
| 6 | `heatmap_filters_by_hours_window` | event 1h ago + 100h ago, filter hours=24 | only 1h-ago cell |
| 7 | `heatmap_top20_truncation` | 30 distinct paths × 1 event each | exactly 20 distinct paths in result; `paths_sampled == 20` |
| 8 | `heatmap_excludes_null_rule_id` | 1 event rule_id=NULL + 1 with SQLI-1 | only SQLI cell present |
| 9 | `heatmap_metadata_counts` | 4 paths × 2 cats × 5 events each | `paths_sampled == 4`, `categories_total == 2`, `total_events == 40` |
| 10 | `heatmap_other_rollup_when_more_than_12_categories` (F3) | 13 distinct categories on 1 path | exactly one category labeled `"other"`; `sum(count) == total_events` (no data lost) |
| 11 | `heatmap_total_events_equals_sum_of_cells` (F3 invariant) | any non-trivial dataset | `total_events == cells.iter().map(|c| c.count).sum()` |
| 12 | `heatmap_truncates_path_to_256_chars` (I7) | 1 event with `path = "/x".repeat(200)` (400 chars) | returned cell `path.len() <= 256` |
| 13 | `heatmap_window_uses_make_interval` (smoke) | event exactly `make_interval(hours => 24)` ago boundary | inclusive boundary deterministic; no panic |

Helper `insert_event(&fx, host, path, rule_id, action, hours_ago)` — write once, reuse across files via `tests/common/mod.rs` extension (additive to existing fixture).

### Step 3 — `repo_stats_overview_filters.rs`

| # | Test | Assert |
|---|------|--------|
| 1 | `overview_default_filter_matches_prefactor_shape` | seed 10 events; result has all existing fields (`total_requests`, `top_ips`, `category_breakdown`, etc.) populated |
| 2 | `overview_host_code_filter` | seed h1+h2; filter h1; counts reflect h1 only |
| 3 | `overview_action_filter` | seed block+log; filter block; counts reflect block only |
| 4 | `overview_hours_filter` | seed event 1h-ago + 200h-ago; filter hours=24; only recent counted |
| 5 | `overview_all_filters_combined` | seed mixed; filter (h1, block, 24h); intersection correct |
| 6 | `overview_empty_db_returns_zero_counts` | no events; all counts zero, vectors empty |

### Step 4 — `handler_stats_endpoints.rs`

| # | Test | Assert |
|---|------|--------|
| 1 | `endpoints_happy_path` | seed events, GET /api/stats/endpoints, 200, JSON has `data.cells`, `data.metadata` |
| 2 | `endpoints_empty_db` | no events, 200, `cells == []`, `total_events == 0` |
| 3 | `endpoints_clamps_hours_low` | `?hours=0` → 200, treated as 1 |
| 4 | `endpoints_clamps_hours_high` | `?hours=99999` → 200, treated as 720 |
| 5 | `endpoints_requires_auth` | no Bearer token → 401 |
| 6 | `endpoints_filter_by_host_code` | seed h1+h2, `?host_code=h1` → only h1 cells |
| 7 | `endpoints_filter_by_action` | `?action=block` → only block cells |

### Step 5 — `handler_stats_overview_filters.rs` + dedicated backward-compat file

**Split into TWO files** (I4 fix):

**5a. `crates/waf-api/tests/handler_stats_overview_filters.rs`** — filter behavior:

| # | Test | Assert |
|---|------|--------|
| 1 | `overview_host_code_filter` | `?host_code=h1` returns 200, counts match h1 subset |
| 2 | `overview_action_filter` | `?action=block` returns 200, counts match |
| 3 | `overview_hours_filter` | `?hours=24` returns 200, counts match recent window |
| 4 | `overview_invalid_hours_clamped` | `?hours=99999` returns 200 (not 400) |
| 5 | `overview_requires_auth` | no Bearer → 401 |
| 6 | `overview_empty_string_filter_treated_as_none` (F4) | `?host_code=&action=` returns same body as no params (both empty strings → None) |

**5b. `crates/waf-api/tests/stats_overview_backward_compat.rs`** — dedicated regression guard (I4):

```rust
//! Backward-compat guard for GET /api/stats/overview.
//!
//! Asserts the response envelope (with no query params) keeps every key
//! the existing dashboard frontend at
//! `web/admin-panel/src/pages/dashboard/index.tsx:70` reads. Adding
//! fields is allowed; removing or renaming is NOT.

#[path = "common/mod.rs"]
mod common;
use common::start_test_server;

#[tokio::test(flavor = "multi_thread")]
async fn overview_no_params_returns_all_legacy_keys() {
    let s = start_test_server().await;
    // Seed: 1 attack_log (action=block) + 1 security_event (action=block) so
    // every branch of the envelope produces a non-trivial value.
    seed_one_of_each(&s.db).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{}/api/stats/overview", s.addr))
        .bearer_auth(&s.admin_token)
        .send().await.expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");

    // Top-level envelope
    assert_eq!(body["success"], serde_json::json!(true));
    let data = &body["data"];

    // Every key the current handler emits (mirror of stats.rs json! block).
    for key in &[
        "total_requests", "total_blocked", "total_allowed", "block_rate",
        "total_requests_live", "total_blocked_live",
        "total_requests_db", "total_blocked_db",
        "hosts_count", "unique_attackers",
        "top_ips", "top_rules", "top_countries", "top_isps",
        "category_breakdown", "action_breakdown", "recent_events",
    ] {
        assert!(
            data.get(*key).is_some(),
            "missing legacy key `{}` in /api/stats/overview response; \
             this breaks the dashboard frontend",
            key,
        );
    }

    // Type checks for the most-consumed fields.
    assert!(data["total_requests"].is_number());
    assert!(data["top_ips"].is_array());
    assert!(data["category_breakdown"].is_array());
    assert!(data["recent_events"].is_array());
}

#[tokio::test(flavor = "multi_thread")]
async fn overview_filtered_and_unfiltered_have_same_envelope_shape() {
    let s = start_test_server().await;
    seed_one_of_each(&s.db).await;

    let unfiltered: serde_json::Value = fetch(&s, "/api/stats/overview").await;
    let filtered: serde_json::Value =
        fetch(&s, "/api/stats/overview?host_code=h1&action=block&hours=24").await;

    // Same set of keys in `data` regardless of filters.
    let keys_a: std::collections::BTreeSet<_> =
        unfiltered["data"].as_object().unwrap().keys().collect();
    let keys_b: std::collections::BTreeSet<_> =
        filtered["data"].as_object().unwrap().keys().collect();
    assert_eq!(keys_a, keys_b, "filter changed response shape");
}
```

Helpers `seed_one_of_each(&db)` and `fetch(&s, path)` are added to `crates/waf-api/tests/common/mod.rs` (additive).

### Step 6 — Run tests in Docker

```bash
docker run --rm \
  -v $PWD:/work -w /work \
  -v /var/run/docker.sock:/var/run/docker.sock \
  rust:1.91-slim-bookworm \
  sh -c "apt-get update && apt-get install -y curl ca-certificates && \
         cargo test -p waf-storage --tests && \
         cargo test -p waf-api --tests"
```

All tests pass. Zero `ignored`.

### Step 7 — Coverage (F8 — concrete CI gate)

**The user's "90% on new code" mandate is enforced via crate-floor ratchet** (MVP, picked over a fragile per-line jq diff). Phase 5 raises the floors in `.github/workflows/coverage.yml` once the new tests are in place:

| Crate | Current floor | New floor | Rationale |
|-------|--------------|-----------|-----------|
| `waf-storage` | 82 | **84** | New repo lines pull crate average up; if average drops, gate fires |
| `waf-api` | 78 | **80** | Same logic for new handler + helpers |

**Why crate-floor ratchet (not new-line jq diff):**
- CI uses `cargo llvm-cov --summary-only` already; ratchet is a one-line YAML edit.
- A jq diff against `git diff origin/main...HEAD` would catch <90% on new lines specifically, but adds new infra and is fragile across rebases.
- The floor ratchet enforces the SPIRIT of "new code clean" — if new lines were <90% covered, average wouldn't rise.

**Local coverage measurement (manual verification before push):**

```bash
docker run --rm \
  -v $PWD:/work -w /work \
  -v /var/run/docker.sock:/var/run/docker.sock \
  rust:1.91-slim-bookworm \
  sh -c "apt-get update && apt-get install -y curl ca-certificates && \
         cargo install cargo-llvm-cov --locked && \
         cargo llvm-cov -p waf-storage --summary-only && \
         cargo llvm-cov -p waf-api --summary-only"
```

Read the `TOTAL` line. Must show ≥84% for waf-storage, ≥80% for waf-api.

**Stretch goal (not required for this PR):** add a CI step that emits per-file deltas:
```bash
cargo llvm-cov --json --output-path coverage.json
# Then jq filter on the changed files from `git diff --name-only origin/main...HEAD`
# matched against coverage.json files[*] entries, asserting line cov ≥90%.
```
Defer to a follow-up PR.

**Manual HTML inspection** (open `coverage/html/index.html` after `--html`):
- `crates/waf-storage/src/repo.rs` — new lines (`get_endpoint_heatmap`, refactored `get_stats_overview` filter branches) ≥90%.
- `crates/waf-api/src/stats.rs` — `stats_endpoints`, query structs, `clamp_hours_*`, `empty_string_as_none` ≥90%.
- `migrations/0009_category_function.sql` — implicit (covered by `category_of` test set).

If new code <90%, add error-branch tests (`try_get` on bad row, malformed filter combos) before raising the floor.

## Todo List

- [ ] Create `repo_category_function.rs` covering all 30 branches + ordering cases (CRS-RESP, ADV-SSRF, OWASP-942, etc.) + NULL + fallback.
- [ ] Create `repo_endpoint_heatmap.rs` with 13 test cases (incl. `'other'` rollup, sum invariant, path truncation, NULL exclusion).
- [ ] Create `repo_stats_overview_filters.rs` with 6 test cases.
- [ ] Create `handler_stats_endpoints.rs` with 7 test cases.
- [ ] Create `handler_stats_overview_filters.rs` with 6 test cases (incl. F4 empty-string).
- [ ] Create `stats_overview_backward_compat.rs` — dedicated I4 regression file.
- [ ] Extend `crates/waf-api/tests/common/mod.rs` with `seed_one_of_each` + `fetch` helpers.
- [ ] If needed, add `#[cfg(test)] pub fn pool(&self) -> &PgPool` to `waf-storage/src/db.rs`.
- [ ] Update any existing test that called `get_stats_overview()` with new `&StatsFilter` arg.
- [ ] Run full test suite in Docker → 0 failures.
- [ ] Generate coverage report; confirm new code ≥90%.

## Success Criteria

- [ ] All test files compile and execute via Docker.
- [ ] `cargo test -p waf-storage --tests` returns 0 failures.
- [ ] `cargo test -p waf-api --tests` returns 0 failures.
- [ ] `cargo llvm-cov -p waf-storage --summary-only` TOTAL line cov ≥ **84%** (new floor).
- [ ] `cargo llvm-cov -p waf-api --summary-only` TOTAL line cov ≥ **80%** (new floor).
- [ ] `stats_overview_backward_compat.rs` passes; both legacy-keys-present + filter-vs-unfiltered-shape tests green.
- [ ] No `.unwrap()` outside `#[cfg(test)]`.

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Docker socket unavailable on CI | Low | High | GitHub Ubuntu runners mount `/var/run/docker.sock` by default; verified by existing testcontainer tests already passing |
| `start_postgres()` cold-start adds CI time | High | Low | Existing pattern (3-5s/file); per-file parallel within crate |
| Snapshot brittleness on overview JSON | Med | Med | Structural-key + type assertions, not byte-equality |
| Coverage floor ratchet too aggressive | Low | Med | Pick **84/80** (not 85/82); leaves headroom; revisit after merge |
| Cross-prefix ordering bug in `category_of` | Low | Critical | Explicit ordering tests (CRS-RESP, ADV-SSRF, OWASP-942) in step 1 |
| `'other'` rollup off by one | Med | Med | Invariant test `total_events == cells.sum()` (test #11) |
| Coverage <90% on new code | Med | High | Manual HTML inspection; add error-branch tests for `try_get` paths if low |

## Security Considerations

- Tests verify auth-required behavior on new endpoint (`endpoints_requires_auth`).
- SQL injection mitigation re-tested implicitly via filter cases (different `host_code` values pass through bind).

## Rollback Plan

Tests are additive in `crates/*/tests/`. If a test fails on CI for environmental reasons (not code bug), gate via `#[ignore]` with a comment + filed issue. Do NOT delete; do NOT relax coverage.

## Next Steps

Phase 5: fmt + clippy + branch + squash + PR + CI.
