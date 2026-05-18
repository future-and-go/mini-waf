---
phase: 6
title: "FR-025 risk distribution API"
status: pending
priority: P1
effort: "2-5h"
dependencies: [0]
---

# Phase 6: FR-025 risk distribution API

## Overview

Sub-issue #4 cần Dashboard band-chart (green/yellow/orange/red) — phân phối requests theo risk score band. Endpoint chưa tồn tại. Phase 0 chốt option A (approximation, 2h) vs option B (schema migration + exact, 5h).

## Requirements

**Functional:**
- `GET /api/stats/risk-distribution?hours=24&host_code=...&action=...` (admin auth):
  ```json
  {
    "bands": [
      { "label": "allow",            "min": 0,  "max": 30, "count": 1230, "color": "green"  },
      { "label": "challenge",        "min": 30, "max": 70, "count": 47,   "color": "yellow" },
      { "label": "elevated",         "min": 70, "max": 85, "count": 12,   "color": "orange" },
      { "label": "block",            "min": 85, "max": 100,"count": 8,    "color": "red"    }
    ],
    "thresholds": { "risk_allow": 30, "risk_challenge": 70, "risk_block": 85 },
    "approximation": true,    // false nếu Phase 0 chốt option B
    "generated_at": "2026-05-18T12:34:56Z"
  }
  ```
- Filter params giống `/api/stats/overview` (host_code, action, hours).
- Thresholds đọc từ `panel_config` (đã có).

**Non-functional:**
- Endpoint < 100ms p99 trên 24h window (≤ 5M rows).
- Cache 30s (band counts không cần real-time).

## Architecture

### Option A — Approximation (locked by researcher report + red-team F6.2 fix)

Map từ `action_breakdown`:
- `action=allow` count → **green band** (1-to-1; allow ≡ score < risk_allow).
- `action=log_only` count → **green band** (operator chose not to act; treat as low-risk per FR-027 semantics).
- `action=challenge` count → **yellow band** (challenge ≡ score ∈ [risk_allow, risk_challenge); midpoint heuristic không justified — leave `elevated` empty unless we have evidence).
- `action=block` count → **red band** (block ≡ score ≥ risk_block).
- `action=redirect` count → **red band** (treat as effective block).

**`elevated` (orange) band luôn = 0 trong Option A.** Honest representation: WAF không expose mid-band signal at action layer. Response includes `approximation: true` flag + field `notes: "elevated band requires schema option B; current approximation buckets at action boundaries"` để FE hiển thị caveat.

```sql
SELECT action, COUNT(*)::bigint AS count
FROM security_events
WHERE created_at >= NOW() - make_interval(hours => $1::int)
  AND ($2::text IS NULL OR host_code = $2)
GROUP BY action
```

Aggregate Rust-side thành 4 band. KISS, no schema change.

### Option B — Schema migration + exact (NOT chosen for this plan; documented if escalated)

1. Migration `migrations/0010_security_events_risk_score.sql`:
   ```sql
   -- Postgres 11+ fast default — no rewrite
   ALTER TABLE security_events ADD COLUMN IF NOT EXISTS risk_score INTEGER NOT NULL DEFAULT 0;
   -- NO CREATE INDEX here — see note below
   ```
   **Red-team F6.1 fix**: `CREATE INDEX CONCURRENTLY` không chạy được trong transaction (`sqlx::migrate!` wraps in tx). Nếu sau này thực sự cần index, chạy manual op ngoài sqlx migration: `CREATE INDEX CONCURRENTLY ... WHERE risk_score > 0`. Không gom vào migration.
2. `engine.rs::log_security_event` ghi thêm `risk_score: decision.cumulative_score`.
3. Endpoint SQL:
   ```sql
   SELECT
     CASE
       WHEN risk_score < $allow    THEN 'allow'
       WHEN risk_score < $challenge THEN 'challenge'
       WHEN risk_score < $block    THEN 'elevated'
       ELSE                            'block'
     END AS band,
     COUNT(*)::bigint AS count
   FROM security_events
   WHERE created_at >= NOW() - make_interval(hours => $hours::int)
     AND ($host_code IS NULL OR host_code = $host_code)
   GROUP BY band
   ```
4. Existing rows: `risk_score = 0` → fall vào "allow" band → biased toward green ban đầu. Acceptable.

**Decision rule** (chốt ở Phase 0): nếu researcher #2 ước tính rubric impact của approximation accuracy < 5%, chọn **A**. Nếu judges verify exact distribution → **B**.

## Related Code Files

- Read: `crates/waf-storage/migrations/` (xem migration patterns)
- Read: `crates/waf-storage/src/repo.rs` (existing `get_stats_overview`)
- Read: `crates/waf-engine/src/risk/scorer.rs` (verify `risk_score` available trên `WafDecision`)
- Read: `crates/waf-common/src/panel_config.rs` (thresholds field)
- Read: `crates/waf-api/src/stats.rs` (handler pattern)
- Create: `crates/waf-api/src/stats_risk_distribution.rs` (~100 lines)
- Modify: `crates/waf-api/src/server.rs` — `route("/api/stats/risk-distribution", get(stats_risk_distribution))`
- Modify: `crates/waf-api/src/stats.rs` — `pub use` re-export
- Create: `crates/waf-api/tests/handler_stats_risk_distribution.rs` (~150 lines)

**Option B only:**
- Create: `crates/waf-storage/migrations/000010_security_events_risk_score.up.sql` (3 dòng)
- Create: `crates/waf-storage/migrations/000010_security_events_risk_score.down.sql`
- Modify: `crates/waf-storage/src/models.rs` — `CreateSecurityEvent { risk_score: Option<i32> }`
- Modify: `crates/waf-storage/src/repo.rs::create_security_event` — bind risk_score
- Modify: `crates/waf-engine/src/engine.rs::log_security_event` — pass `decision.risk_score`

## Implementation Steps

(Option A path — switch nếu Phase 0 chốt B)

1. **Repo method**: `Database::get_action_aggregates(filter) -> Vec<(String, i64)>` reuse pattern từ stats_overview.
2. **Handler** `stats_risk_distribution`:
   - Parse query params (reuse `OverviewQuery` struct nếu identical, hoặc tạo `RiskDistributionQuery`).
   - Fetch action aggregates + thresholds từ panel_config.
   - Map sang 4 bands theo heuristic A.
   - Return JSON.
3. **Tests**:
   - `risk_dist_empty_db_returns_zero_all_bands`
   - `risk_dist_with_seed_returns_expected_split`
   - `risk_dist_host_code_filter`
   - `risk_dist_action_filter`
   - `risk_dist_requires_auth`
   - `risk_dist_approximation_flag_true`
4. **Docs**: thêm endpoint vào `docs/codebase-summary.md` API section.

## Success Criteria

- [ ] Endpoint < 100ms p99 trên 1M-row window.
- [ ] 6 integration tests pass.
- [ ] Coverage ≥ 90% trên `stats_risk_distribution.rs`.
- [ ] Response shape match acceptance criteria sub-issue #4.
- [ ] `approximation` field rõ ràng để FE label "estimated" nếu cần.

## Risk Assessment

- **Approximation lệch khi judges verify**: doc `approximation: true` cho phép FE warn user. Nếu Phase 0 chọn B, gap đóng.
- **Migration on prod DB** (option B): backfill async chỉ là `DEFAULT 0` — không cần script backfill riêng (default fills new rows; existing rows stay 0 forever, biased green band).
- **Threshold change runtime**: panel_config cập nhật → response thay đổi ngay. OK, behavior expected.

## Notes

- Option A locked per researcher report. Migration deferred.
- **Cache** (red-team F6.4 fix): `tower_http::CacheLayer` KHÔNG tồn tại trong crate đó. Drop cache claim. Mỗi request hit DB; với existing `action_breakdown` query đã tested, không thêm overhead vì query có sẵn ở `stats/overview`. Nếu p99 > 100ms trong bench Phase 7, bump bằng moka in-memory cache (5s TTL) — không trong scope phase này (YAGNI).
- **Threshold drift**: response include `thresholds + generated_at`; FE invalidate khi config changes.
