# E18 — Admin Panel API Completeness

Source: `docs/review/admin-panel/admin-panel-gap-remediation-spec.md` and the
per-feature plans under `docs/review/admin-panel/plans/`. This epic groups the
backend API surfaces the admin panel already calls but that 404 / stub / are
missing, so each broken GUI feature becomes a working end-to-end contract.

Lane: per-story (A2 is high-risk: response hot path + `defense_json` data-model
change + existing behavior).

## Stories

| ID | Title | Plan | Lane | Status | Req IDs |
| --- | --- | --- | --- | --- | --- |
| US-1801 | Response Filtering — preview endpoint + per-host API | A2 | high-risk | implemented | FR-033, FR-034, FR-035 |
| US-1802 | DDoS Protection — live metrics, ban table, working unban | B1 | normal | implemented | FR-005, FR-004 |

## Notes

The runtime response-filtering engine already exists
(`crates/gateway/src/filters/response_*`); these stories add only the admin
**API surface** and the DB→`HostConfig` wiring, never new redaction algorithms.
