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
| US-1803 | TX Velocity — config read/write API + hot-reload + editable form | C2 | normal | implemented | FR-012, FR-031 |
| US-1804 | Threat-Intel feeds API + runtime feed registry | D3 | normal | implemented | FR-042, FR-008 |
| US-1805 | Dashboard Detection Engines + Enforcement Plane Map from live state | D1, D2 | tiny | implemented | FR-030, FR-031, E10, E14 |

## Notes

The runtime response-filtering engine already exists
(`crates/gateway/src/filters/response_*`); these stories add only the admin
**API surface** and the DB→`HostConfig` wiring, never new redaction algorithms.
