# Admin-Panel Completion — Implementation Plans

One self-contained implementation plan per missing/broken/stub item from
section **G. Summary Overview** of
[`../admin-panel-gap-remediation-spec.md`](../admin-panel-gap-remediation-spec.md).

Every plan follows the same discipline and is grounded in a fresh codebase
audit (2026-06-25):

1. Audit the existing codebase first, then identify gaps.
2. List assumptions explicitly before proposing.
3. Define verifiable success criteria for each phase.
4. Make minimal, surgical changes — no broad refactor.
5. Cover edge cases, failure modes, security, observability.
6. Phased plan where each phase is independently testable and reversible.
7. Flag what is out of scope.
8. Identify what's missing for production-readiness.

All plans conform to [`../../../ARCHITECTURE.md`](../../../ARCHITECTURE.md)
(parse-first boundaries, command/query separation, observability contract) and
[`../../../CONTEXT_RULES.md`](../../../CONTEXT_RULES.md) (lane + phase reading
discipline). Lanes follow [`../../../FEATURE_INTAKE.md`](../../../FEATURE_INTAKE.md).

## Index

| Plan | G.1 rows | Title | Lane |
| --- | --- | --- | --- |
| [A1](A1-logs-audit-log-rewire.md) | 1–3 | Logs page — rebuild on a live audit/event source | normal |
| [A2](A2-response-filtering-api.md) | 4–6 | Response Filtering — preview + per-host API | high-risk |
| [B1](B1-ddos-protection-live-data.md) | 7–9 | DDoS Protection — live metrics, ban table, unban | normal |
| [B2](B2-challenge-engine-stats.md) | 10–11 | Challenge Engine — live stats, preview auth, PoW | normal→high-risk |
| [C1](C1-cc-protection-relabel-hotlink.md) | 12–13 | CC Protection — relabel + hotlink GET wire-up | tiny→normal |
| [C2](C2-tx-velocity-config-api.md) | 14 | TX Velocity — config read/write API + hot-reload | normal |
| [D1](D1-dashboard-detection-engines.md) | 15 | Dashboard — Detection Engines live state | tiny |
| [D2](D2-enforcement-plane-map.md) | 16 | Enforcement Plane Map — drive from capabilities | tiny |
| [D3](D3-threat-intel-feeds-api.md) | 17 | Settings — Threat Intel feeds API | normal |
| [D4](D4-geo-restriction-countries.md) | 18–19 | Geo Restriction — country list + label accuracy | tiny→normal |
| [D5](D5-client-side-accuracy-endpoints.md) | 20–22 | Server-side accuracy endpoints (rule test / agg / histogram) | normal |
| [G2](G2-backend-no-gui-wireups.md) | G.2 | Wire up backend endpoints that have no GUI | tiny→normal |

## Suggested execution order

Per spec §F (requirement weight × user impact):
A1 → B1 → B2 → A2 → C2 → C1 → D1–D4 → D5 → G2.

> **Note on doc paths.** These plans live at `docs/review/admin-panel/plans/`.
> Repo-relative source links use `../../../../crates/...` and
> `../../../../web/...`. The functional-requirements catalog is at
> `analysis/requirements.md` (repo root), not `docs/analysis/`.
