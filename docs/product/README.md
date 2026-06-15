# Product Docs

This directory is intentionally generic and mostly empty in Harness v0.

When a user provides a project spec, derive smaller product contract files here
instead of keeping one large spec as the living plan. Name files by the product
domains that actually exist in that spec, for example `overview.md`,
`billing.md`, `workflows.md`, `permissions.md`, or `api-conventions.md`.

Do not create domain files before the spec just to fill the folder. Empty
structure is healthier than fake product truth.

## Interop Contract v2.3 (benchmark surface)

Derived from `analysis/docs/EN_waf_interop_contract_v2.3.md` — intake at
`docs/product/_interop-contract-v2.3-spec-intake.md`, decision
`docs/decisions/0008-interop-contract-v2.3-adoption.md`. Epics `E10`–`E17` under
`docs/stories/epics/`.

| Product doc | Contract | Epic |
| --- | --- | --- |
| `waf-control-plane.md` | §2 | E10 |
| `observability-headers.md` | §4, §5 | E11 |
| `audit-log.md` | §6, §10 | E12 |
| `decision-classes.md` | §3, §7 | E13 |
| `enforcement-modes.md` | §2.5, §2.7, §5.3 | E14 |
| `caching-observability.md` | §9 | E15 |
| `startup-contract.md` | §8 | E16 |
| `challenge-lifecycle.md` | §4 | E17 |

## Update Rule

When behavior changes:

1. Update the affected product doc.
2. Update or create the story packet.
3. Update durable proof status with `scripts/bin/harness-cli story add` or
   `scripts/bin/harness-cli story update`.
4. Record a decision if the change affects architecture, scope, risk, or a
   previously settled product rule.
