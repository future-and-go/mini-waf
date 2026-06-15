# Spec Intake — WAF Interop Contract v2.3

Date: 2026-06-15

## Source

- User prompt: "read CLAUDE.md and the interop contract, create full epic, story".
- Attached file: `analysis/docs/EN_waf_interop_contract_v2.3.md`.
- External reference: WAF Hackathon 2026 benchmark/judging protocol.

## Project Summary

The interop contract is the **benchmark-facing control and observability contract**
the WAF must expose so event organizers can evaluate it deterministically. It is
distinct from the functional product (`analysis/requirements.md`, the detection
engine). It governs: a local control plane (`/__waf_control/*`), six mandatory
`X-WAF-*` response headers on every response, a JSONL audit log, six decision
classes, `enforce`/`log_only` mode semantics, caching observability, the startup
contract, and the source-IP trust model.

Much of this contract is already implemented (see `crates/waf-api/src/interop_control.rs`,
`crates/waf-engine/src/interop/mode_registry.rs`, `crates/waf-api/tests/interop_*`).
This intake formalizes the contract into harness epics, stories, and durable proof
so compliance is tracked behavior-by-behavior rather than as scattered plans.

## Candidate Product Docs

| File | Purpose | Source sections |
| --- | --- | --- |
| `docs/product/waf-control-plane.md` | Control endpoints, secret auth, capabilities/reset/set_profile/flush | §2 |
| `docs/product/observability-headers.md` | Six mandatory `X-WAF-*` headers + consistency rules | §4 (min), §5 |
| `docs/product/audit-log.md` | JSONL append-only log, required fields, IP semantics | §6, §10 |
| `docs/product/decision-classes.md` | Six decision classes, threat→action mapping, normalization | §3, §7 |
| `docs/product/enforcement-modes.md` | `enforce`/`log_only` per feature/policy; mode resolution | §2.5, §2.7, §5.3 |
| `docs/product/caching-observability.md` | `X-WAF-Cache` semantics, BYPASS defaults, flush | §9 |
| `docs/product/startup-contract.md` | Binary, `./waf run`, config, health, audit-log creation | §8 |
| `docs/product/challenge-lifecycle.md` | Challenge response formats and solve flow | §4 |

## Candidate Epics

| Epic | Description | Status |
| --- | --- | --- |
| E10 | WAF Control Plane (§2) | sliced |
| E11 | Observability Headers (§5) | sliced |
| E12 | Audit Log (§6, §10) | sliced |
| E13 | Decision Classes & Actions (§3) | sliced |
| E14 | Enforcement Modes / log_only (§2.5, §5.3, §7) | sliced |
| E15 | Caching Observability (§9) | sliced |
| E16 | Startup & Binary Contract (§8) | sliced |
| E17 | Challenge Lifecycle (§4) | sliced |

## Architecture Questions

- Runtime stack: Rust workspace on Pingora; control plane in `crates/waf-api`,
  detection + mode registry in `crates/waf-engine`, shared types in `crates/waf-common`.
- Product surfaces: HTTP proxy data plane + local admin/control plane.
- Storage: PostgreSQL for config; `./waf_audit.log` JSONL for the audit evidence.
- External providers: none required by this contract (benchmark is loopback-only).
- Deployment target: single `./waf` binary, `./waf run`.
- Security model: control endpoints gated by `X-Benchmark-Secret`, local/admin-only,
  never proxied upstream.

## Validation Shape

| Layer | Expected proof |
| --- | --- |
| Unit | Header builders, capability serialization, mode-registry resolution, audit-record shape. |
| Integration | `crates/waf-api/tests/interop_*` — control endpoints, secret auth, mode enforcement, audit correlation. |
| E2E | Loopback benchmark run: send traffic, assert headers + audit lines + control-plane effects match. |
| Platform | `./waf run` startup + health probe before timeout; audit-log file created on first request. |
| Release | Full workspace test + benchmark dry-run scoring. |

## Open Decisions

- Unsupported-item behavior in `set_profile` (400/422 vs. success-with-`unsupported`)
  MUST be one consistent choice for the whole run — recorded in
  `docs/decisions/0008-interop-contract-v2.3-adoption.md`.

## First Story Candidates

- US-1002 benchmark-secret auth (hard gate: auth).
- US-1005 `set_profile` mode control (cross-cutting, blocks E14).
- US-1401 mode resolution wired into engine hot path (the highest-risk gap area).

## Harness Delta

- New product-doc family under `docs/product/` for the interop contract.
- New epic tree `docs/stories/epics/E10..E17`.
- Decision `0008-interop-contract-v2.3-adoption`.
- Durable intake + stories registered via `scripts/bin/harness-cli`.
