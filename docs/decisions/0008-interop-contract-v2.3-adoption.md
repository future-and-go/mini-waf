# 0008 Interop Contract v2.3 Adoption

Date: 2026-06-15

## Status

Accepted

## Context

The WAF Hackathon 2026 benchmark grades the WAF through a deterministic,
machine-readable interface defined in `analysis/docs/EN_waf_interop_contract_v2.3.md`:
a local control plane, six mandatory `X-WAF-*` response headers, a JSONL audit log,
six decision classes, `enforce`/`log_only` mode semantics, caching observability,
a startup contract, and a source-IP trust model. Missing required headers or an
inconsistent control plane are scored as contract failures regardless of detection
quality. The contract was previously tracked as scattered plans
(`plans/260527-1157-waf-interop-v23-critical-compliance` and siblings) with no
durable story/proof linkage. This decision adopts the contract as a first-class
product contract decomposed into the harness epic/story tree.

## Decision

1. Adopt interop contract v2.3 as a product contract under `docs/product/*`
   (one doc per contract surface) and decompose it into epics `E10`–`E17` with
   per-behavior stories.
2. Control endpoints (`/__waf_control/*`) are local/admin-only, MUST NOT be
   proxied upstream, and MUST require the `X-Benchmark-Secret` header
   (`403` on missing/invalid). This is an auth hard gate.
3. The six `X-WAF-*` headers in §5.1 are REQUIRED on **every** response,
   including `allow`. HTTP status/body is a compatibility fallback only.
4. Audit log `ip` MUST be the TCP `peer_addr`, never a value parsed from
   `X-Forwarded-For`/`X-Real-IP`. The audit log is append-only and MUST survive
   `reset_state`.
5. `enforce`/`log_only` is resolved **per feature/policy** through the engine
   hot path; in `log_only` the WAF reports the intended `X-WAF-Action` but MUST
   NOT apply enforcement, and the request continues upstream.
6. **`set_profile` unsupported-item behavior:** return success for supported
   items and list unsupported items in the `unsupported` array (the
   success-with-`unsupported` form, not `400`/`422`). This choice MUST be
   consistent for the entire benchmark run.

## Alternatives Considered

1. Keep the contract as plans only — rejected: no durable behavior→proof linkage,
   compliance not queryable via `query matrix`.
2. `set_profile` returns `400`/`422` for any unsupported item — rejected in favor
   of partial success because it lets the benchmarker toggle valid items without
   a whole-request failure; either form is contract-legal but only one may be used.

## Consequences

Positive:

- Contract compliance is tracked behavior-by-behavior with durable proof status.
- Auth, audit, and mode-resolution risks are explicit high-risk stories.

Tradeoffs:

- Header/audit/mode requirements are cross-cutting; changes ripple across
  `waf-api`, `waf-engine`, and `waf-common`.
- The partial-success `set_profile` contract must be enforced consistently and
  guarded against drift.

## Follow-Up

- Verify the §2.5 mode-resolution hot-path wiring flagged in `gaps.md` is fully
  closed (E14 / US-1401) before claiming `log_only` compliance.
- Run a loopback benchmark dry-run as E2E proof for E11/E12.
