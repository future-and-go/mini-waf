# Interop v2.3 E2E Proof — Closure (epics E10–E17)

**Date:** 2026-06-16
**Severity:** Low (close-out; no product defect)
**Component:** E2E harness (`tests/e2e/`), interop benchmark contract
**Status:** Closed

## What Happened

Every interop story (US-1001…US-1702) was unit- and integration-proven but
carried `e2e: no` in the test matrix — the single largest proof gap. There was
no live, end-to-end suite that drove the surface a benchmark harness actually
touches: the `/__waf_control/*` control plane, the six `X-WAF-*` headers, the
JSONL audit sink, decision classes, enforcement modes, cache classification,
startup, and the challenge endpoint.

Added `tests/e2e/run-interop.sh` (41 assertions) and wired it into the nightly
workflow alongside the existing suites. Ran the full stack locally
(postgres + go-httpbin + prx-waf) and brought the suite to **41/41 pass**.

Lane: normal (test-only; no product code changed).

## Coverage Added (e2e flag flipped to yes)

- **E10 control plane** — US-1001 (local-only, not via proxy port), US-1002
  (secret auth 403/200), US-1003 (capabilities shape), US-1004 (reset_state),
  US-1005 (set_profile + bad-mode 400), US-1006 (flush_cache).
- **E11 headers** — US-1101…US-1106 (all six `X-WAF-*` present incl. on allow;
  request-id correlated with audit).
- **E12 audit** — US-1201 (log created on first request), US-1202 (eight
  required fields in flushed line), US-1204 (request_id correlation).
- **E13 decisions** — US-1301 (allow→200/action=allow, block→403/action=block live).
- **E14 modes** — US-1401/1402/1403 (log_only forwards the same SQLi that
  enforce blocks; `X-WAF-Mode` reflects; enforce restored).
- **E15 cache** — US-1501 (valid enum), US-1502 (dynamic route → BYPASS).
- **E16 startup** — US-1601 (binary starts, both listeners answer), US-1603
  (health 200 + audit on first request).

## Deliberately Left `e2e: no` (honest scope)

These contracts are not reproducible against the httpbin upstream / live CRS
config, and remain covered by unit + integration tests:

- **US-1203** (ip = peer not XFF) — suite asserts the `ip` field exists, not the
  peer-vs-XFF distinction.
- **US-1302** (threat-category acceptable-set) — not surfaced over the wire.
- **US-1503** (flush clears stale entries) — no cacheable route in this upstream
  to populate then prove eviction.
- **US-1602** (config discovered from cwd) — container passes config by path.
- **US-1701 / US-1702** (challenge format / positive solve→proceed) — issuance is
  risk-score-driven and the verify endpoint is shadowed by CRS-920420 in this
  config; only the negative guard (unsolved → denied, does not proceed upstream)
  is proven live.

## Test-Assumption Corrections

The first run was 29/40. All three failures were wrong assertions, not product
bugs — diagnosed by direct inspection of the running container:

1. **Cache** — assumed MISS→HIT on `/cache/120`. The httpbin routes classify as
   `CatchAll` tier with no cacheable policy, so every route correctly returns
   `BYPASS` (which *is* US-1502). Reframed to assert valid enum + BYPASS on the
   dynamic route; positive HIT/MISS stays in `cache_integration`.
2. **Audit** — eight field assertions failed because the suite finished before
   the async audit flush. Added a poll loop on the probe's request_id.
3. **Challenge** — the unsolved POST was denied by CRS-920420, not the challenge
   verifier (false attribution). Reframed to the observable contract: the
   submission is denied (403) and `X-WAF-Action` proves the WAF handled it.

## Harness Gap Found

The repo had no `.dockerignore`, so `docker build` shipped multi-GB `target/`
trees as build context (exhausted the builder's disk once). Added one scoped to
keep only `target/release/waf` for `Dockerfile.prebuilt`.

## Artifacts

- `tests/e2e/run-interop.sh` — the suite.
- `tests/e2e/configs/e2e.toml` — added `[interop]` + `[audit]` blocks.
- `.github/workflows/nightly-e2e.yml` — `interop` job + report aggregation.
- `.dockerignore` — build-context fix.
