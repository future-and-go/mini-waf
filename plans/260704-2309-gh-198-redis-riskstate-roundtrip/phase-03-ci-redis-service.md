---
phase: 3
title: "CI Redis Service"
status: in-progress
effort: "S"
priority: P1
dependencies: [1, 2]
---

# Phase 3: CI Redis Service

## Overview

Close the CI gap: the `test` job in `.github/workflows/ci.yml` runs
`cargo test --workspace --all-features` with no Redis, so every
`REDIS_TEST_URL`-gated test early-returns as a silent pass. Add a Valkey
service container and export `REDIS_TEST_URL` so the Redis conformance suite
actually gates merges.

## Requirements

- Functional: Redis-gated tests execute (not skip) in the `test` job.
- Non-functional: no measurable CI slowdown beyond container pull (~seconds);
  Valkey to match the project's local verification habit (prior test runs used
  Valkey); pinned image tag.

## Architecture

`test` job is on `ubuntu-latest` (ci.yml:46) — GitHub-hosted, supports
`services:` containers natively. Tests read `REDIS_TEST_URL` and use a unique
key prefix per test (`unique_prefix()`, redis.rs), so a single shared instance
is safe for parallel tests.

## Related Code Files

- Modify: `.github/workflows/ci.yml` (test job only)

## Implementation Steps

1. Add to the `test` job:
   ```yaml
   services:
     valkey:
       image: valkey/valkey:8-alpine
       ports:
         - 6379:6379
       options: >-
         --health-cmd "valkey-cli ping"
         --health-interval 5s
         --health-timeout 3s
         --health-retries 5
   ```
2. Add `REDIS_TEST_URL: redis://127.0.0.1:6379` to the `Run tests` step `env`.
3. Other workflows are out of scope — verified during planning:
   `coverage.yml` runs `cargo llvm-cov -p <crate>` via
   `.github/scripts/coverage-check.sh:20` **without** `--all-features`, so the
   `redis-store`-gated tests are not compiled there; no service needed.
4. Push and confirm in the PR's CI run: the previously-skipped tests appear as
   executed and pass — verify by test count delta or by grepping the job log
   for `conformance_redis` (must not log the "skipping: REDIS_TEST_URL unset"
   marker).

## Success Criteria

- [ ] CI `test` job runs Redis-gated tests against the Valkey service (log
      evidence: no `REDIS_TEST_URL unset` skip messages in `risk::` tests)
- [ ] All three previously-failing tests pass in CI on top of phases 1-2
- [ ] Full workspace suite green

## Risk Assessment

- **Docker-dependent engine test:** `engine::tests::fast_path_exits_skip_risk_scoring`
  uses testcontainers (Postgres) and already runs on ubuntu-latest — the new
  service container does not interfere (different mechanism).
- **Port conflicts on shared runners:** service maps 6379 on localhost of the
  job's network namespace — isolated per job; safe.
- **Flakiness:** health-check gate prevents tests racing container startup.
  Existing `op_timeout`/breaker tests use their own unique prefixes; a shared
  instance is the established pattern (local runs used one Valkey on 16379).
- **Image drift:** pin `valkey/valkey:8-alpine`; bump deliberately, not via
  `latest`.
