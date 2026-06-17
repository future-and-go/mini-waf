# Interop v2.3 E2E Proof (E10–E17)

## Goal
Close the e2e proof gap: every interop story (US-1001–US-1702) is `implemented`
with unit+integration proof but `e2e: no` in the harness matrix. Add one e2e
suite that exercises the interop surface end-to-end on the live docker stack,
wire it into the nightly workflow, then flip `e2e: yes` once the suite runs green.

## Scope
Test-only. No production behavior change. Normal lane (proving already-shipped
behavior; no weakening of validation).

## Surface map (verified)
- Binary `waf` (crates/prx-waf), run via docker-compose.e2e.yml stack.
- Control plane `/__waf_control/*` on the **admin API** port (16827).
  Auth header `x-benchmark-secret`, secret `waf-hackathon-2026-ctrl`.
- X-WAF-* response headers + decision classes + cache via **proxy** port (16880).
- Audit JSONL written to `[audit] log_path` (set to `/tmp/waf_audit.log`).
- Challenge solve at `POST /challenge/verify` on proxy.

## Steps
1. **e2e.toml** — add explicit `[interop]` (secret) + `[audit]` (deterministic
   `/tmp/waf_audit.log`). Additive; harmless to existing suites.
2. **tests/e2e/run-interop.sh** — new runner mirroring run-api/run-gateway:
   - E10: control-plane auth (no/wrong secret → 403; correct → 200),
     capabilities shape, set_profile/reset_state/flush_cache 200, local-only
     (control path on proxy port is NOT the control plane).
   - E11: all six X-WAF-* headers present on a proxied response.
   - E13: allow GET → 200 action=allow; SQLi POST → 403 action=block.
   - E14: set_profile all→log_only makes SQLi forward (not enforced),
     X-WAF-Mode=log_only; reset_state restores enforce.
   - E15: X-WAF-Cache MISS→HIT on cacheable path.
   - E12: read audit JSONL (docker exec), assert 8 required fields +
     request_id correlation with response header.
   - E17: POST /challenge/verify bad body → 403 (negative path).
3. **nightly-e2e.yml** — add `interop` job + add to `report` needs/staging loop
   + dispatch input doc.
4. **Validate** — `bash -n` syntax; full green requires a compose run (CI nightly
   or local `docker compose -f tests/e2e/docker-compose.e2e.yml up`).
5. **Flip proof** — after a green run, `harness-cli story update <id> --e2e 1`
   for US-1001–1702; journal the closure.

## Success criteria
- run-interop.sh passes against the live stack (all assertions green).
- Nightly workflow runs the suite + aggregates its report.
- Matrix shows `e2e: yes` for the interop stories (post green run).

## Open questions
- Full challenge *issuance* is risk-score-driven, not deterministically
  triggerable in e2e → only the verify negative path is covered here. Flag if
  the harness requires positive issuance proof too.
