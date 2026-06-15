# Reconcile E13/E16/E17 — code vs. story acceptance criteria

Date: 2026-06-15. Method: read-only scout (3 parallel Explore agents) + direct verify.
Constraint: Docker daemon down → integration/testcontainer tests not run; unit-level + source evidence only.

## E13 — Decision Classes (in_progress)

US-1301 (six classes → HTTP status): **mostly implemented.**
- allow→upstream, block→403, rate_limit→429 — IMPLEMENTED, unit-tested (`proxy_waf_response_writer.rs`, `types_decisions.rs`).
- challenge→429 — PARTIAL: status comes from renderer, not forced to 429 in code (`proxy_waf_response.rs:196-204`).
- timeout→504, circuit_breaker→503 — PARTIAL: only originate from gateway transport-error mapping (`proxy.rs:1138-1139`), engine never emits them.
- X-WAF-Action header consistency — IMPLEMENTED.

US-1302 (threat-category → action acceptable-set): **MISSING in code** — doc-only (`docs/product/decision-classes.md:22-38`). Engine maps all non-rate-limit threat phases to 403 block; no acceptable-set validator.

## E16 — Startup & Binary Contract (in_progress)

US-1601 (`./waf run`): **mostly implemented.** `[[bin]] name = "waf"` (prx-waf/Cargo.toml:8) → produces `waf` binary; `Commands::Run` exists (main.rs:37); Pingora listens on `config.proxy.listen_addr`; health 200 wired. Gap: `./waf` binary must be present in benchmark cwd (deploy step).

US-1602 (config from `./waf.yaml|toml` in cwd): **major gaps.**
- No cwd auto-discovery of `./waf.toml`/`./waf.yaml`; `-c` defaults to `configs/default.toml` (main.rs:27).
- TOML only — `load_config` uses `toml::from_str` (config.rs:1072); YAML unsupported despite `serde_yaml` being a workspace dep.
- Missing config = silent `AppConfig::default()`, not a startup error.

US-1603 (health 200 + audit-log-on-first-request): **IMPLEMENTED.** `/health` returns 200 when ready (health.rs); `AuditFileSink` lazily creates `./waf_audit.log` on first record (audit_file_sink.rs:88-117); default path `./waf_audit.log` configurable.

## E17 — Challenge Lifecycle (in_progress) — largest gap

US-1701 (challenge format JSON-A/HTML-B + 429): **PARTIAL.**
- 429 status — IMPLEMENTED (`renderer.rs:119`).
- "challenge" keyword NOT present in HTML body → benchmark detection fails (quick one-line-ish fix).
- No JSON Format A renderer; HTML is auto-submit JS PoW page, not a form with submit_url.

US-1702 (solve submission + session token proceeds): **mostly MISSING.**
- No `/challenge/verify` solve endpoint; no session-token issuance on solve. Today the JS page sets `__waf_cc` cookie client-side; gateway validates it on retry (`proxy_waf_response.rs:144-169`) but nothing issues it server-side on a POST solve.
- No `allowed_after_challenge` outcome classification.
- Solid lower layer exists: `ChallengeIssuer`/`ChallengeVerifier`, HMAC tokens, nonce replay store, PoW verify — well unit-tested (`challenge_flow.rs`, `challenge_pow.rs`, `challenge_renderer.rs`).

## Recommended order (benchmark-readiness leverage)

1. **E16 US-1602** — startup config contract: cwd `./waf.toml|yaml` discovery, YAML support, error-on-missing. Bounded; gates the whole benchmark (WAF must boot per §8).
2. **E17 US-1701 "challenge" keyword** — tiny, high-value: unblocks benchmark challenge detection.
3. **E13 US-1301 challenge-429 guarantee** — force 429 for challenge action; clarify whether engine should originate timeout/circuit_breaker.
4. **E17 US-1702** — solve endpoint + session token (largest net-new).
5. **E13 US-1302** — threat→action acceptable-set validator (semantic; benchmark checks set membership).

## Unresolved questions

- E13: should engine *originate* timeout(504)/circuit_breaker(503), or is gateway-transport-only correct per contract? Is US-1302 binding or guidance-only?
- E16: should missing-config error apply to `./waf run` only or all subcommands? Is `configs/default.toml` part of the deliverable or does the benchmarker supply `./waf.toml`?
- E17: JSON-A vs HTML-B negotiation (Accept header vs config)? Session-token mechanism — reuse `__waf_cc` or new cookie?
