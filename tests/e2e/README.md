# Nightly E2E Suite

Drives the `.github/workflows/nightly-e2e.yml` workflow. Each suite emits
JUnit XML, JSON, and Markdown artefacts that the workflow renders as a
GitHub run summary, a Checks-tab report, and a downloadable HTML page.

## Layout

```
tests/e2e/
├── lib.sh                       # shared helpers (assert_*, JUnit/JSON writers)
├── configs/e2e.toml             # PRX-WAF config used by the suites (httpbin upstream)
├── docker-compose.e2e.yml       # postgres + go-httpbin + prx-waf stack
├── run-rules-engine.sh          # verifies every rule category in rules/
├── run-gateway.sh               # crates/gateway proxy behaviour
├── run-api.sh                   # crates/waf-api admin endpoints
├── run-interop.sh               # interop v2.3 benchmark contract (E10–E17)
├── run-cluster.sh               # wraps tests/e2e-cluster.sh (crates/waf-cluster)
├── run-risk-config.sh           # risk-scoring admin-UI settings (persistence + behavioral)
├── docker-compose.risk-override.yml  # risk-enabled override (writable /configs, tier thresholds)
├── configs/risk.yaml            # pristine risk fixture (seeded into a writable runtime copy)
├── configs/risk-e2e.toml        # main config + [tiered_protection] ref
├── configs/tier-risk-e2e.toml   # low RiskThresholds so enforcement is observable
├── render-report.sh             # aggregates per-suite JSON → Markdown + HTML
└── out/                         # per-suite results.json / junit.xml / summary.md
```

## Running locally

```bash
# 1. Build the binary (Dockerfile.prebuilt copies it into the image)
cargo build --release -p prx-waf
mkdir -p data web/admin-panel/dist  # placeholders for Dockerfile.prebuilt

# 2. Start the stack
docker compose -f tests/e2e/docker-compose.e2e.yml up -d --build

# 3. Run any suite
bash tests/e2e/run-rules-engine.sh
bash tests/e2e/run-gateway.sh
bash tests/e2e/run-api.sh
bash tests/e2e/run-interop.sh

# 4. Cluster suite — uses docker-compose.cluster.yml (separate stack)
bash tests/e2e/run-cluster.sh

# 5. Aggregate
bash tests/e2e/render-report.sh tests/e2e/out tests/e2e/out/aggregated
open tests/e2e/out/aggregated/report.html
```

## Risk config suite

`run-risk-config.sh` verifies every Risk Scoring Engine setting the admin UI
exposes, driven through the exact API the UI calls (`PUT`/`GET /api/risk/config`)
plus gateway data-plane observation. Each setting gets a **persistence** proof
(PUT→GET round-trip) and, where observable, a **behavioral** proof across the
data plane with the observed evidence logged into each assertion.

It uses its **own** risk-enabled override stack on **distinct ports**
(`26880` proxy / `26827` admin) so it coexists with a dev stack on `16xxx`. The
script self-manages that stack (seed config → `up --build` → wait → test):

```bash
# Prerequisite: a CURRENT release binary (the image bakes target/release/waf;
# a stale binary silently disables risk scoring — the smoke gate fails loudly).
cargo build --release -p prx-waf

# Run (brings its own stack up on 26880/26827):
bash tests/e2e/run-risk-config.sh
# Against an already-running risk override stack (skip build/seed):
RISK_MANAGE_STACK=0 bash tests/e2e/run-risk-config.sh

# Artifacts: tests/e2e/out/risk-config/{results.json,junit.xml,summary.md}
# render-report.sh auto-appends any present results dir not in its expected
# SUITES list, so a local aggregate includes risk-config while a nightly run
# (no risk-config job yet) simply omits it — no MISSING/FAIL.
```

**Excluded (documented, not hidden):**

- `GET /api/risk/metrics` and `GET /api/risk/actors` are **v1 stubs** (return
  zeros / empty) — asserted only as documented exclusions.
- `store.*` fields and `gc_interval_secs` are **persistence-only** (memory-only
  stack; no black-box behavioral signal).

**Findings surfaced by the suite (asserted as real contract, logged loudly):**

- `PUT /api/risk/config` validates **structure (serde) only, not semantics**: a
  well-typed but invalid `store.backend` (e.g. `postgres`) is accepted (HTTP
  200) and written; the engine's reload `validate()` is the sole backstop
  (rejects it, keeps the prior snapshot).
- **Decay params** (`decay_rate` / `min_clean_streak` / `max_decay`) **plus
  `ttl_secs` and `gc_interval_secs`** are applied at store **construction (boot)
  only** — the reload watcher swaps the config snapshot but never rebuilds the
  store (`MemoryRiskStore` caches `DecayConfig`; `build_risk_store` captures
  `ttl_ms` and starts the purge loop once). A PUT persists but does not take
  effect until restart, and (unlike `store.backend`) **no warning is logged**.
  The suite proves decay + ttl expiry behaviorally at the boot fixture and cites
  `risk/decay.rs` unit coverage for the `decay_rate=0` (constant) case.

**CI (not wired yet — local-only for now).** To add a nightly job, mirror an
existing suite job in `.github/workflows/nightly-e2e.yml`: build the binary,
`docker compose -f tests/e2e/docker-compose.e2e.yml -f
tests/e2e/docker-compose.risk-override.yml up -d --build`, then
`RISK_MANAGE_STACK=0 bash tests/e2e/run-risk-config.sh`, and upload
`tests/e2e/out/risk-config/`.

## On-GitHub viewing

After the nightly run completes the report is reachable from three places:

- **Workflow run page** — the Markdown summary at the top of the page (every
  suite job + the aggregated `report` job all write to `$GITHUB_STEP_SUMMARY`).
- **Checks tab** — `mikepenz/action-junit-report` publishes per-test pass/fail
  with stack traces directly on the commit / PR.
- **Artifacts** — `e2e-report` artifact contains a self-contained `report.html`
  for sharing or archiving.
