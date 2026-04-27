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
├── run-cluster.sh               # wraps tests/e2e-cluster.sh (crates/waf-cluster)
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

# 4. Cluster suite — uses docker-compose.cluster.yml (separate stack)
bash tests/e2e/run-cluster.sh

# 5. Aggregate
bash tests/e2e/render-report.sh tests/e2e/out tests/e2e/out/aggregated
open tests/e2e/out/aggregated/report.html
```

## On-GitHub viewing

After the nightly run completes the report is reachable from three places:

- **Workflow run page** — the Markdown summary at the top of the page (every
  suite job + the aggregated `report` job all write to `$GITHUB_STEP_SUMMARY`).
- **Checks tab** — `mikepenz/action-junit-report` publishes per-test pass/fail
  with stack traces directly on the commit / PR.
- **Artifacts** — `e2e-report` artifact contains a self-contained `report.html`
  for sharing or archiving.
