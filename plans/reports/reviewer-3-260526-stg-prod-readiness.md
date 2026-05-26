---
type: reviewer
date: 2026-05-26
slug: stg-prod-readiness
target: release/stg deploy from `main`
reviewer: reviewer-3
team: stg-issue-triage-260526
---

# Reviewer-3 Report — Production Readiness Audit cho release/stg deploy

**Branch:** `main` @ `4c0a1d73` (read-only)
**Standard:** production-grade (cao hơn dev)
**Verdict ngắn gọn:** ⚠ **NO-GO** cho release/stg cho đến khi blocker nhóm 1+2 fix xong. CI đang đỏ cả `CI` lẫn `Coverage` trên main. Có 21 issue HIGH/CRITICAL open chưa giải quyết.

---

## 1. Deploy Readiness Checklist

| Category | Status | Note |
|---|---|---|
| CI pipeline pass trên main | ✗ | 4 lần push gần nhất: Coverage fail (waf-storage), CI fail (Test job), Nightly E2E fail. Chi tiết §2.1 |
| Test job (full workspace) | ✗ | Job `Test` của CI fail trên commit gần nhất (`af10edb5`). Cần xác nhận failure cause |
| Coverage gate ≥90% (rules.md item 6) | ⚠ | Per-crate floors thấp hơn rule (waf-api 80, gateway 85, waf-engine 80, waf-cluster 82, prx-waf chỉ 5). Coverage scoped gate trong `ci.yml` đã bị comment out hoàn toàn. Coverage `waf-storage` job đang fail trên main |
| Lint (clippy + fmt + machete) | ⚠ | Job `Lint` chưa thấy fail gần đây nhưng job `Test` đỏ → coi như chain blocker |
| `cargo fmt --all -- --check` | ⚠ | Chưa verify trên main này; CI enforce nên nếu Lint pass thì ok |
| Dockerfile multi-stage build | ✓ | `Dockerfile` (3 stage: valkey + frontend + rust + runtime) — chuẩn |
| Dockerfile.prebuilt | ✓ | Single-stage debian:bookworm-slim cho local binary fast path |
| docker-compose.yml stack | ✓ | Postgres 16 + Valkey 8 + tls-init + prx-waf + juice-shop (test target). Healthcheck đầy đủ. Ports 16880/16843/16827 |
| Config completeness | ⚠ | `configs/default.toml` có [proxy] [api] [storage] [cache] [security] [panel] [rate_limit] [victoria_logs]. Một số section quan trọng còn comment (community, outbound, cluster). Không có file `prod.toml` riêng — staging dùng default.toml + ENV override |
| Secret loading | ⚠ | `JWT_SECRET` env có default `change-me-in-production-with-a-long-random-secret` trong docker-compose.yml — **MUST override trên stg** |
| Env-var override | ✓ | `CACHE_BACKEND`, `JWT_SECRET`, `DATABASE_URL`, `RUST_LOG`, `SSL_CERT_FILE` đều support qua env |
| Migrations consistency | ⚠ | 16 migration `.sql` UP-only. Không có `down.sql` / rollback. Production rollback = restore from snapshot only |
| Latest migration | ✓ | `0016_host_http_redirect.sql` — đơn giản, additive `ADD COLUMN IF NOT EXISTS` (safe) |
| Admin panel build | ✓ | `web/admin-panel/dist/` đã pre-build (assets + index.html). Embedded via `rust_embed` vào binary, serve `/ui/*` |
| Single-binary deploy (NFR §4) | ✓ | `cargo build --release` → 1 binary `prx-waf` (rename → `waf` trong release tarball). Migrations + rules + configs bundled trong tar.gz |
| Release workflow (`release.yaml`) | ✓ | Trigger trên tag `v*` hoặc workflow_dispatch. Build trên rocky9 container (glibc 2.34 = EC2 target). Deploy job self-hosted runner trên EC2 + health probe `/health` |
| Health endpoint | ✓ | `http://127.0.0.1:9527/health` — release deploy job wait tới 60s |
| Observability — VictoriaLogs sidecar | ✓ | `[victoria_logs] enabled = true`, auto-install v1.50.0, loopback only (127.0.0.1:9428), proxy qua `/api/v1/logs` với JWT |
| Observability — metrics/tracing | ⚠ | `tracing` có nhưng chưa thấy Prometheus `/metrics` endpoint trên audit này. Verify trước khi prod |
| FR-001..039 P0 coverage trong code | ⚠ | 29/39 FR có reference trực tiếp trong code. Một số FR thiếu reference: FR-013 (SQLi), FR-021–024 (rule hot-reload + scoping + priority), FR-026–027 (risk dynamics + thresholds), FR-029 (live feed), FR-031 (hot config), FR-038 (configurable fail-mode). Chi tiết §4 |
| FR-040..046 P1 (bonus) | ⚠ | FR-040 TLS termination chưa hoàn thành (issue #95 open, PR #98 phases 03–06 chưa land). FR-041 GeoIP có maxminddb dep + asn_feed. Khác chưa verify |
| 7 open issues CRITICAL | ✗ | #70 cluster join token unused, #75 dual-Main split-brain, #76 single-node split-brain, #77 SSRF IPv6 bypass, #78 WASM MAX_MEMORY không enforce |
| 14 open issues HIGH | ✗ | #71–73, #79–87 (regex DoS, cert validation, WS DoS, rule reload partial state, snapshot bomb, charset bypass, header injection, FP rotation DoS, response cache leak) |

---

## 2. BLOCKERS — Phải fix trước/cùng staging deploy

### 2.1 CI/Coverage đang đỏ trên main (BLOCKING)

- Run `26423375952` (CI) và `26423375954` (Coverage) đang `in_progress` 6m45s — last terminal state 4/5 push gần đây là `failure`.
- Coverage `waf-storage` matrix luôn fail; các crate khác pass với floors hiện tại (gateway 87.47%, waf-engine 92.31%, waf-common 96.78%).
- Job `Test` của CI (workflow `ci.yml`) fail trên commit `af10edb5`.
- **Action:** Fix root cause Coverage(waf-storage) (Postgres service container start nhưng tests vẫn fail — không thấy line "OK:" hay floor check trong log; ngụ ý cargo test panic trước khi llvm-cov tính %). Rerun, đảm bảo green trước khi cut tag.

### 2.2 Coverage gate dưới chuẩn rules.md item 6

- `rules.md` line 6 yêu cầu **≥90% mandatory**.
- Coverage matrix floors hiện tại: waf-common 88, waf-storage 84, waf-cluster 82, waf-api 80, gateway 85, waf-engine 80, prx-waf 5.
- Trong `ci.yml` các block `cache-coverage`, `coverage` (gateway scoped 95%), `device_fp-coverage` đã bị **comment toàn bộ** — không enforce gì cả.
- **Action:** Hoặc nâng floors lên 90 + uncomment scoped gates, hoặc document rule downgrade (cần user approval — không tự ý reverse rule).

### 2.3 CRITICAL issues open (5)

- **#75 Cluster main không step down khi mất quorum → dual-Main split-brain** — nếu stg deploy multi-node phải vô hiệu cluster mode hoặc fix trước.
- **#76 Single-node bootstrap promote → split-brain sau peer eviction** — same as #75.
- **#77 SSRF private-IP guard bypass qua IPv4-compatible IPv6** — security boundary bypass, WAF nhiệm vụ core.
- **#78 WASM plugin `MAX_MEMORY_BYTES` declared but never enforced** — plugin DoS vector.
- **#70 Cluster join token validation wired but unused (PKI only)** — auth gap nếu cluster bật.
- **Action stg-specific:** nếu stg single-node + cluster disabled + WASM plugin disabled → #70/#75/#76/#78 không impact runtime. #77 vẫn là critical vì SSRF guard luôn active. Phải fix #77 hoặc accept risk có document.

### 2.4 JWT_SECRET default trong docker-compose.yml

- `JWT_SECRET: ${JWT_SECRET:-change-me-in-production-with-a-long-random-secret}` — nếu deploy quên set env, sẽ chạy với secret hardcode.
- **Action:** stg deploy phải set `JWT_SECRET` qua `/etc/prx-waf/env` (release deploy script render từ env). Verify trước boot.

### 2.5 Migration không có rollback

- 16 migration UP-only, không có `down.sql`.
- Latest (`0016_host_http_redirect.sql`) additive nên safe forward, nhưng nếu cần rollback chỉ có cách restore DB snapshot.
- **Action:** Stg pre-deploy phải snapshot Postgres. Document trong runbook.

---

## 3. Nice-to-have improvements (không block stg, nên fix trong sprint sau)

- **CI:** unify `Test` và `Coverage` workflow. Hiện 2 workflow song song nhưng coverage không gate trên test pass.
- **CI:** upgrade `actions/checkout@v4` → khắc phục Node.js 20 deprecation warning (deprecate Sep 2026).
- **release.yaml:** dùng `cargo build --release --locked` đã có; nên thêm `cargo deny check` step (đã có sec-audit workflow nhưng release.yaml không depend).
- **Dockerfile:** chỉ build với `--features gateway/valkey` — nếu stg dùng `backend = "memory"` thì lãng phí binary size. Có thể split image variant.
- **Observability:** Prometheus `/metrics` endpoint nếu chưa có. Audit log đã có (VictoriaLogs), nhưng cần dashboard config.
- **Config:** thêm `configs/stg.toml` riêng để tách dev/stg/prod, tránh sửa default.toml gây drift.
- **Docs:** `docs/deployment-guide.md` đã có, nên cập nhật quy trình stg cut + rollback runbook.

---

## 4. FR-* P0 gap analysis (xếp theo severity)

### High severity — FR thiếu reference rõ ràng trong code (cần verify implementation)

| FR | Yêu cầu | Status grep | Risk |
|---|---|---|---|
| FR-021 | Hot-reload rules WITHOUT rebuild | có `rules/engine.rs`, `access/reload.rs`, `cache/rules.yaml` watcher — implementation tồn tại, không reference theo code FR-021 | Verify operator có thể edit YAML và rules reload |
| FR-022 | Rule format YAML/TOML + condition+action+risk_score_delta | có `rules/formats/custom_rule_yaml.rs` | OK đoán |
| FR-023 | Rule scoping (global, tier, route, IP, session, device_fp) | scope-by-tier có; per-session/per-device_fp scope chưa verify | Medium |
| FR-024 | Rule priority numeric | grep "priority" trong rules engine cần verify | Medium |
| FR-026 | Risk score dynamics (increase/decrease) | có `risk/scorer.rs`, `risk/state.rs` — implementation có | Verify decrease path |
| FR-027 | Decision thresholds configurable <30/30-70/>70 | `checks/rate_limit/check.rs` có `challenge: 70` — verify configurable | Medium |
| FR-029 | Live request feed realtime | Dashboard backend có (`260515-1714-fr030-dashboard-backend`) | Verify Refine UI render live feed |
| FR-031 | Hot config update — NO restart | hot-reload có cho rules, panel config; thresholds verify | Medium |
| FR-038 | Fail-mode configurable per tier | `tier_config_watcher.rs` có `fail_mode = "close"/"open"` | ✓ verified |
| FR-013 | SQL Injection (classic, blind, time-based, UNION) | `checks/sql_injection.rs`, `checks/sql_injection_scanners.rs`, `checks/sql_injection_patterns.rs` — implementation hiện diện. Open issue #85 charset bypass | Active |

### Medium severity — chưa land hoặc partial

| FR | Status |
|---|---|
| FR-040 (P1) HTTPS/TLS termination | issue #95 open, PR #98 phase 01+02 landed, phase 03–06 (ACME, renewal hardening, UI, audit) chưa. Có thể stg vẫn dùng nginx fallback hoặc disable TLS native |
| FR-041 (P1) GeoIP restriction | maxminddb dep + asn_feed có. Chưa verify wiring + DB file present |
| FR-045 (P1) Auto Scaling | cluster mode có nhưng issue #75/#76 chặn |

---

## 5. Recommended Pre-Deploy Verification Steps

```bash
# 5.1 Local pre-flight
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo build --release --locked --features gateway/valkey -p prx-waf

# 5.2 Docker build smoke (without local rust)
podman-compose down && podman-compose up -d --build
curl -fsS http://localhost:16827/health
curl -fsS http://localhost:16880/  # WAF proxy through juice-shop

# 5.3 CI green check before tag
gh run list --branch main --limit 1   # all SUCCESS

# 5.4 Stg deploy procedure
# a) Snapshot Postgres prod DB
# b) Set /etc/prx-waf/env: JWT_SECRET=<32+ random bytes>, DATABASE_URL=...
# c) Push tag vX.Y.Z-stg
# d) Self-hosted runner trigger release.yaml deploy job
# e) Watch /health probe (max 60s wait)
# f) Smoke test golden path: GET /, POST /login, /api/v1/logs
# g) Verify migrations: psql -c "SELECT * FROM _sqlx_migrations ORDER BY version DESC LIMIT 1;"
# h) Verify VictoriaLogs sidecar: curl 127.0.0.1:9428/-/health

# 5.5 Rollback plan (no auto rollback)
# a) Restore Postgres snapshot
# b) Re-deploy previous tag via workflow_dispatch
# c) systemctl restart prx-waf
```

---

## Top-3 Blockers (TL;DR cho lead)

1. **CI/Coverage đỏ trên main** — `Test` job + `Coverage (waf-storage)` cùng fail liên tiếp 4 commits. Phải debug root cause trước khi cut release tag (release.yaml không depend trên CI nhưng nên gate manual).
2. **5 issue CRITICAL open** (#70 #75 #76 #77 #78) — #77 SSRF bypass impact stg ngay cả single-node. #75/#76 chặn nếu định bật cluster mode trên stg.
3. **Coverage gate < rules.md mandate 90%** — workspace floors 5–88%. Cần lead approve downgrade (không tự ý reverse user rule) hoặc nâng floors + uncomment các scoped gates trong `ci.yml`.

**Recommendation:** **NO-GO** stg deploy đến khi (1) CI green ≥ 2 lần liên tiếp, (2) #77 SSRF fix hoặc accept-risk có dấu, (3) JWT_SECRET stg env confirmed set, (4) DB snapshot pre-deploy ready.

Nếu time-pressure, **CONDITIONAL-GO** với:
- Cluster mode DISABLED trong stg config (vô hiệu #70/#75/#76).
- WASM plugins DISABLED (vô hiệu #78).
- #77 patched hoặc SSRF guard tightened cho IPv6.
- CI gate manual override + DB snapshot taken.

---

## Open Questions

1. Stg deploy target: single-node EC2 (như release.yaml) hay multi-node cluster? Cluster mode chưa production-ready (5 critical open).
2. JWT_SECRET production secret rotation policy — có sẵn vault/env-store? Hay phải gen + paste manual?
3. Coverage rule (rules.md item 6 = 90%) có flex cho stg deploy hay strict luôn?
4. PR #98 phase 03–06 (ACME + audit + metrics) có phải scope stg hay defer? Nếu stg cần HTTPS native phải merge tất cả phases trước.
5. Migration rollback: stakeholder accept "no rollback, snapshot only" hay cần build down.sql cho 16 migration?
6. Coverage `waf-storage` fail root cause — tests assume sqlx fixtures? Need debug log.
7. Frontend admin panel embedded build version (1.1.0 trong package.json) — đã test với latest backend API contract chưa?
