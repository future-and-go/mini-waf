# Reviewer-2 — Open Issues Triage vs requirements.md

**Date:** 2026-05-27
**Branch:** `release/stg` @ `1d1434d6`
**Scope source:** `analysis/requirements.md` (228 lines)
**Issues triaged:** 6 (`gh issue list --state open`)

---

## Per-Issue Triage

### #95 — Complete native SSL/TLS architecture (ACME + DB cert + SslManager wiring)

- **Scope:** IN-SCOPE (P1) — bonus
- **Effort:** MULTI-DAY (issue itself estimates 5–25 days depending on path A/B/C/D; even Path B "DB → file materialization KISS" = ~5–7 days)
- **FR mapping:** FR-040 (`requirements.md:85`) — HTTPS/TLS termination (P1 Bonus, Medium difficulty)
- **Risk if deferred:** LOW — `context.md:188-209` shows TLS termination ALREADY live in prod via `prx-waf` (SAN cert from Let's Encrypt, certbot deploy hook). Attack Battle scoring rubric (`requirements.md:155-163`) gives 0 direct points to ACME automation. The "deferred" state only forfeits the P1 bonus (max ~3 pts of 20 in Security category since FR-040 is already counted as working).
- **Solo-loop eligible:** NO — issue body explicitly says "cần brainstorm session riêng để pick path (A/B/C/D)" + "PR riêng cho từng phase (KHÔNG big-bang)". Architectural decision required before any code; multi-phase rollout.
- **Recommendation:** DEFER post-Attack-Battle. Cert renewal is currently handled by certbot deploy hook (`context.md:191`). The issue is architectural cleanup, not a Battle blocker. **Rank: 6 (lowest pre-Battle priority).**

---

### #76 — [Critical] Single-node bootstrap promote → split-brain after peer eviction

- **Scope:** IN-SCOPE (P1) — bonus (cluster mode is FR-045 territory)
- **Effort:** MULTI-DAY — issue references `election/mod.rs:262-272` + `health/mod.rs:117-123` + needs `ever_had_peers` tracking. Cluster Criticals share the same election state machine as #75; per `context.md:18-20` "needs `NodeState` mock + QUIC roundtrip" and reviewer-1 already explicitly rejected as multi-day.
- **FR mapping:** FR-045 (`requirements.md:90`) — Auto Scaling (P1 Bonus, "High" difficulty; "shared state via Redis/etcd")
- **Risk if deferred:** MEDIUM/LOW for Attack Battle — Attack Battle is 45min single-cluster (`requirements.md:23`). Split-brain triggers require partition + peer eviction, which Red Team is unlikely to induce in 45 min on a hardened single-node deploy. Production risk is real but post-Battle.
- **Solo-loop eligible:** **NO** — explicit hard counter-condition per `context.md:183` ("anything requiring multi-node mock or wholesale refactor"). Reviewer-1 already rejected.
- **Recommendation:** ESCALATE — needs dedicated cluster-mode sprint with multi-node integration test harness. **Rank: defer (post-Battle).**

---

### #75 — [Critical] Cluster main never steps down on quorum loss → dual-Main split-brain

- **Scope:** IN-SCOPE (P1) — cluster mode is FR-045
- **Effort:** MULTI-DAY — `election/mod.rs:240-247` modification + multi-node mock to verify demote-to-worker; companion to #76 (same election state machine per `context.md:20`).
- **FR mapping:** FR-045 (`requirements.md:90`) — Auto Scaling / cluster correctness
- **Risk if deferred:** MEDIUM/LOW for Attack Battle (same reasoning as #76 — partition+eviction within 45min unlikely). HIGH for any multi-node production deploy.
- **Solo-loop eligible:** **NO** — same hard counter-condition (`context.md:183`). Issue body explicitly requires election state machine refactor + quorum-counting on heartbeat tracker.
- **Recommendation:** ESCALATE — bundle with #76 + #70 as a single cluster-correctness sprint after Attack Battle. **Rank: defer (post-Battle).**

---

### #74 — [Medium] Follow-up cleanup (WS DoS / rate-limit XFF / heatmap semantics / category function migrate)

- **Scope:** Mixed — see sub-items below.
- **Effort:** MEDIUM — issue is a grab-bag of 7 sub-items, each surgical individually; `context.md:24` says "Multi-PR split". Total estimated 2–3 PRs.
- **FR mapping per sub-item:**
  - 74.1 (WS conn cap per-user): FR-031 / FR-032 (`requirements.md:71-72`) — Dashboard auth surface hardening. **IN-SCOPE infra (admin panel DoS resistance).**
  - 74.2 (WS JWT in query): FR-032 (`requirements.md:72`) — audit log integrity. **IN-SCOPE security hygiene.**
  - 74.3 (API rate limiter XFF): FR-004 (`requirements.md:44`) **indirectly** — admin API rate limit (not request rate limit on protected traffic). Borderline; admin-panel only. **IN-SCOPE P1 hygiene.**
  - 74.4 (heatmap `rule_id IS NOT NULL`): FR-030 (`requirements.md:70`) — endpoint heatmap correctness. **IN-SCOPE P0 dashboard.**
  - 74.5 (`stats_overview` live override): FR-030 (`requirements.md:70`) — visualization correctness. **IN-SCOPE P0.**
  - 74.6 (`category_of()` migration): FR-030 (`requirements.md:70`) — category classification consistency. **IN-SCOPE P0.**
  - 74.7 (per-route body limit on admin POST): post-#71 defense-in-depth. **IN-SCOPE hygiene.**
- **Risk if deferred:**
  - 74.1/74.2/74.3 — Attack Vector "DDoS L4 & L7" (`requirements.md:186`) targets the WAF data-plane, but admin panel auth surface DoS could pivot operator visibility during Battle. LOW-MEDIUM risk.
  - 74.4/74.5/74.6 — Direct judge-visibility risk. FR-030 attack visualization scored under "Dashboard UI/UX 10pts" (`requirements.md:162`). Heatmap with empty cells / category mismatch is observable by judges.
- **Solo-loop eligible:** **YES per sub-item.** Each is 1-file surgical. Mirrors pattern from PR #117 (`apply_sync_response` guard) and PR #122 (cap validation).
- **Recommendation:** SPLIT — solo-loop the 3 dashboard-correctness items first (74.4, 74.5, 74.6 → highest judge-visibility, 1 PR each) and 74.1/74.7 next. Defer 74.2/74.3 to backlog (UX cost vs Battle marginal). **Rank: 2-3-4-5 (top of queue for dashboard semantics).**

---

### #70 — [Critical] Cluster join token validation wired but unused — PKI is only auth

- **Scope:** IN-SCOPE (P1) — cluster mode (FR-045)
- **Effort:** MULTI-DAY — issue cites `lib.rs:147-157` + `transport/server.rs:203-261` + needs integration test reject empty/bad token. Per `context.md:18` "Needs `NodeState` mock + QUIC roundtrip"; reviewer-1 deferred.
- **FR mapping:** FR-045 (`requirements.md:90`) — cluster security (defense-in-depth on join). No direct rubric requirement; mTLS auth currently satisfies single-binary cluster join.
- **Risk if deferred:** LOW for Attack Battle — Red Team is not attacking cluster join (sandbox is single-instance per `requirements.md:23`). Production risk = whoever has node cert can join with bogus token; mTLS PKI is the actual gate.
- **Solo-loop eligible:** **NO** — `context.md:183` hard counter-condition. Multi-node mock + QUIC roundtrip needed.
- **Recommendation:** ESCALATE with #75 + #76 (cluster sprint). Alternative simpler path mentioned in issue body: "xoá `crypto/token.rs` + doc rõ cluster join = mTLS với node cert pre-issued" — that variant IS solo-loop eligible (surgical delete) but **reverses dead-code** decision and needs user confirmation (`review-audit-self-decision.md` Rule 3: never silently reverse). **Rank: defer (post-Battle).**

---

### #60 — Admin Panel Missing FR Coverage (meta — 7 sub-issues bundled)

- **Scope:** IN-SCOPE (P0) — direct dashboard requirements
- **Effort:** MEDIUM (per sub-issue ~3–6h, total ~28h frontend); `context.md:26` notes "PR #62 split in progress (#105 PR-A draft + B/C/D pending)" — splitting already underway.
- **FR mapping per sub-item:**
  - #60.1 Challenge stats widget: **FR-006** (`requirements.md:46`) P0
  - #60.2 Relay/Proxy panel: **FR-007** (`requirements.md:47`) P0
  - #60.3 Transaction velocity page: **FR-012** (`requirements.md:52`) P0
  - #60.4 Risk score dashboard: **FR-025/026/027** (`requirements.md:65-67`) P0
  - #60.5 Honeypot hit log: **FR-028** (`requirements.md:68`) P0
  - #60.6 IP reputation status: **FR-007/FR-042** (`requirements.md:47, 87`) — FR-007 P0, FR-042 P1
  - #60.7 Geo attack map: **FR-030** (`requirements.md:70`) P0
- **Risk if deferred:** **HIGH judge-visibility** — `requirements.md:155-163` rubric "Security Effectiveness 40 pts" implicitly evaluated via dashboard evidence; "Intelligence & Adaptiveness 20 pts" rewards visible risk-score evidence; "Dashboard UI/UX 10 pts" directly scored. Without these widgets the backend FRs exist but **cannot be demonstrated** to judges in 45 min Battle.
- **Solo-loop eligible:** **YES per sub-issue.** Each is single-page Refine/React/Ant Design surgical work (issue body labels 5 as P0 ~3-6h each, 2 as P1). PR #62 split (`context.md:26`) already established the per-sub-issue pattern. No multi-node mock needed, no Rust core refactor.
- **Recommendation:** **SOLO-LOOP TOP PRIORITY.** Order from issue body summary (re-confirmed against rubric):
  1. #60.5 (Honeypot) — FR-028 direct + Attack Vector "Canary/Recon Scan" (`requirements.md:193`)
  2. #60.4 (Risk Score) — FR-025/026/027 + "Intelligence & Adaptiveness 20 pts"
  3. #60.1 (Challenge) — FR-006 + Attack Vector "Bot Login & Credential Stuffing" (`requirements.md:187`)
  4. #60.3 (TX Velocity) — FR-012 + Attack Vector "Transaction Fraud" (`requirements.md:191`)
  5. #60.2 (Relay) — FR-007 + Attack Vector "Relay & Proxy Attack" (`requirements.md:188`)
  6. #60.7 (Geo) — FR-030 stretch
  7. #60.6 (IP Reputation) — FR-042 P1, lowest

**Rank: 1 (top of Battle-prep queue).**

---

## Fix Order (Solo-loop priority queue)

Pre-Attack-Battle, in execution order — Battle visibility weighted highest:

| # | Issue | Effort | Why this slot |
|---|---|---|---|
| 1 | **#60.5 Honeypot UI** (FR-028) | SURGICAL ~4h | Highest judge visibility; "Canary/Recon Scan" Attack Vector directly tested. PR #62 split pattern ready. |
| 2 | **#60.4 Risk Score Dashboard** (FR-025-027) | SURGICAL ~5h | Direct evidence for "Intelligence & Adaptiveness 20 pts". |
| 3 | **#60.1 Challenge Stats** (FR-006) | SURGICAL ~4h | Bot Login Attack Vector defense visibility. |
| 4 | **#74.4 Heatmap rule_id filter** | SURGICAL <1h | FR-030 correctness; 1-line SQL fix per issue body. |
| 5 | **#74.5 stats_overview filter prio** | SURGICAL <1h | FR-030 correctness; conditional override per issue body. |
| 6 | **#74.6 category_of() migrate** | SURGICAL ~2h | FR-030 category classification consistency across 3 endpoints. |
| 7 | **#60.3 TX Velocity Page** (FR-012) | MEDIUM ~6h | New page + nav + i18n; Transaction Fraud Attack Vector. |
| 8 | **#60.2 Relay/Proxy Panel** (FR-007) | SURGICAL ~3h | Relay & Proxy Attack Vector. |
| 9 | **#74.1 WS per-user conn cap** | SURGICAL ~2h | DashMap pattern already in repo (mirror #112). |
| 10 | **#60.7 Geo Attack Map** (FR-030) | SURGICAL ~3h | Existing `top_countries` data, no backend work. |

### Deferred (post-Attack-Battle) — escalate, do NOT solo-loop

| Issue | Reason |
|---|---|
| **#70** Cluster join token | Hard counter-condition: needs `NodeState` mock + QUIC roundtrip (`context.md:18, 183`). Reviewer-1 explicit reject. |
| **#75** Cluster main step-down | Hard counter-condition: election state machine refactor + multi-node mock (`context.md:19, 183`). |
| **#76** Single-node bootstrap | Hard counter-condition: same election state machine as #75 (`context.md:20, 183`). |
| **#95** Native TLS phases 03–06 | Multi-day, architectural path-choice required (A/B/C/D), brainstorm before code. Production cert renewal already handled via certbot deploy hook (`context.md:191`). |
| **#74.2/.3/.7** | UX/hardening, marginal Battle value. |
| **#60.6** IP Reputation status UI | P1 + degrades gracefully without new backend endpoint. |

---

## Hard Counter-Conditions Surfaced (per context.md:183)

Three of the six issues (#70 / #75 / #76 — all "Critical" labeled) match the `context.md` solo-loop counter-conditions explicitly:

- **Multi-node mock required:** #70 (`NodeState` + QUIC roundtrip), #75 (3-node election w/ partition simulation), #76 (peer eviction + heal sequence).
- **Wholesale refactor / state-machine redesign:** #75 + #76 share the same election state machine; demote logic + `ever_had_peers` field is invasive.
- **Reviewer-1 explicit reject:** documented in `context.md:16`.

**DO NOT solo-loop these.** Bundle as a single dedicated cluster-correctness sprint, post-Attack-Battle, with multi-node integration test infrastructure spun up first.

Issue #95 is NOT in the hard counter-conditions list literally, but is functionally multi-day with architectural decision required (issue body acceptance criteria lists 9 items including path selection + test coverage ≥90% + deployment doc). Treat as escalate-equivalent.

---

## Unresolved Questions

1. **#74 sub-item priority:** Should the 3 dashboard-correctness items (74.4/74.5/74.6) ship as 3 separate PRs (mirroring solo-loop pattern) or 1 bundled PR? `context.md` 17-PR ledger leans 1-PR-per-fix; bundling 3 SQL fixes is also defensible if they share a migration.
2. **#60 split status:** `context.md:26` says PR #105 = #60-PR-A draft. Is that already covering #60.5 (Honeypot, top of my recommended queue)? Worth checking before opening a duplicate.
3. **#70 alternative path:** Issue body offers "delete `crypto/token.rs` + doc PKI-only auth" as an alternative resolution. That IS surgical and solo-loop eligible, but reverses a previous user decision to ship the token feature. Per `review-audit-self-decision.md` Rule 3, requires explicit user confirmation before applying.
4. **#95 cert renewal SLA:** Cert expires 2026-08-19 (`context.md:191`). Attack Battle date unknown. If Battle > 2026-08-19 and certbot hook is the only renewal mechanism, infra dependency on certbot needs to be in the prod runbook regardless of #95 resolution.
