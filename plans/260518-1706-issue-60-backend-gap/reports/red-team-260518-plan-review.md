---
name: red-team-issue-60-backend-gap
description: Adversarial review of audit-emitter plan — finds wrong entry-points, latency risk, WS broadcast loss, suppression hiding evidence
date: 2026-05-18
target: plans/260518-1706-issue-60-backend-gap/
reviewer: code-reviewer
---

# Red-team — Plan 260518-1706 Issue #60 Backend Gap

## TL;DR

1. **Multiple entry points in plan are factually wrong against the codebase.** `RelayDetector::evaluate` is invoked in `crates/gateway/src/proxy.rs:432`, **not** `engine.rs` — Phase 2 cannot wire its emit at the location it claims. `tx_velocity::check::evaluate(...) -> Option<TxBreach>` **does not exist** — `TxVelocityCheck::check()` is a `Check` impl that always returns `None` and records into the store; breaches are emitted as risk signals from `recorder.rs`, not breaches returned to a caller (Phase 3 entire entry-point story is broken).
2. **`canary::check_and_ban` returns `bool`, not `CanaryDecision`** (verified `risk/canary.rs:96`). Phase 4's reference signature `CanaryDecision::Block` does not exist. Caller in `risk/scorer.rs:178` already conditionally branches on `true`; Phase 4 must hook there, not the imaginary engine site it claims.
3. **WebSocket subscribers lose events when the rate-limiter suppresses.** `Database::create_security_event` calls `broadcast_event` on every persisted row (`repo.rs:429`). 59 of every 60 hits will not just skip Postgres — they will also not surface in the live FE feed. Plan never discusses this trade-off.
4. **Plan reference to `engine.rs:858/859` is the wrong target** for a "replace bare tokio::spawn" — that path runs only for the **single** decision result built by `log_security_event`, which already has its own rate-limit semantics (one row per rule match per request). Hot-path multiplication only happens **inside the detection layers**, not at that call site. Phase 1 step 6 ("`engine.rs::log_security_event` chuyển 100% qua emitter") will not reduce DDoS load on its own; it just adds a hop.
5. **No rollback strategy across all 8 phases.** When emitter starts dropping events at 0.5%, the only knob is the channel cap, which requires recompile. No feature flag, no kill switch, no AuditEmitterConfig::disabled mode wired into Engine ctor.

---

## Per-phase findings

### Phase 0 — Research consolidation (`phase-00-research-consolidation.md`)

**F0.1 — "Default `HONEY-001` if reviewer silent within 24h" is irreversible after merge** (§Risk Assessment, §Implementation Step 3).
Default lands in `engine.rs` constants + integration test expectations + DB rows. If reviewer wakes 25h later wanting `CANARY-NNN`, every historical row is mis-labeled and FE filters by the wrong prefix forever. This violates `review-audit-self-decision.md` Rule 3 ("Guard User Decisions Against Audit/YAGNI Drift") — `@protonmns` has not confirmed; you're proposing to silently lock the value via timeout. **Concrete failure**: PR #58 already merged on 2026-05-15; if the issue #60 reviewer is the same person and follows a typical FE-team review cadence (3–5 days), the 24h timeout is short enough to ship the wrong constant. Mitigation: ship behind a `const HONEYPOT_RULE_ID: &str = "HONEY-001"` so the rename is one diff, plus DB UPDATE script in the same PR — neither is in the plan.

**F0.2 — Verifying "entry-point signatures unchanged" does not catch the gap that's already there.**
Step 7 says "verify signature `evaluate()` / `check_and_ban()` chưa thay đổi so với assumption". The signatures **were never what the plan assumes**: `RelayDetector::evaluate(peer_ip, headers) -> ClientIdentity` (not invoked from engine), `TxVelocityCheck::check(ctx) -> Option<DetectionResult>` returning always-None (no breach return-value), `canary::check_and_ban(...) -> bool` (no enum). A "snapshot" exercise that compares against an incorrect baseline silently approves the wrong assumption. Phase 0 must instead **discover** where each detection actually reaches `WafDecision` and trace it, not just `wc -l` the function header.

**F0.3 — Researcher #2 (risk distribution) blocking Phase 0 is not gated.**
plan.md row "Risk distribution endpoint | (chờ researcher #2)". Phase 0 success-criteria checkbox "table 100% chốt" depends on a researcher output that is not in the repo. If `/ck:cook` is run before that lands, Phase 0 either ships with TBD or quietly picks Option A — no gate.

---

### Phase 1 — Shared audit emitter (`phase-01-audit-emitter.md`)

**F1.1 — `format!("{}#{}", ctx.client_ip, rule_id)` allocates on every hot-path emit.** §Architecture, §Step 3.
At 5k req/s with up to 3 relay signals per request = 15k allocs/s of a 60-89-byte `String`, plus the `Arc<str>` wrapping. The researcher's claim "no per-lookup String allocation (critical at 5k req/s)" applies to **lookups in the DashMap**, but you still allocate the key to `get()` it. DashMap's `Entry` API can lookup by `&str`, but the plan calls `Arc::<str>::from(format!(...))` unconditionally. p99 ≤ 5ms budget under DDoS is tight; you've added a guaranteed alloc + UTF-8 format + `IpAddr` Display impl (which itself allocates 15-45 bytes for v4/v6) on the path.

**F1.2 — `try_send` on a full channel drops the most recent event, not the oldest.** §Architecture diagram, §Step 3, researcher §5.
`tokio::sync::mpsc::Sender::try_send` returns `Err(Full(value))` and **discards the new event**. Under sustained DB lag, this means you preserve a stale 60s-old event and drop the current one — i.e. the dashboard freezes on the queue's contents. The plan calls this "drop oldest via `try_send` not `send`" (line 58 phase-01) which is **factually inverted** — `try_send` on Full does *not* evict the oldest, it just refuses the new one. Worse, the rate-limit bucket has already been "claimed" (`replace` ran) before `try_send`, so the next 60s of emits for that key are also suppressed → cascading silent loss.

**F1.3 — Bucket claim before send creates "silent loss window".** §Architecture (3-phase ordering).
The plan orders: `check_bucket` → reserve bucket (insert) → build event → `try_send`. If `try_send` fails (Full), the bucket entry was already inserted with `expires_ms = now + 120s`. Result: **120 seconds of complete suppression** for that (IP, rule_id) after a single queue-full event, because every subsequent `check_bucket` finds an unexpired entry and short-circuits. Researcher report uses count semantics; plan inverts to expires-only — exacerbates the bug. Fix path: only insert bucket entry on successful `try_send`; not in plan.

**F1.4 — Worker is a single tokio::spawn with no supervision.** §Step 2 + §Risk Assessment.
`while let Some(event) = rx.recv().await { db.create_security_event(event).await }` — if the worker panics (e.g. sqlx returns a non-recoverable error pattern that triggers a panic somewhere in the chain), the channel becomes Closed and **every subsequent `try_send` returns `Err(Closed)` → emit() returns false silently for the rest of the process lifetime**. Risk section acknowledges this as "FOLLOW-UP, không trong phase 1" — but this is a P0 plan covering Attack Battle. A supervisor task is 10 lines and must be in scope.

**F1.5 — WebSocket broadcasts only fire when the row actually persists.** `crates/waf-storage/src/repo.rs:429` calls `broadcast_event(event_json)` inside `create_security_event` AFTER the INSERT succeeds. The plan's rate-limiter suppresses 59/60 events per IP/rule_id → **FE WebSocket feed (`/ws/events` or whatever subscribes) drops 98% of relay/tx/honeypot events under DDoS demo**. Sub-issue #2/#3/#5 frontend assumes live feed. Plan does not call this out anywhere — not in Risk, not in Out-of-scope.

**F1.6 — Metric counters not in cargo dependency graph.** §Step 5 says "3 `prometheus::IntCounter` (hoặc tracing::counter nếu codebase chưa có prometheus crate — verify)". `verify` is not a plan step — it's a question. If neither exists, Phase 1 falls into 2-hour decision drift. Either gate this on Phase 0 or pick now.

**F1.7 — `entry_ttl_secs: 120` and `window_secs: 60` are two knobs encoding one concept.**
With TTL = 2× window per researcher rationale, the GC saves work but the rate-limit window is still effectively 120s because `check_bucket` returns suppressed for the **whole expiry window**, not the 60s emit window. Plan says "1 INSERT ≤ 1/60s/IP/rule_id" but actual behavior is **≤ 1/120s/IP/rule_id**. Phase 7 cardinality test will pass falsely (60 inserts allowed but only ~30 will appear).

---

### Phase 2 — FR-007 relay emission (`phase-02-relay-emission.md`)

**F2.1 — Wrong crate. `RelayDetector::evaluate` is invoked in `crates/gateway/src/proxy.rs:432`, not `engine.rs`.** Verified.
Phase says "Modify: `crates/waf-engine/src/engine.rs` — insert emit loop after relay evaluate". No such call exists. Inserting the emit at the gateway proxy point means the emitter must be threaded through `RequestCtx`/proxy ctx — a substantially different design from "emit from engine". Also `engine` is the wrong owner: the signals are produced in the access phase before WAF rule evaluation, so by the time `engine.inspect()` runs, the signals already live in `ctx.client_identity.as_ref().map(|id| &id.signals)`. Plan must rewrite Phase 2 to wire from `gateway::pipeline::access_phase` (it exists per gateway CLAUDE.md) — not engine.

**F2.2 — Mapping table doesn't match Signal enum variants.** `relay/signal.rs:30-47` enumerates:
`XffSpoofPrivate`, `XffMalformed`, `XffTooLong`, `ExcessiveHopDepth(u8)`, `AsnDatacenter{asn,org}`, `AsnResidential`, `AsnUnknown`, `TorExit`.
Plan's table lists: `XffMalformed/XffSpoof`, `ProxyChain`, `TorExit`, `AsnSuspect/AsnBlocked`, catch-all. **Five of these variants don't exist** (`XffSpoof`, `ProxyChain`, `AsnSuspect`, `AsnBlocked`, catch-all). And the actual `ExcessiveHopDepth(u8)`, `AsnResidential`, `AsnUnknown` are not mapped. Phase 2 §Success criteria demands "exhaustive match" — that will fail to compile until the table is rewritten. The mapping work is *not* the "1 hour" implied by phase 2's 3h estimate.

**F2.3 — `&'static str` action selection conflicts with engine's existing action vocabulary.**
Engine uses `WafAction::{Block,Allow,LogOnly,Redirect,Challenge}` → maps to action strings `block/allow/log_only/redirect/challenge` (verified `engine.rs:830-836`). Phase 2 talks about "action value lấy từ engine decision … mặc định `log_only` nếu signal chỉ raise risk score". But at the gateway access-phase emit site, the engine decision **has not run yet** — so you have no `WafDecision` to read. The mapping is "always log_only" until plumbing is added. Plan should be explicit: relay-signal emits are **always `log_only`**, or the design needs a second emit pass after engine runs.

---

### Phase 3 — FR-012 tx_velocity emission (`phase-03-tx-velocity-emission.md`)

**F3.1 — `tx_velocity::check::evaluate(...) -> Option<TxBreach>` does not exist.** Verified.
`crates/waf-engine/src/checks/tx_velocity/check.rs` (213 lines): only `impl Check::check(&self, ctx) -> Option<DetectionResult>` returning `None` unconditionally (signal-only check, per file's own docstring). Breaches are emitted as risk signals **inside** `recorder.rs::record()` via classifiers — they never return up the call stack. Phase 3 §Architecture pseudocode (`let breach = self.classifier.classify(...)?; self.emitter.emit(...); Some(breach)`) describes code that does not exist and contradicts the documented "signal-only" architecture (`check.rs:3-9`).

The actual insertion point is inside `recorder.rs:201` where `classifiers.iter().filter_map(|c| c.evaluate(&snap, now_ms, &cfg))` produces signals — these are routed to the aggregator. The emit needs to attach there, or in the aggregator that consumes them. Phase 3's "modify check.rs" is impossible without redesigning the recorder. **Effort estimate "3h" is wrong — closer to 1d** once the right insertion is found.

**F3.2 — `ctx.request` does not exist.** Phase 3 pseudocode `self.emitter.emit(&ctx.request, …)`. The recorder operates on `SessionKey`, not `RequestCtx` — the request has been turned into a session event by then. To emit, you need to plumb `RequestCtx` (or just `client_ip` + `host_code`) through the recorder, which the recorder explicitly avoids per its design.

**F3.3 — `Check::new(...) thêm param emitter`** breaks `TxVelocityCheck::new()`'s `const fn` signature.
Phase 3 step 2 wants to inject `Arc<AuditEmitter>` into `TxVelocityCheck`. The current constructor is `pub const fn new(cfg, store) -> Self`. `Arc<AuditEmitter>` is fine in const fn (since Rust 1.78). But the deeper concern: the emit needs to happen from the **recorder** (where breach detection actually runs), not from the `Check` wrapper that records-and-forgets. Threading the emitter through `TxStore` is a non-trivial refactor — at minimum changes the public `TxStore::new(cfg)` signature and ripples through the FR-012 plan's owner.

---

### Phase 4 — FR-028 honeypot emission (`phase-04-honeypot-emission.md`)

**F4.1 — `canary::check_and_ban` returns `bool`, plan references nonexistent `CanaryDecision::Block`.** Verified `risk/canary.rs:96`.
`pub fn check_and_ban(&self, path: &str, ip: IpAddr, now_ms: i64) -> bool`. Phase 4 §Architecture references `CanaryDecision::Block` and `match canary_decision { CanaryDecision::Block => ... }`. That enum doesn't exist. The real call site is `risk/scorer.rs:178`: `if let Some(ref canary) = self.canary && cfg.canary.enabled && canary.check_and_ban(&ctx.path, ctx.client_ip, now_ms) { ... }`. That's the only consumer.

**F4.2 — Honeypot rate-limit collapses bot-quét evidence to 1 path per IP per 60s.** §Requirements +§Notes.
Plan: "bot quét sẽ hit cùng IP nhiều honeypot path trong burst; chỉ cần 1 entry là đủ alert". This is a defensible product call **for alerting**, but it destroys forensic evidence: if a scanner sequentially probes `/.env`, `/.git/config`, `/wp-admin`, you record exactly **one** path. For Attack Battle judges asking "what did they probe" the answer is "we deduplicated". Detail JSON only carries the first path. No counter for "additional honeypot hits suppressed". This is precisely the kind of cardinality decision that should be explicit, with a "stretch" metric showing the true count.

**F4.3 — `format!(r#"{{"path":"{}"}}"#, escape_json(&ctx.path))` is hand-rolled JSON.** §Architecture Option (b).
`escape_json` does not exist in this codebase (verify before claiming). Plan elsewhere insists on `serde_json::json!` for safety. Using `serde_json::json!({"path": ...}).to_string()` is fine and standard — drop the hand-rolled variant.

**F4.4 — Plan emits AFTER the canary returns true, but scorer immediately calls `force_max` and `ban_table.insert` — race window where a duplicate burst hits before the emit but after the ban applies.** `scorer.rs:176-199`.
Result: same IP hits `/honeypot` 1000 times in 5ms before ban propagates; first call emits (bucket empty), but you've also short-circuited every subsequent call's path in scorer (`force_max` already pinned, ban applied). The bucket suppresses the 999 anyway. Acceptable but should be documented as "honeypot count is unreliable for cardinality reasons" not "honeypot emits 1 row per hit".

---

### Phase 5 — FR-042 reputation API (`phase-05-reputation-api.md`)

**F5.1 — `state.engine.reload_reputation_feeds()` does not exist.** §Step 4.
There is no such method on engine. Reload pattern in `relay/mod.rs:70-76` spawns `intel_refresh_loop(provider, interval)` tasks at construction; refresh runs on interval, not on demand. To make `POST /api/reputation/refresh` work, you must either (a) add `fn trigger_refresh(&self)` on `IntelProvider` trait + a hand to wake the loop or (b) directly call `provider.refresh()` from the handler — bypassing the loop. Phase 5 §Architecture says "spawn `state.engine.reload_reputation_feeds()` (gọi existing reload)" — that gloss hides a real design choice. Estimate "3h" is again low.

**F5.2 — `last_refreshed_at` and `last_error` are NOT tracked anywhere.** Verified — `relay/intel/mod.rs` defines `IntelProvider::refresh() -> Result<RefreshOutcome>` (Updated/NotModified/Failed); the `intel_refresh_loop` in `relay/mod.rs:94` *discards* the outcome ("log + retain on failure"). Plan step 1 says "Mỗi feed provider có inner state: `Arc<RwLock<FeedInternalState>>` với …". This is **new infrastructure on every provider** — `IpinfoLiteFeed`, `IptoasnFeed`, `TorFeed`, `DatacenterSet` — each gets a new state struct. That's 4 files, not "minor modify".

**F5.3 — `POST /api/reputation/refresh` lacks rate limit & idempotency token.**
Admin auth alone is not enough. If a clicker mash-clicks the refresh button 20× while a feed fetch takes 30s, you spawn 20 concurrent `refresh()` calls on the same provider, each hammering the upstream Tor exit list URL. Plan says "Refresh không block hot-path traffic (existing relay reload đã async)" — but the upstream rate-limit on the source is what fails first (HTTP 429 from torproject.org). Need a per-feed mutex or atomic "in-flight" flag, not in plan.

**F5.4 — Auth claim "reuse existing `AuthAdmin` extractor"** — that extractor name does not exist.
Codebase uses `require_auth` middleware (`crates/waf-api/src/middleware.rs:21`) — checks for JWT, sets user role into request extensions. Admin-role gating is done **per-route** inside handlers, not as an extractor. Plan must look at how `reload_rule_registry` (server.rs:193) enforces admin — that's the pattern to copy. Not "use `AuthAdmin`".

---

### Phase 6 — FR-025 risk distribution (`phase-06-risk-distribution-api.md`)

**F6.1 — Zero-downtime `ALTER TABLE security_events ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0` claim is misleading for Postgres ≥ 11.** §Architecture Option B + §Risk Assessment.
Postgres 11+ supports constant-default ADD COLUMN without a table rewrite (`fast default` feature), so the operation itself is fast. **But**:
1. The `NOT NULL` clause requires a full table scan in some Postgres minor versions if the default isn't recognized as constant — risk depends on the Postgres patch version. Not verified in plan.
2. The follow-up `CREATE INDEX ... WHERE risk_score > 0` is **not** zero-downtime — it requires `CONCURRENTLY` to avoid taking an ACCESS EXCLUSIVE lock. Plan SQL uses `CREATE INDEX IF NOT EXISTS` without `CONCURRENTLY`. On a 5M-row table this is a multi-minute lock.
3. Migration framework (`sqlx`) typically runs migrations inside a transaction — `CREATE INDEX CONCURRENTLY` is **not allowed inside a transaction**. Plan must drop the index-in-migration approach and run it as a manual op, or use sqlx's non-transactional migration support.

**F6.2 — Option A "approximation" returns plausible-looking but unverifiable numbers.** §Architecture Option A.
"`challenge` count → split 50/50 vào yellow + orange" is a fabricated heuristic with no empirical basis. Judges will compare with raw `security_events` and the 50/50 will be obviously wrong (challenge actions cluster around the configured threshold, not uniformly). Better fail: return empty `elevated` band and document. The plan picks 50/50 silently — this is exactly the kind of "Claude makes a number up" failure that `review-audit-self-decision.md` Rule 3 guards against.

**F6.3 — Phase 6 declares dependency on Phase 0** but Option A vs B decision depends on Researcher #2 which is not in the repo. Same gating gap as F0.3.

**F6.4 — Cache claim "30s response: dùng existing `tower_http::CacheLayer` nếu có, không thì skip (YAGNI)".**
`tower_http` does not ship a `CacheLayer`. If you want response caching you build it. The "if not, skip" silently flips the perf budget — endpoint must hit DB on every request → with action_breakdown style query on 5M-row 24h window, that's a 200-500ms query at p99, breaking the < 100ms claim. Either bench it (not in plan) or implement a proper cache (also not in plan).

---

### Phase 7 — Tests + cardinality (`phase-07-tests-and-cardinality.md`)

**F7.1 — Cardinality test uses 1 IP. The dangerous case is 10k IPs each hitting once per second.** §Architecture §7.1.
Plan: "1k req/s × 60s từ cùng 1 IP". This tests rate-limit suppression, which is the easy case. The dangerous case is unique IPs (botnet) where every request *passes* the bucket and goes to DB. Channel cap 512 × DB latency 50ms = 25.6s saturation budget → at 5000 unique req/s you overrun in < 0.1s. Test does not cover this. Phase 1 success criterion "5k emit/s sustained không panic" tests only `try_send` not actual DB throughput.

**F7.2 — Memory test marked `#[ignore]` on non-Linux** §Implementation Step 3. 
CI runs on `ubuntu-latest` so this is fine for CI but the developer running locally on macOS (your dev env per CLAUDE.md docker section) will silently never run it. No documented "must run before push from macOS" workflow. Memory growth in DashMap is exactly the kind of bug that bites in production but not in dev — coverage promise is weak.

**F7.3 — `cardinality test flaky on CI (timing-sensitive) — assert ≤ 63`** §Risk Assessment.
A ±5% tolerance test is a smoke test, not a regression test. If a refactor makes the limiter 10× looser (e.g. accidentally drops the bucket-claim step), 60 → 63 passes, but production behavior is now broken. Either tighten to `assert!(count >= 1 && count <= 2)` (1 IP × 60s should produce exactly 1, period, since the window is 60s) — or accept the test as a smoke test and add an exact-count test separately.

**F7.4 — Coverage gate sees pass at 90% but no semantic gate.**
A pure unit test of `signal_to_rule_id` can hit 100% line coverage by enumerating arms but say nothing about whether the emit actually persists a row. Phase 7 needs at least one end-to-end "fire request → INSERT row → readback" assertion that exercises Phase 1+2+ DB simultaneously, not just module-scoped 90% line cov. Step 1 mentions "Mock DB worker" — counter increments are not DB rows. False sense of security.

**F7.5 — "Update parent plans" §Step 8.**
Modifying `plans/260501-2003-fr007-relay-proxy-detection/plan.md` without that plan's owner's review violates `team-coordination-rules.md` file-ownership rule. At minimum should be "post a comment / send message to owner; do not silently edit owner's plan".

---

## Cross-cutting concerns

### CC1 — No observability for silent loss
The four loss modes:
1. Rate-limit suppression (expected, but cardinality unknown)
2. Channel full → `try_send` Err(Full) — current event dropped
3. Worker crash → channel Closed — all events lost forever
4. DB error inside worker → row not inserted, but bucket already claimed

Plan adds a `dropped_queue_full` counter for (2) and `suppressed_rate_limit` for (1). Cases (3) and (4) are not metric'd, not alerted. In Attack Battle, an undetected mode (3) means dashboard goes silent and the judge thinks the WAF stopped working.

### CC2 — No rollback / feature flag
Across all 8 phases, no `audit_emitter.enabled = false` knob. If Phase 1 lands and at-scale shows 5% event loss, the only fix is revert PR + redeploy. Industry standard for hot-path additions: behind an env/config flag, default-on in staging / default-off in prod for first 24h. Plan does not include this.

### CC3 — Cardinality contract is fragile
Plan claims "30 distinct rule_ids" (plan.md §Approach / researcher §2). But:
- Phase 2 mapping table currently lists 5 IDs (`BOT-XFF-SPOOF-001`, `BOT-PROXY-CHAIN-001`, `BOT-RELAY-TOR-001`, `BOT-RELAY-ASN-001`, `BOT-RELAY-OTHER-001`).
- Phase 3 adds 3 (`TX-SEQ-001`, `TX-WITHDRAW-001`, `TX-LIMIT-001`).
- Phase 4 adds 1 (`HONEY-001`).
That's 9, not 30. If a future contributor includes ASN or hop-depth in rule_id (e.g. `BOT-RELAY-ASN-1234-001`), cardinality grows unboundedly and the DashMap hits its 100k cap. **The 30 number has no enforcement** — nothing in code prevents drift. At minimum: rule_id should be `&'static str` validated against a hard list at compile time (e.g. enum), and bucket lookup should refuse unknown IDs.

### CC4 — WebSocket FE feed coupling
Already noted as F1.5 but cross-cutting: every `create_security_event` call broadcasts via `repo.broadcast_event`. Rate-limited emits suppress both DB and WS. Plan does not propose splitting: e.g. always broadcast to WS (cheap), only persist 1/60s/IP/rule_id. That would give judges a live view of the storm while keeping the DB sane.

### CC5 — Plans claim entry points that don't match reality
F2.1, F3.1, F4.1, F5.1 are independent failures of the same kind: phase architecture references code that does not exist or lives elsewhere. This means **Phase 0's "snapshot signatures" step is the load-bearing risk-mitigation in the plan — and it is too weak**. Phase 0 must be a code-walk that produces a *new* entry-point map, not a "verify unchanged" exercise. Otherwise /ck:cook will hit walls at Phase 2-5 and burn the timeline.

### CC6 — Estimate 22h backend is significantly low
After F2.1, F3.1, F5.1 corrections:
- Phase 2: gateway integration, not engine, plus mapping rewrite → 5-6h not 3h
- Phase 3: recorder/aggregator integration, not check.rs → 6-8h not 3h
- Phase 5: tracking infra on 4 providers + refresh trigger plumbing → 5-6h not 3h

Revised P0 estimate ~22-28h backend. Doesn't fit "1 day of work" framing.

---

## Prioritized fix list — top 5 things to address before `/ck:cook`

1. **Fix entry-point claims in Phase 2, 3, 4, 5 via a real code-walk in Phase 0.**
   Replace "verify signature unchanged" with "produce a file:line table of where each detection actually reaches the WAF decision/audit boundary, and where emit must be inserted." This must include `gateway::pipeline::access_phase` for relay, `recorder.rs:201` or aggregator for tx_velocity, `scorer.rs:178` for canary, and the actual non-existence of `reload_reputation_feeds()` for reputation.

2. **Reorder `emit()` so bucket-claim happens AFTER successful `try_send`, not before.**
   Phase 1 §Architecture must change. Otherwise a single Full event causes a 120s outage on that key. Add explicit unit test: "Full channel → bucket NOT poisoned, retry next request succeeds."

3. **Add a feature flag / kill switch to AuditEmitter** (e.g. `AuditEmitterConfig::enabled: bool` + Engine ctor reads from config). Without this, a 0.5%-loss bug in production is non-recoverable without a redeploy.

4. **Decouple WebSocket broadcast from DB persist** so suppression doesn't blind FE live feed. Either: (a) always broadcast, persist 1/60s; (b) broadcast suppression count as a metric event. Pick one and document.

5. **Lock the honeypot rule_id with reviewer BEFORE merge, not via 24h-timeout default.**
   If `@protonmns` does not ack within 24h, **escalate** — do not silently land `HONEY-001` and bake it into rows. The cost of waiting is 1 day; the cost of relabeling historical security events is forever.

---

## Open questions

- Is `repo.broadcast_event` consumed by any WebSocket client today, or is that wire idle? (Verifies CC4 priority.)
- Does the FR-007/FR-012 plan owner expect this emit work as their phase, or is it a separate concern? (CC5 + team-coord rule 1.)
- Is Researcher #2 (risk distribution) expected to land before /ck:cook, or should Phase 6 be deferred?
- What's the Postgres patch version in prod? (F6.1 — fast-default behavior diverges between 11.0 and 11.4+.)

---

**Status:** DONE_WITH_CONCERNS
**Summary:** Plan has multiple verified factual errors in entry-point claims (Phases 2, 3, 4, 5 reference code that does not exist or lives in a different crate), a load-bearing emit-ordering bug (F1.3) that produces 120s blackouts under burst, and no rollback story. Top 5 must-fix items listed.
**Concerns/Blockers:** Phase 0 as written cannot catch these gaps — it verifies against the wrong baseline. Plan should not enter `/ck:cook` until F2.1, F3.1, F4.1, F5.1 are reconciled via a real code-walk and the entry-point table is rewritten.
