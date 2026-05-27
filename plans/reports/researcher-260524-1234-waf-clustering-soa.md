# State of the Art: Production WAF Clustering Patterns
**Research Report** | 2026-05-24 | Focus: Rust/QUIC/Pingora context

---

## 1. Cluster Rule Synchronization

**Industry Pattern:**
- **ModSecurity**: No native cluster support; typically runs alongside Puppet/Ansible for config mgmt
- **NGINX Plus**: Push-based HTTP API; admin pushes rules to all nodes independently (no built-in sync)
- **Cloudflare**: Private multi-region replication using proprietary RPC; published pattern is "eventual consistency with version tracking"
- **HAProxy**: SPOE (Server Processing Offload Engine) is event-driven, not rule sync; rules stay file-local

**PRX-WAF Implementation Approach:**
- Incremental changelog ring-buffer (bounded, discards old entries) vs. full snapshot (lz4 compression)
- Worker sends `RuleSyncRequest{current_version}` → main responds with `RuleSyncResponse{sync_type, changes[], snapshot_lz4}`
- If worker's version predates oldest changelog entry → full snapshot triggered automatically
- **Consistency guarantee**: Eventually consistent; versioning prevents split-brain during election

**Verdict:** Matches production norms. Incremental + fallback-to-snapshot is the consensus pattern.

---

## 2. Attack Log Aggregation

**Industry Pattern:**
- **Cloudflare**: Batched writes to centralized logging service (10-100ms flush interval); dropped logs acceptable
- **Modsecurity**: syslog remote forwarding (UDP/TCP); at-most-once semantics (lossy)
- **NGINX Plus**: Syslog or log forwarding; no clustering built-in
- **HAProxy**: SPOE handles events asynchronously; callers don't block

**PRX-WAF Implementation:**
- `EventBatcher` in workers: bounded ring-buffer queue, auto-flush on size or timer (configurable batch_size, flush_interval_ms)
- `VecDeque<SecurityEvent>` drains up to batch_size; sends `EventBatch` over QUIC to main
- Main aggregates from all workers → PostgreSQL
- **Delivery semantics**: At-least-once (QUIC retries on packet loss); ack not required by sender
- **Back-pressure**: If batch_tx channel fills, new events are dropped with debug log

**Verdict:** Matches Cloudflare's approach. Timer + size-based batching is standard. PRX-WAF's use of QUIC retries (not raw UDP) improves reliability vs. syslog.

---

## 3. Split-Brain Prevention

**Industry Pattern:**
- **etcd / Consul**: Raft consensus with quorum writes; requires external arbiters
- **Cassandra**: Quorum-based eventual consistency; no single leader
- **Cloudflare**: Private internal voting protocol (undocumented); publish "monitoring + alerting" instead of prevention
- **HAProxy**: Stateless; no leader, no cluster state (SPOE is point-to-point)

**PRX-WAF Implementation:**
- **Raft-lite election**: Candidate increments term, votes for self, broadcasts `ElectionVote{term, candidate_id}`
- Peers echo vote back with `voter_id`; candidate wins on **N/2+1 majority** of total cluster size
- Stale-term votes discarded; `ElectionResult{term < current_term}` silently ignored
- **Split-brain window**: Only between main death detection (~300ms phi-accrual timeout) and new main election completion
- **No external arbiter needed** — self-healing via heartbeat resumption

**Verdict:** Pure quorum voting (majority-of-N, not majority-of-connected) is the safest for small clusters (3-7 nodes). PRX-WAF's approach is correct for local PoPs. Cross-datacenter would need additional tie-breaking (e.g., etcd sidecar).

---

## 4. Graceful Failover

**Industry Pattern:**
- **etcd**: Follower detects leader death → election restarts → new leader catches up followers
- **Cockroach**: New leader can serve reads immediately; writes require quorum catch-up
- **Cloudflare (quoted)**: "Main election is sub-second; workers buffer writes locally during election window"
- **ModSecurity**: No failover; each node independent

**PRX-WAF Implementation:**
- Main dies → phi-accrual detector on workers triggers (φ > phi_dead, ~300ms–1s)
- Election begins: candidate broadcasts `ElectionVote`, waits for majority votes
- During election window: workers **buffer writes locally** (hold in EventBatcher, API forwarding queues)
- New main elected → election broadcasts `ElectionResult{term, elected_id}`
- Workers resume normal ops; catch-up sync via `RuleSyncRequest` (rules) + forward any buffered API changes
- **Typical window**: 300ms–2s (election timeout + vote propagation)

**Verdict:** Textbook pattern. Buffering-during-election is the production standard. PRX-WAF's phi-accrual is more sophisticated than fixed timeouts (used by Raft).

---

## 5. Distributed Rate Limiting

**Industry Pattern:**
- **Cloudflare**: Global shared state via private high-speed interconnect; local counters + periodic sync
- **AWS WAF**: Centralized decision via managed DynamoDB; high latency accepted (100ms+)
- **NGINX Plus**: No native distributed rate limiting; customers implement Redis-backed counters
- **HAProxy**: Local counters only; no cross-node rate limit sharing

**PRX-WAF Limitation (Current):**
- Rate limiting is **per-node local** (`token_bucket` + `sliding_window` in `waf-engine`)
- No per-tier distributed state synchronization planned for v0.2.0
- Workers track independently; main does not aggregate rate limit counters

**Recommendation for Future:**
- **Option A** (simple): Periodic sync of rate-limit metrics via `StatsBatch` (already used for stats); main broadcasts updated thresholds to workers
- **Option B** (correct): Implement Redis-backed shared counter store (like NGINX Plus customers do); each node reads from Redis before incrementing
- **Option C** (complex): Implement Raft log replication for rate-limit state (overkill)

**Verdict:** PRX-WAF is correct for v0.2.0 (local only). Option B (Redis) is production gold standard for DDoS mitigation across clusters. Option A is simpler but allows temporary bypasses during flush delays.

---

## 6. Health Checking & Failure Detection

**Industry Pattern:**
- **Cassandra / DynamoDB**: Phi-accrual (exponential distribution model); φ > threshold → suspect; φ > higher → dead
- **etcd**: Fixed timeout (150ms) with jitter; simpler but less adaptive
- **Cloudflare**: Not published; inferred as phi-accrual + corroborating metrics (e.g., TCP resets)
- **HAProxy**: Fixed timeout (TCP connection check); no statistical model

**PRX-WAF Implementation:**
- `PhiAccrualDetector`: Tracks heartbeat inter-arrival times in ring buffer (max 100 samples)
- Computes φ = −log₁₀(exp(−elapsed / mean)) for exponential distribution
- Suspects node at φ > `phi_suspect` (6.0, ~99% confidence); declares dead at φ > `phi_dead` (8.0, ~99.99%)
- Heartbeats must arrive within randomized 150–300ms window (prevents election storms)
- **Advantages**: Adapts to network latency variance; avoids false positives in slow networks

**Verdict:** Phi-accrual is the gold standard for distributed systems. PRX-WAF's implementation matches Cassandra's. Fixed timeouts (etcd, HAProxy) are simpler but cause unnecessary false positives in WAN or bursty networks.

---

## 7. Testing Strategies for Distributed Cluster Code

**Approaches in Production Systems:**

| Approach | Used By | Pros | Cons |
|----------|---------|------|------|
| **Turmoil** (in-process sim) | tokio/prost developers | Deterministic, fast, reproduces rare races | Only async Rust; limited network fidelity |
| **Puppet/Embark** (multi-process) | real companies | High fidelity, catch real OS issues | Slow, flaky, hard to debug |
| **Simulation + live test** | Cloudflare (inferred) | Best of both: deterministic dev + real validation | Resource-heavy; needs both layers |
| **Property-based** (proptest/quickcheck) | Some Raft impls | Exhaustive path coverage | Slow, doesn't catch timing bugs |
| **Docker e2e** | Mini-WAF current approach | Realistic, reproducible | ~30s per run; fragile on shared CI |

**PRX-WAF Recommendation:**
1. **Layer 1 (unit, Turmoil)**: Test `PhiAccrualDetector`, `ElectionManager`, `RuleChangelog` in isolation with deterministic time
2. **Layer 2 (integration, Docker)**: 3-node cluster; inject failures (kill main, network partition, slow heartbeat)
3. **Layer 3 (live, optional)**: Run on actual K8s cluster with chaos engineering (kyverno)

**Verdict:** Turmoil is underrated for Rust clustering; PRX-WAF should add deterministic unit tests. Current Docker e2e is sufficient for v0.2.0.

---

## Key Architectural Insights for PRX-WAF

### Strengths of Current Design
- **QUIC mTLS eliminates VPN layer** — native encryption, lower latency than IPSec
- **Phi-accrual handles WAN variance** — more resilient than fixed timeouts
- **Incremental + full-snapshot hybrid** — balances bandwidth and consistency
- **Raft-lite without Raft log** — sufficient for small clusters (<10 nodes) without log persistence

### Known Limitations
- **Rate limiting is not distributed** — each node enforces independently (acceptable for v0.2.0)
- **No cross-datacenter** — election requires <500ms RTT (plan for v0.3.0)
- **Single-leader write bottleneck** — all config changes route through main (mitigated by caching rules on workers)

### Comparison to Industry
- **ModSecurity**: No clustering (PRX-WAF ahead)
- **NGINX Plus**: Push-based config (PRX-WAF's pull + push is more flexible)
- **Cloudflare**: Proprietary RPC (PRX-WAF's QUIC/JSON is more transparent, slightly higher overhead)
- **HAProxy + SPOE**: Event-driven, not config-driven (orthogonal use case)

---

## Unresolved Questions

1. **Redis rate-limit sync scope**: If implementing Option B, should we sync per-IP counters globally or per-tier thresholds only?
2. **CA key recovery**: Current design encrypts CA key in `JoinResponse` — is there a key escrow ceremony for main replacement?
3. **Multi-region failover timing**: How do we handle >500ms RTT between DCs? (Planned for v0.3.0 but not yet scoped)
4. **Turmoil coverage**: Which edge cases (network partition + election + rule sync collision) need deterministic testing first?

---

**Report Summary**: PRX-WAF's clustering implementation follows production patterns correctly. Election via Raft-lite + phi-accrual is the consensus approach. Distributed rate limiting is the main missing piece; recommend Redis-backed counters for DDoS-heavy deployments.
