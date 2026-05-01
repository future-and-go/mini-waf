# Request Pipeline

Detailed walkthrough of the per-request processing path: tier classification, the Phase-0 access gate, and the 16-phase WAF rule pipeline. Extracted from [system-architecture.md](./system-architecture.md) for focus.

## Pre-Phase: Tier Classification (FR-002)

```
Tier Classification:
├─ RequestCtx populated in gateway::ctx_builder
├─ TierPolicyRegistry::classify(&request_parts) runs
├─ Returns (Tier, Arc<TierPolicy>) from current snapshot
├─ ctx.tier and ctx.tier_policy set before Phase 1
└─ All downstream phases read tier for policy-aware decisions
   (e.g., rate-limit threshold, block action per tier)
```

**Default**: If no tier registry configured at boot, uses `Tier::CatchAll` + permissive policy (fallback mode).

**Wired in**: `prx-waf/src/main.rs::try_init_tier_registry()` loads config, spawns `TierConfigWatcher` for hot-reload, injects registry into gateway.

### Tier Flow Diagram

```mermaid
flowchart LR
    A([HTTP Request]) --> B[ctx_builder]
    B --> C{TierPolicyRegistry\n.classify}
    C -->|"(Tier, Arc&lt;TierPolicy&gt;)"| D[RequestCtx\ntier + tier_policy]
    D --> E[WAF Checks\nPhases 1–16]
    E -->|Allow| F([Upstream])
    E -->|Block| G([403 / 429])

    subgraph hot-reload ["Hot-Reload (background)"]
        H[configs/default.toml\nwatcher] -->|ArcSwap.store| C
    end

    subgraph consumers ["Downstream consumers"]
        D -.->|ddos_threshold_rps| FR005[FR-005 DDoS]
        D -.->|risk_thresholds| FR006[FR-006 Challenge]
        D -.->|cache_policy| FR009[FR-009 Cache]
    end
```

See [tiered-protection.md](./tiered-protection.md) for the consumer guide.

---

## Phase-0: Access Gate (FR-008)

Phase-0 gate runs **before** the 16-phase rule pipeline: three stages in order: **(1)** Host gate (per-tier FQDN whitelist, deny-by-default if non-empty) → **(2)** IP blacklist (Patricia trie, longest-prefix v4/v6) → **(3)** IP whitelist (Patricia trie, per-tier `full_bypass` vs `blacklist_only` dispatch).

**Rationale**: Blacklist before whitelist prevents leaked whitelist IPs from bypassing explicit blocks.

**Configuration**: `rules/access-lists.yaml` (YAML v1). Hot-reload via `notify` (250ms debounce, SIGHUP forces immediate). Atomic `ArcSwap` swaps; on parse error, retains previous snapshot with `tracing::warn!`. Soft-warn ≥50k entries, hard-reject ≥500k.

**Audit Fields**: Every request stamped with `access_decision` (continue|bypass_all|host_gate|ip_blacklist), `access_reason`, `access_match` (host/IP or empty), `access_dry_run` (bool).

See [Access Lists Operator Guide](./access-lists.md) for full schema, worked examples, dry-run mode, troubleshooting.

---

## Phases 1-4: IP & URL Filtering

```
Phase 1: IP Allowlist (CIDR)
├─ Check if client IP in allow_ips table
├─ If match → allow this phase, continue to Phase 2
└─ If no match → continue (allowlist is permissive)

Phase 2: IP Blocklist (CIDR)
├─ Check if client IP in block_ips table
├─ If match → BLOCK (decision made)
└─ If no match → continue to Phase 3

Phase 3: URL Allowlist (regex + literal)
├─ Check if request path in allow_urls table
├─ If match → bypass all downstream phases, allow
└─ If no match → continue to Phase 4

Phase 4: URL Blocklist (regex + literal)
├─ Check if request path in block_urls table
├─ If match → BLOCK
└─ If no match → continue to Phase 5
```

## Phases 5-7: Rate Limiting & Behavior Analysis

```
Phase 5: CC/DDoS Rate Limiting
├─ Per-IP sliding-window counter
├─ Increment on each request
├─ If counter > threshold → BLOCK (or challenge)
└─ else → continue to Phase 6

Phase 6: Scanner Detection
├─ Check User-Agent against scanner fingerprints (Nmap, Nikto, etc.)
├─ Check request patterns (unusual paths, SQL comments in URI, etc.)
├─ If scanner detected → log & continue (or block, configurable)
└─ else → continue to Phase 7

Phase 7: Bot Detection
├─ Check User-Agent against known bot list (headless browsers, etc.)
├─ Check for browser fingerprinting anomalies
├─ If malicious bot → BLOCK (or challenge)
└─ else → continue to Phase 8
```

## Phases 8-11: Payload Attack Detection

```
Phase 8: SQL Injection (SQLi)
├─ Parse request body + query string (up to 256KB JSON)
├─ Run libinjectionrs detect_sqli fingerprint engine
├─ Check 19 modular regex patterns (SQLI-001..019: classic, blind, error-based)
├─ Apply SqliScanConfig (header/JSON toggles, denylist/allowlist, 4KB header cap)
├─ If SQL injection payload detected → BLOCK
└─ else → continue to Phase 9

Phase 9: Cross-Site Scripting (XSS)
├─ Parse request body + headers
├─ Run libinjectionrs detect_xss fingerprint engine
├─ Check compiled XSS regex patterns (script tags, event handlers, etc.)
├─ If JavaScript/HTML injection detected → BLOCK
└─ else → continue to Phase 10

Phase 10: Remote Code Execution (RCE)
├─ Check for command injection patterns (shell metacharacters, etc.)
├─ Check for expression language injection (${}, #{}, etc.)
├─ Check for template injection (Jinja2, Freemarker, etc.)
├─ If RCE pattern detected → BLOCK
└─ else → continue to Phase 11

Phase 11: Directory Traversal
├─ Normalize path (decode, resolve ../)
├─ Check for attempts to escape web root
├─ Check for Windows alternate data streams (::$DATA)
├─ If traversal detected → BLOCK
└─ else → continue to Phase 12
```

## Phases 12-16: Advanced & Custom Rules

```
Phase 12: Custom Rules (User-Defined)
├─ Load from custom_rules table (Rhai scripts + JSON DSL)
├─ Execute Rhai scripts in sandboxed environment
├─ Evaluate JSON DSL conditions
├─ If rule matches → action (block/log/challenge)
└─ else → continue to Phase 13

Phase 13: OWASP CRS (Core Rule Set)
├─ 24 pre-compiled rule patterns
├─ Categories: XSS, SQLi, RCE, RFI, LFI, protocol violations, etc.
├─ If CRS rule matches → action (block/log)
└─ else → continue to Phase 14

Phase 14: Sensitive Data Leakage
├─ Aho-Corasick multi-pattern matching
├─ Patterns: credit card numbers, SSN, API keys, passwords, etc.
├─ If sensitive data in request → log & continue (or block)
└─ else → continue to Phase 15

Phase 15: Anti-Hotlink Protection
├─ Check Referer header
├─ If Referer not in allowed list → BLOCK (return 403)
└─ else → continue to Phase 16

Phase 16: CrowdSec Integration
├─ Query CrowdSec bouncer for active decisions on client IP
├─ If IP has active decision (ban, captcha, etc.) → apply action
├─ If IP is in local cache → use cached decision
├─ Push attack logs to CrowdSec Log Pusher
└─ FINAL DECISION: Allow / Block / Challenge
```

## Post-Decision

```
After Phase 16:
├─ Decision = Allow
│  ├─ Route to backend (vhost → load balancer → upstream)
│  ├─ Receive response from backend
│  ├─ Store in response cache (if eligible)
│  └─ Return response to client
│
├─ Decision = Block
│  ├─ Return HTTP 403 Forbidden
│  ├─ Log to security_events + attack_logs
│  ├─ Send notifications (email, webhook, etc.)
│  └─ Increment blocked_requests counter
│
└─ Decision = Challenge
   ├─ Return HTTP 429 Too Many Requests (or CAPTCHA page)
   ├─ Log to security_events
   └─ Wait for client to solve challenge before allowing
```

---

## Related Docs

- [system-architecture.md](./system-architecture.md) — Topology, components, storage, cluster.
- [tiered-protection.md](./tiered-protection.md) — Tier classifier consumer guide.
- [access-lists.md](./access-lists.md) — Phase-0 access gate operator guide.
- [custom-rules-syntax.md](./custom-rules-syntax.md) — Phase-12 custom rule schema.
