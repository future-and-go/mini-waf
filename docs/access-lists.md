# Access Lists (FR-008) — Operator Guide

Phase-0 access-control gate: per-tier IP whitelist, IP blacklist, per-tier Host (FQDN) whitelist. Hot-reloaded from `rules/access-lists.yaml` via the same `ArcSwap` pattern as FR-002.

> **Schema sync:** YAML examples in this doc and `rules/access-lists.yaml` are byte-identical for the schema portion. Update both on any schema change.

---

## 1. Overview

Access lists run **before** Phase-1 of the WAF pipeline (the 16-phase rule chain). The gate has three stages, evaluated in fixed order:

```
Host gate  →  IP blacklist  →  IP whitelist
```

Each stage may short-circuit:

| Stage | Hit | Miss |
|---|---|---|
| Host gate (per-tier, deny-by-default when list non-empty) | continue | **403 Block** (`reason: host_gate`) |
| IP blacklist | **403 Block** (`reason: ip_blacklist`) | continue |
| IP whitelist | dispatch on per-tier `whitelist_mode` (see §4) | continue |

**No match** at any stage → request continues to Phase-1 unchanged.

**Why this order?** Blacklist runs **before** whitelist so a leaked / shared whitelist IP cannot bypass an explicit block.

---

## 2. YAML Schema

```yaml
version: 1                # only v1 supported; mismatch = parse error
dry_run: false            # if true, log "would-block" but do not block

ip_whitelist:             # CIDR or bare IP, v4 + v6 freely mixed
  - 10.0.0.0/8
  - 192.168.1.5
  - 2001:db8::/32

ip_blacklist:
  - 203.0.113.0/24
  - 198.51.100.42

host_whitelist:           # per-tier FQDN allowlist (lowercase, no port)
  critical:
    - api.example.com
    - secure.example.com
  high:
    - api.example.com
  medium:    []           # empty = gate OFF for this tier
  catch_all: []

tier_whitelist_mode:      # per-tier dispatch on whitelist hit
  critical:  blacklist_only
  high:      blacklist_only
  medium:    full_bypass
  catch_all: full_bypass
```

### Field reference

| Field | Type | Default | Notes |
|---|---|---|---|
| `version` | `u32` | required | `1` only — bumped on breaking change |
| `dry_run` | `bool` | `false` | log-only mode (D6) |
| `ip_whitelist` | `[CIDR \| IP]` | `[]` | empty = gate OFF |
| `ip_blacklist` | `[CIDR \| IP]` | `[]` | empty = gate OFF |
| `host_whitelist.<tier>` | `[FQDN]` | `[]` | empty = gate OFF for that tier |
| `tier_whitelist_mode.<tier>` | `full_bypass \| blacklist_only` | `blacklist_only` | safer default — typo must not silently bypass rules |

**Caps:** soft-warn at 50 000 entries (whitelist + blacklist combined); hard-reject above 500 000 (parse error, previous snapshot retained).

---

## 3. Decision Order — Worked Example

Given `client_ip = 10.1.2.3`, `host = evil.com`, `tier = Critical`, against:

```yaml
host_whitelist:
  critical: [api.example.com]
ip_blacklist:   [203.0.113.0/24]
ip_whitelist:   [10.0.0.0/8]
```

1. Host gate: `evil.com` not in `critical` allowlist (which is non-empty) → **Block, reason=host_gate**.

Even though the IP would have hit the whitelist, the host gate runs first.

---

## 4. Per-Tier Whitelist Mode (Strategy)

| Mode | Effect on whitelist hit |
|---|---|
| `full_bypass` | Skip every downstream WAF phase. Fast path for fully-trusted internal traffic. |
| `blacklist_only` *(default)* | Continue to rules. Defense-in-depth: the whitelist suppresses the host-gate / blacklist deny but rules still run. |

**Why `blacklist_only` is the default:** A typo in YAML must not silently bypass the WAF. Operators must explicitly opt into `full_bypass` for each tier.

---

## 5. Hot-Reload

- File watcher (`notify`) on `rules/access-lists.yaml`. ~250 ms debounce window covers editor save bursts.
- On change: read → parse → validate → build → atomic `ArcSwap::store`. Old snapshot kept alive until in-flight readers drop their `Arc`.
- **On error:** previous snapshot retained; `tracing::warn!` with file path and error chain. **The gateway never crashes from a bad config.**
- Per-request cost on the hot path: one relaxed atomic load. No lock contention.
- A SIGHUP forces an immediate reload (skips debounce).

**Verifying reload took effect:**

```bash
# 1. Edit rules/access-lists.yaml.
# 2. Tail the gateway log for one of these structured events:
#    INFO  access-list reload ok       — new snapshot live
#    WARN  access-list reload failed   — kept previous snapshot, see error
```

---

## 6. Dry-Run Mode

Set `dry_run: true` to validate a configuration in production traffic without enforcing it.

- Decisions are computed normally.
- A would-be `Block` becomes `Continue` for the request.
- A `WARN` log entry is emitted with the same `access_decision` / `access_reason` / `access_match` fields as a real block.

Use this when introducing a host-gate to an existing service: enable dry-run for one rollout window, sample the WARN logs for false positives, then flip `dry_run: false`.

---

## 7. Operational Caveats

### 7.1 Client-IP source (XFF / `client_ip`)

Until FR-007 lands a validated `ctx.client_ip` (XFF-aware with trusted-proxy CIDRs), the access lists evaluate against **the TCP peer IP**. Behind a reverse proxy that does not preserve the source IP, every request appears to come from the proxy.

**Workaround:** terminate the reverse proxy at a layer that exposes peer IP (PROXY protocol or HTTP/3 source IP) until FR-007 ships.

### 7.2 Host header normalization

The Host gate matches against the request `Host` header **after**:

- lowercasing,
- stripping any `:port` suffix.

`API.example.com:8080` and `api.example.com` are treated identically. The YAML parser **rejects** uppercase letters or `:port` in `host_whitelist` entries with a clear error — this prevents silent misses at lookup time.

### 7.3 Empty-list semantics (D4)

A missing or empty list disables the corresponding gate. There is no "deny-all by default" toggle — that would lock out prod traffic on first deploy.

### 7.4 Size caps

| Cap | Action |
|---|---|
| > 50 000 combined entries | `tracing::warn!` on every reload |
| > 500 000 combined entries | parse error, previous snapshot retained |

If you legitimately need >500 k entries, escalate — that scale points to a feed-driven design (FR-042 reputation refresh) rather than a static YAML file.

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| All prod traffic returns `403 host_gate` | `host_whitelist.<tier>` populated but request host not in list | Verify `Host` header (lowercased, no port). Add the host or empty the list to disable the gate. |
| Edit to `access-lists.yaml` not taking effect | Parse error → previous snapshot retained | `grep "access-list reload" /var/log/prx-waf/gateway.log` — read the WARN line. |
| Blacklisted IP still hitting backend | Phase-0 gate not wired into proxy | `grep -n access_phase crates/gateway/src/proxy.rs` — pipeline must register the access phase before Phase-1. |
| Whitelist hit but rules still running | Tier mode is `blacklist_only` (default) | Set `tier_whitelist_mode.<tier>: full_bypass` for full bypass. |
| Block with `reason: ip_blacklist` despite whitelist entry | Working as designed — blacklist runs before whitelist | Remove the IP from blacklist or scope the blacklist CIDR more tightly. |
| `parse error: ip_blacklist[N] invalid CIDR/IP` | Bad CIDR syntax (e.g. `10.0.0.0/33`) | Fix entry; previous snapshot stays live until the file parses. |

---

## 9. Audit Log Fields

Every access-list decision is stamped on the request audit record:

| Field | Values |
|---|---|
| `access_decision` | `continue` \| `bypass_all` \| `host_gate` \| `ip_blacklist` |
| `access_reason` | same enum as `access_decision` (mirrors `BlockReason::as_str`) |
| `access_match` | the matched host (host gate) or IP (blacklist / whitelist), or `""` for `continue` |
| `access_dry_run` | `true` if the snapshot was loaded with `dry_run: true` |

Filter the log stream on `access_decision != continue` to see every block / bypass.

---

## 10. Schema Versioning

`version: 1` is the only supported value. A future breaking change will:

1. Bump the constant in `crates/waf-engine/src/access/config.rs`.
2. Document the migration in this doc + `CHANGELOG.md`.
3. The parser will keep accepting v1 for at least one minor release with a `tracing::warn!` deprecation.

---

## 11. Related

- FR-002 tiered protection: [`tiered-protection.md`](./tiered-protection.md) — the `Tier` enum keys used in `host_whitelist` and `tier_whitelist_mode`.
- Brainstorm (locked decisions D1–D11): `plans/reports/brainstorm-260429-2222-fr-008-whitelist-blacklist.md`.
- Implementation plan: `plans/260429-2237-fr-008-whitelist-blacklist/plan.md`.
- Follow-ups: **FR-042** (Tor exit list), **FR-007** (XFF-aware `client_ip`).
