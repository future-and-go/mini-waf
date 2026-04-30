# Access Lists — Operator Guide (FR-008)

> **Source of truth:** `rules/access-lists.yaml`
> **Schema version:** 1
> **Hot-reload:** yes — file save triggers atomic swap (~250 ms debounce)

---

## Overview

The access-list subsystem is the **Phase-0 gate** — it runs before every other WAF check. A request that hits a deny rule at this stage never reaches rule evaluation, risk scoring, or rate limiting. A request with a `full_bypass` whitelist hit skips all downstream phases entirely.

Three checks run in fixed order:

```
Host gate → IP blacklist → IP whitelist → Continue (no match)
```

All gates are **off by default**. An empty `rules/access-lists.yaml` (the shipped default) passes every request through to the rest of the WAF unchanged. Gates activate only when you populate the relevant list.

---

## File Location

```
rules/access-lists.yaml
```

The path is resolved relative to the WAF working directory and is currently hardcoded — for a containerized deploy, bind-mount the host file onto `<workdir>/rules/access-lists.yaml`. A configurable override key is tracked as a follow-up.

The file is watched with `notify` (inotify on Linux, FSEvents on macOS, ReadDirectoryChanges on Windows). Editor "rename then write" workflows (vim, most IDEs) are supported because the watcher observes the parent directory, not the inode.

Reload can also be triggered manually with **SIGHUP**:

```bash
kill -HUP $(pgrep prx-waf)
```

---

## Schema Reference

```yaml
version: 1              # Required. Only version 1 is supported; bump = breaking change.
dry_run: false          # Optional. true = log decisions but never actually block.

ip_whitelist: []        # List of IPv4/IPv6 CIDRs or bare IPs.
ip_blacklist: []        # List of IPv4/IPv6 CIDRs or bare IPs.

host_whitelist:         # Per-tier FQDN allowlist. Empty list = gate disabled for that tier.
  critical:  []
  high:      []
  medium:    []
  catch_all: []

tier_whitelist_mode:    # Per-tier whitelist short-circuit behaviour.
  critical:  blacklist_only   # default
  high:      blacklist_only
  medium:    full_bypass
  catch_all: full_bypass
```

### Field Details

| Field | Type | Default | Notes |
|---|---|---|---|
| `version` | integer | `0` (invalid) | Must be `1`. Missing field causes rejection. |
| `dry_run` | bool | `false` | Audit-only mode; see below. |
| `ip_whitelist` | list\<string\> | `[]` | CIDRs/IPs to trust. |
| `ip_blacklist` | list\<string\> | `[]` | CIDRs/IPs to block. |
| `host_whitelist` | map\<tier, list\<string\>\> | `{}` | Per-tier FQDN allowlist. |
| `tier_whitelist_mode` | map\<tier, mode\> | `{}` | `full_bypass` or `blacklist_only`. Missing tier defaults to `blacklist_only`. |

---

## Whitelist Modes

### `blacklist_only` (default)

A whitelist hit does **not** skip downstream checks. The request continues through rule evaluation and risk scoring as normal. Only the IP blacklist check is effectively bypassed (because blacklist runs before whitelist and already passed).

Use this for internal networks you trust enough not to block, but still want to audit.

### `full_bypass`

A whitelist hit **skips all downstream WAF phases**. The request is forwarded to the upstream with no further inspection. This is the fast path for known-clean traffic (internal load balancers, health checkers).

Use with caution: a misconfigured CIDR silently bypasses the entire WAF.

**Default assignment in shipped config:**

| Tier | Default mode |
|---|---|
| `critical` | `blacklist_only` |
| `high` | `blacklist_only` |
| `medium` | `full_bypass` |
| `catch_all` | `full_bypass` |

---

## CIDR and IP Format

Both IPv4 and IPv6 are accepted, and you can mix them freely in the same list.

```yaml
ip_blacklist:
  - 203.0.113.0/24       # IPv4 CIDR
  - 198.51.100.42        # bare IPv4 (treated as /32)
  - 2001:db8::/32        # IPv6 CIDR
  - 2001:db8::1          # bare IPv6 (treated as /128)
```

Longest-prefix match is used: a `/32` entry overrides a `/8` entry for the same IP. There is no "weight" — the first matching rule wins in blacklist order; the blacklist always wins over the whitelist regardless of entry order (blacklist is evaluated first in the chain).

**Hard cap:** 500 000 combined entries across `ip_whitelist` + `ip_blacklist`. The parser rejects files that exceed this. **Soft cap:** 50 000 entries triggers a `WARN` log on load.

---

## Host (FQDN) Format

```yaml
host_whitelist:
  critical:
    - api.example.com
    - secure.example.com
```

Rules:
- Lowercase only (no `API.example.com`).
- No port suffix (no `api.example.com:443`).
- No leading/trailing whitespace.
- Exact match only — wildcards (`*.example.com`) are **not** supported in v1.
- Empty list for a tier = host gate disabled for that tier (any host allowed).

The `Host` request header is lowercased before comparison so case differences in the upstream request are handled transparently.

---

## Hot-Reload Mechanics

1. File save detected by OS watcher (parent-dir watch, non-recursive).
2. 250 ms debounce window drains editor burst events (truncate + write + chmod).
3. File is read, parsed, and validated.
4. On success: `ArcSwap::store()` atomically replaces the live snapshot. In-flight requests using the old snapshot complete normally; new requests see the new snapshot.
5. On failure: **prior snapshot is retained**. A `WARN` log line is emitted with the parse error. The WAF continues operating with the last known-good config.

```
[WARN] access-lists reload failed; keeping previous  path=rules/access-lists.yaml  error=...
[INFO] access-lists reloaded                          path=rules/access-lists.yaml
```

---

## Audit Logging

Block and bypass decisions emit structured log fields. `Continue` is silent on the hot path.

| Field | Values | Emitted on | Notes |
|---|---|---|---|
| message | `access: whitelist bypass` / `access: block` / `access: block (dry-run) — treating as continue` | bypass / block / dry-run | `tracing` event message |
| `reason` | `host_gate`, `ip_blacklist` | block, dry-run block | Which gate fired |
| `matched` | client IP string or `Host` header | bypass, block, dry-run block | What triggered the decision |
| `host` | request `Host` header | bypass, block, dry-run block | Host as observed by the gate |
| `tier` | `Critical`, `High`, `Medium`, `CatchAll` | bypass, block, dry-run block | Tier the request resolved to |
| `dry_run` | `true` | dry-run block only | Marker that the block was suppressed |
| `status` | `403` | block, dry-run block | HTTP status that would be returned (even in dry-run mode) |

In `dry_run: true` mode the gateway logs a `WARN` (`access: block (dry-run) — treating as continue`) and forwards the request — no traffic is actually blocked.

---

## Decision Flow

```
Request arrives
      │
      ▼
┌─────────────────────────────────────┐
│  Host gate (per-tier FQDN check)    │
│  Enabled only if host_whitelist     │
│  for this tier is non-empty.        │
│  Host NOT in list → Block(HostGate) │
└────────────────┬────────────────────┘
                 │ pass
                 ▼
┌─────────────────────────────────────┐
│  IP blacklist (CIDR trie lookup)    │
│  IP matches → Block(IpBlacklist)    │
└────────────────┬────────────────────┘
                 │ pass
                 ▼
┌─────────────────────────────────────┐
│  IP whitelist (CIDR trie lookup)    │
│  IP matches + FullBypass → BypassAll│
│  IP matches + BlacklistOnly → Cont. │
└────────────────┬────────────────────┘
                 │ no match
                 ▼
             Continue
        (downstream WAF phases)
```

**Blacklist beats whitelist.** If the same IP appears in both lists, the blacklist check fires first and the request is blocked regardless of the whitelist entry.

---

## Operator Playbook

### Block a known-bad IP

```yaml
ip_blacklist:
  - 198.51.100.99        # specific attacker
  - 192.0.2.0/24        # entire hostile /24
```

Save the file. Reload happens within ~250 ms. Verify:

```bash
tail -f logs/waf.log | grep '"reason":"ip_blacklist"'
```

### Trust an internal admin IP (full bypass)

```yaml
ip_whitelist:
  - 10.10.0.0/16        # internal admin network

tier_whitelist_mode:
  critical: full_bypass  # admins skip WAF on critical tier too
```

### Lock a Critical-tier service to known frontends only

```yaml
host_whitelist:
  critical:
    - api.internal.example.com
    - admin.internal.example.com
```

Any request to a `Critical`-tier upstream with a different `Host` header receives a 403 at Phase 0.

### Test a new blocklist non-destructively

```yaml
dry_run: true
ip_blacklist:
  - 203.0.113.0/24
```

The WAF logs `reason=ip_blacklist dry_run=true` but forwards every request normally. Review logs, then set `dry_run: false` to activate.

---

## Troubleshooting

**Reload not taking effect:**
```bash
tail -f logs/waf.log | grep 'access-list'
```
Look for `WARN access-lists reload failed` — the error message contains the YAML line/column of the parse failure.

**Unexpected blocks:**
Check the `reason` and `matched` fields in the request log to identify which gate fired and which entry matched.

**Tier not found:**
If the `Tier` field in a request log is unexpected, verify the tier-routing config in `configs/gateway.toml`. The access-list evaluator uses whatever tier the gateway assigned.

**File parse rejected:**
- Confirm `version: 1` is present.
- Hosts must be lowercase with no port (`:443` suffix breaks validation).
- CIDRs must be valid (`10.0.0.0/33` is rejected; max prefix is `/32` for v4, `/128` for v6).
- Total IP entries must not exceed 500 000.

---

## Production Caveats

- **Soft cap 50 000 entries** — a `WARN` is logged on load. Performance degrades gracefully (trie lookup is O(prefix-length), not O(n)).
- **Hard cap 500 000 entries** — the parser rejects the file. The previous snapshot is retained.
- **Empty file** — parsed as all-gates-disabled (same as the shipped default). The WAF continues normally.
- **Missing file at boot** — WAF starts with an empty (all-gates-disabled) snapshot and logs an `INFO`. A subsequent file creation triggers a reload automatically.

---

## Migration from FR-008 v1 (threat_intel module)

The `threat_intel` module (Tor exit-node fetcher, ASN auto-classifier, Ed25519 signed blocklists) was **deferred to FR-042** and is not present in this release. Operators who need Tor exit-node blocking can:

1. Download the Tor exit-node list periodically (e.g. from `https://check.torproject.org/torbulkexitlist`).
2. Concatenate the IPs into `ip_blacklist:` in `rules/access-lists.yaml`.
3. Automate the refresh with a cron job that writes the file — the hot-reload watcher picks up the change within 250 ms.

ASN-based blocking and cryptographically signed blocklist distribution are tracked in FR-042.
