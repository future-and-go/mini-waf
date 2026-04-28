# Code Review — Merge b73c3de (PR #15 "Feature/e2e test")

**Scope:** 37 files, +2375/-109. WAF detection logic, gateway request_filter, cluster transport (rustls), prx-waf bootstrap, e2e harness (bash + GH Actions), advisory ignore lists, build.rs.

**Overall verdict:** Mostly solid. Several real correctness wins (WAF now actually inspects bodyless requests, host header excluded from `field: all`, scripted-client UA gated). Two genuine production-impact issues, several Important findings, plus bash/CI hygiene Minor items. Nothing in the diff weakens auth, opens injection, or leaks secrets to logs. The advisory ignore list grows aggressively (24 new entries) — risk-managed but worth acknowledging.

---

## Critical

### C1. `e2e_finalize` masks failure when `set -e` interacts with `||` chain
**Files:** `tests/e2e/run-rules-engine.sh:30`, `run-api.sh:23,38`, `run-cluster.sh`, `run-gateway.sh`.
Pattern used at every early-exit:
```
e2e_finalize || true
exit 1
```
`e2e_finalize` ends with `[[ "$E2E_FAIL" -gt 0 ]] && return 1 || return 0`. Under `set -e`, `&& return 1 || return 0` returns the last expression's status (0). That's actually fine here — but the surrounding `e2e_finalize || true` masks the artefact-write failure path entirely. More importantly, **`exec > >(tee -a "$LOG_FILE") 2>&1`** in `run-cluster.sh:38` redirects stdout to a subshell; if the script then early-exits before `wait`-ing the tee process, partial logs get lost in CI. Add `wait` in a trap or accept the risk explicitly. Not a bug per se but is the kind of hidden state you flagged in earlier comments.

**Fix:** Replace `e2e_finalize || true; exit 1` with `e2e_finalize; exit 1` (function already returns the right code). For the cluster script, ensure tee subshell is reaped on exit.

### C2. Advisory ignore list is now load-bearing
**Files:** `deny.toml`, `.cargo/audit.toml`.
24 advisories now silenced, including 12 wasmtime CVEs, two rustls-webpki cert-validation issues, rsa Marvin sidechannel, thin-vec UAF, rand soundness. Each has a plausible justification, but:
- `RUSTSEC-2026-0098/0104` (rustls-webpki name-constraint) — the comment says "irrelevant to cluster mTLS". True for the cluster transport, but rustls-webpki is also reachable from any HTTPS client (CrowdSec sync, GeoIP updater). Verify no untrusted-CA TLS path exists before considering this fully mitigated.
- `RUSTSEC-2026-0099` (thin-vec via rhai) — comment says "rhai scripts are admin-uploaded and sandboxed". UAF on panic during drop is reachable from any rhai value-drop with a panicking destructor. If admin-supplied scripts can be defined via API (audit log shows this is possible per `custom-rules.list` test), the trust boundary is thinner than the comment implies.
- `severity_threshold = "low"` in `audit.toml` — fine, but combined with 24 ignores it means a future medium advisory will still pass CI iff it's added to ignore. Add a CI check that fails if `ignore = []` length grows without an accompanying review-by date update.

Not a code defect but a governance one — flagging because Critical-tier of "supply chain weakening".

---

## Important

### I1. `request_filter` resolves host AGAIN even though `upstream_peer` already does
**File:** `crates/gateway/src/proxy.rs:191-208`.
The fix is correct: WAF must run before upstream_peer to catch GETs/UA-only attacks. But now `router.resolve(host)` runs in BOTH `request_filter` and `upstream_peer` (the latter fallthrough still calls it). On a request that doesn't get blocked, we resolve+build_request_ctx twice on the hot path. `build_request_ctx` clones headers (`HashMap<String,String>`) — measurable per-request allocation overhead.

**Fix:** Move the resolution into `request_filter` unconditionally and have `upstream_peer` only consume `ctx.host_config` / `ctx.upstream_addr`. If `ctx.host_config` is `None` after request_filter, that's the "no matching host" case → return 502 from upstream_peer or short-circuit. The current `if ctx.host_config.is_none()` guard reads as "belt-and-braces" but actually doubles the hot-path allocation.

### I2. `is_routing_header` skip-list is reasonable, but `accept` skip is dubious
**File:** `crates/waf-engine/src/checks/owasp.rs:115-130`.
Skipping `host`, `:authority`, `:method`, etc. is correct — the comment cites OWASP CRS precedent. However:
- `accept` value `*/*` triggers some regexes — listed as the rationale. `*/*` is fine, but attackers DO put attack payloads in `Accept: text/html,<script>...`. Excluding `accept` entirely is over-broad. Either narrow to "skip `accept` only when value matches `^[*\w/+,;= .-]+$`", or don't skip it at all (most CRS rules don't fire on the typical Accept value).
- `x-forwarded-host` and `x-real-ip` are attacker-controlled in many deployments (anyone reaching the WAF can set them unless the upstream LB strips). Calling them "not user-controlled payload" is incorrect for a public-facing WAF. SSRF-style payloads in `X-Forwarded-Host` should still be inspected.

**Fix:** Reduce skip list to `host`, `:authority`, `:method`, `:path`, `:scheme`, `accept-encoding`, `accept-language`, `connection`, `content-length`. Inspect `x-forwarded-*` and `accept`.

### I3. `CompiledRule` URL-decode loop allocates `String` per header per request
**File:** `crates/waf-engine/src/checks/owasp.rs:163-249`.
Every rule with `field: "all"` now runs `url_decode + url_decode_recursive` over path, query, body, and every non-routing header value, allocating up to 3 Strings per field per rule. With ~hundreds of rules and ~10 headers, you're looking at thousands of `String` allocations per request — direct violation of CLAUDE.md rule #7 "Minimize allocations". The values to decode don't depend on the rule; decode them ONCE per request before the rule loop.

**Fix:** Pre-compute `(raw, decoded, recursive)` triples for path/query/body/headers in `RequestCtx` (or a per-request scratch struct) and pass them into rule evaluation. Keep behaviour unchanged, eliminate N×M allocations. This is the kind of fix to do now while the code is fresh — it'll be much harder once more rules land.

### I4. `tracing::info!` on every WAF rule fire — log spam + side-channel
**File:** `crates/waf-engine/src/checks/owasp.rs:179-194`.
`test_with_decoded` calls `tracing::info!(rule = %self.id, ..., "WAF rule fired on {}: {}", label, raw)` BEFORE returning true. On a noisy production deployment with every Apache scanner on the internet probing, this logs the full decoded attack payload at INFO level, every request. Two issues:
- Volume: turns a 1k-rps WAF into a 1k-log-line/sec firehose at INFO.
- Information disclosure: payload content (which may contain exfil'd cookies, tokens, or path-encoded creds) lands in plain log files. CLAUDE.md says "Sanitize URLs before logging", same principle applies.

**Fix:** Demote to `debug!` or gate behind `if tracing::enabled!(Level::DEBUG)`. Production block-side audit logging should go through the existing `attack_logs` DB path, not the tracing subscriber.

### I5. `cargo audit` step lost the audit-check action's PR comments
**File:** `.github/workflows/sec-audit.yml:38-55`.
Replacing `rustsec/audit-check@v2.0.0` with raw `cargo audit` is fine for forks but means **no inline PR comments when a new advisory lands**. The justification ("Resource not accessible by integration") only applies to PRs from forks; for internal PRs the action did add value. Consider a conditional: use `audit-check` when `github.event.pull_request.head.repo.full_name == github.repository`, else fall back to `cargo audit`.

Also `cargo install --locked cargo-audit` on every run is a 60-90s build per job — pin a binary install via `taiki-e/install-action` for a 5x speedup.

### I6. `prx-waf` rustls provider install — error path silently dropped
**File:** `crates/prx-waf/src/main.rs:280-294`.
```rust
match rustls::crypto::ring::default_provider().install_default() {
    Ok(()) => eprintln!("rustls: installed ring as the process-default CryptoProvider"),
    Err(_) => eprintln!("rustls: another CryptoProvider was already installed (ignored)"),
}
```
The `Err(_)` branch discards the error — fine here because the Err type IS the already-installed provider, not a failure. But the message says "another CryptoProvider was already installed" without verifying it's actually `ring`. If `aws-lc-rs` somehow wins the race (transitive `init` from another crate's `LazyLock`), the cluster's mTLS path will use one provider while the rest of the codebase uses another. The explicit `builder_with_provider(ring)` in `transport/{client,server}.rs:51-56` saves us from inconsistency, but the `eprintln!` is misleading.

**Fix:** Either log the actual installed provider name or strengthen the comment.

### I7. `_record` in `lib.sh` doesn't escape names containing `]`
**File:** `tests/e2e/lib.sh:64-69` and `_xml_escape:251-258`.
`_xml_escape` handles `& < > " '`. It does NOT handle the test name passed to `<testcase classname="..." name="...">` containing newlines or control characters. Test names today are safe but `assert_*` accepts arbitrary strings — a future test passing `"$response"` as a name would break the JUnit XML or worse, allow XML injection via a controlled response body. Add a `_xml_escape "$name"` use everywhere the name is interpolated.

### I8. `render-report.sh` glob/grep parser is fragile under content the JSON keys could include
**File:** `tests/e2e/render-report.sh:46-50, 162-181`.
`read_field` uses `grep -oE "\"$1\":[[:space:]]*[0-9]+"` — this accidentally matches inside the `tests` array's `detail` strings if a test detail contains `"pass": 42` (yes, this can happen — `assert_contains` records `haystack` content into details). Pin to first-N-lines or use a real JSON parser (`jq` is in every CI image). The `awk` test parser at line 165-180 has the same class of bug: `"name": "evil\"} fake"` will desync the parser.

Not directly exploitable (test content is operator-trusted), but in CI rendering it can produce broken HTML.

### I9. `cluster` job in nightly-e2e.yml has no compose-up step
**File:** `.github/workflows/nightly-e2e.yml:262-296` (cluster job).
The job runs `bash tests/e2e/run-cluster.sh` directly with no prior `docker compose up`. The script DOES bring up the cluster itself, but only via `cluster-init` and `up -d node-a node-b node-c`. If `docker-compose.cluster.yml` requires extra build steps that the rules-engine job's `--build` flag handled, this will fail. Verify by running the workflow once on a clean runner (the workflow has a temporary `push: feature/e2e-test` trigger for exactly this — good).

Also the cluster job lacks the `Wait for prx-waf to become healthy` polling step that the other 3 jobs have — `wait_health` inside the script handles it, but failures will only show up after the 120s wait expires.

---

## Minor

### M1. `_json_escape` in `lib.sh:240-248` uses literal tab and newline in pattern substitution
**File:** `tests/e2e/lib.sh:243-246`. Embedded tab/newline characters in source are fragile across editors and `dos2unix` runs. Use `$'\t'` / `$'\n'` or replace with a `printf '%s'` + `sed` pipeline.

### M2. `wait_health` retries every 2s for up to 90/120s with no exponential backoff
**File:** `tests/e2e/lib.sh:117-128`. Fine for CI; not a defect.

### M3. `cluster-override.yml` injects `ADMIN_PASSWORD: admin123` as a literal
**File:** `tests/e2e/cluster-override.yml`. Comments justify it (CI-only). Make sure the file is `chmod 644` and lives outside any image build context that could embed it.

### M4. `e2e.toml` sets `api_rate_limit_rps = 0`
**File:** `tests/e2e/configs/e2e.toml:25`. Disables admin API rate limiting for tests. Document explicitly that this is test-only — a future operator copy-pasting will inherit a DoS-prone config.

### M5. `build.rs` writes placeholder dist on every clean build
**File:** `crates/waf-api/build.rs:30-58`. Acceptable. `#![allow(clippy::expect_used, clippy::print_stdout)]` at file scope is correct given the unwrap rule in CLAUDE.md.

### M6. `SQLI_SET` `#[allow(clippy::expect_used)]` is properly scoped
**File:** `crates/waf-engine/src/checks/sql_injection_patterns.rs:47-50`. Well-justified, follows the pattern.

### M7. `defense_config` mutation on `AppState` after `AppState::new`
**File:** `crates/prx-waf/src/main.rs:1452-1456`. `api_state.cluster_state = cluster_state;` is a public-field assignment that bypasses any future invariants that `AppState::new` might want to enforce. Convert to `with_cluster_state(...)` builder when convenient.

### M8. `host(client_ip)` repeated in WHERE and SELECT
**File:** `crates/waf-storage/src/repo.rs:357-385`. Two SQL changes: (1) wrap `client_ip` with `host()` in the WHERE comparison, (2) project `host(client_ip) AS client_ip` instead of `SELECT *`. Both correct. Consider an index on `host(client_ip)` if attack-log filter-by-IP is hot — current B-tree on the INET column won't be used after the function wrap. Functional index: `CREATE INDEX ON attack_logs ((host(client_ip)))`.

### M9. `proxy.rs:194` `unwrap_or("")` for non-UTF8 host header
**File:** `crates/gateway/src/proxy.rs:198`. A non-UTF8 `Host:` header silently becomes empty string and then resolves to None — fine, request gets dropped via `Ok(false)`. Worth a one-line `tracing::debug!` so this isn't invisible during incident response.

---

## Adversarial findings

- **A1. SQLi regex bypass via Unicode normalization:** `url_decode_recursive` only handles `%xx` percent-encoding. Payloads using HTML entity encoding (`&#x27;` for `'`) reach the body matcher unchanged. libinjection covers most of these but rule-based regex paths don't. Worth checking whether OWASP CRS YAMLs include `'`-style alternatives.

- **A2. DoS via deeply nested URL-encoding:** `MAX_ITERATIONS = 3` caps recursion. Good. But each iteration allocates a fresh `String`, and `body_preview` can be up to a configured cap. With body-inspection enabled and a 1MB cap, a single request triggers ~3MB of decode allocations × N rules with `field: all`. Easy DoS vector. **See I3 — fix decodes-once-per-request.**

- **A3. Host-routing via long Host header:** `router.resolve(host)` is called twice per request (I1) on a string that is unbounded length. If the resolver is a HashMap lookup, fine; if it does any per-request regex over hostnames, this compounds.

- **A4. Cluster transport race on rustls install:** `prx-waf/src/main.rs:289` installs `ring` first; cluster transport at `transport/server.rs:65` ALSO uses `ring` explicitly. Compatible. But `transport::client::build_tls_config` runs on whatever runtime spawns it — verify QUIC doesn't internally reach for the process-default before this builder runs. The defensive `builder_with_provider` should cover it.

- **A5. e2e test stack as supply-chain vector:** `docker.io/mccutchen/go-httpbin:2.22.1` is pinned (good) but image digests are not. Add `@sha256:…` for full reproducibility. `debian:bookworm-slim` in the workflow is unpinned — same fix.

- **A6. `cargo install --locked cargo-audit` runs as the runner user** — cargo-audit ships its own advisory DB downloads. CI run-time fetches `https://github.com/RustSec/advisory-db.git` over HTTPS — non-deterministic but standard.

---

## Positive observations

- WAF inspection of bodyless requests is now actually correct — the `request_filter` change closes a bypass that affected every GET. This was probably the highest-impact fix in the PR.
- `block_scripted_clients` flag — clean, off-by-default, real attack tools always blocked. Tests cover both modes including the regression case.
- Cluster `ClusterNode::new` / `state()` split — good separation; the comment explains the lifecycle exactly.
- Recursive YAML directory walk in `OWASPCheck::from_directory` — proper handling of non-rule files via `debug!` not `warn!`.
- `host(client_ip)` SQL fix — well-commented, addresses a real sqlx prepared-statement type-mismatch issue.
- All `expect_used`/`unwrap_used` allowances are scoped, justified, and limited to clearly compile-time-safe constructs.

---

## Metrics

- Files changed: 37
- Lines added/removed: +2375 / -109
- New `.unwrap()` in production code: 0 ✅
- New `.expect()` in production code: 0 (only scoped `#[allow]` on compile-time literals) ✅
- New advisory ignores: 24 (deny.toml + audit.toml combined)
- Test coverage: e2e harness adds 4 suites covering rules-engine, gateway, waf-api, cluster

---

## Recommended actions (priority order)

1. **I3** — Hoist URL-decoding out of the per-rule loop into per-request scratch. Biggest perf/DoS impact.
2. **I4** — Demote `tracing::info!` rule-fire log to `debug!`.
3. **I2** — Trim `is_routing_header` skip list (drop `accept`, `x-forwarded-*`, `x-real-ip`).
4. **I1** — Resolve host once in `request_filter`, not twice.
5. **C1** — Audit the `e2e_finalize || true; exit 1` pattern, add tee-reaper for cluster script.
6. **I8** — Replace render-report.sh's grep/awk JSON parsing with `jq` (it's available on every standard runner).
7. **C2** — Add a CI check that any new entry in `deny.toml`/`audit.toml` ignore lists requires a tracking-issue link in the comment.
8. **I9** — Verify cluster job actually works end-to-end on the temporary push trigger before merging to main.

---

## Unresolved questions

1. Are admin-uploaded rhai custom rules (RUSTSEC-2026-0099 acknowledgment) actually sandboxed against panicking destructors, or just against syscalls? Worth checking before merging the deny.toml entry.
2. Is `body_preview` length capped before reaching `CompiledRule::matches`? If not, I3 is a Critical, not Important.
3. Does the cluster job's lack of an explicit compose-up step actually work on a clean ubuntu-latest runner? The temp push trigger should answer this — verify before removing the `push: feature/e2e-test` block.
4. Why does `unmaintained = "all"` in `deny.toml:13` coexist with three `unmaintained` ignores? Tighten the policy to only ignore ones with concrete issue links.
5. The `permissions: pull-requests: write` on nightly-e2e.yml is unused (no PR-comment step). Drop unless an upcoming step needs it.
