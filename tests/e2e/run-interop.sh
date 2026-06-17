#!/usr/bin/env bash
# Interop v2.3 benchmark-contract E2E suite (epics E10–E17).
#
# Exercises the surface a benchmark harness drives, end-to-end on the live
# docker stack:
#   E10 — /__waf_control/* control plane (auth, capabilities, set_profile,
#         reset_state, flush_cache) on the admin API port; local-only.
#   E11 — six X-WAF-* observability headers on a proxied response.
#   E13 — decision classes (allow→200, block→403) with X-WAF-Action.
#   E14 — log_only mode forwards instead of enforcing; X-WAF-Mode reflects it.
#   E15 — X-WAF-Cache carries a valid enum; dynamic upstream → BYPASS.
#   E12 — audit JSONL: required fields + request_id correlation.
#   E17 — unsolved challenge submission is denied (does not proceed upstream).
#
# Pre-requisites: tests/e2e/docker-compose.e2e.yml is running.

set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=tests/e2e/lib.sh
source tests/e2e/lib.sh

PROXY="http://localhost:16880"   # gateway proxy listener
ADMIN="http://localhost:16827"   # admin API listener (control plane lives here)
CTRL="$ADMIN/__waf_control"
SECRET="waf-hackathon-2026-ctrl"
CONTAINER="${E2E_CONTAINER:-e2e-prx-waf}"
AUDIT_LOG="/tmp/waf_audit.log"

e2e_init "interop"

if ! wait_health "WAF API" "$ADMIN/health" 90; then
    fail "waf.health" "API never became healthy"
    e2e_finalize || true
    exit 1
fi
pass "waf.health"

# Fetch a single response header value (case-insensitive) from a proxied request.
# Usage: header_value "<header-name>" <curl args...>
header_value() {
    local name="$1"; shift
    curl -sk -D - -o /dev/null --max-time 10 "$@" 2>/dev/null \
        | awk -F': ' -v h="$(echo "$name" | tr '[:upper:]' '[:lower:]')" '
            { k=tolower($1); sub(/\r$/,"",$2); if (k==h) { print $2; exit } }'
}

# ── E10: control-plane auth (US-1001/1002) ──────────────────────────────────
assert_http_status "ctrl.auth.no-secret"    "403" "$CTRL/capabilities"
assert_http_status "ctrl.auth.wrong-secret" "403" \
    -H "X-Benchmark-Secret: nope" "$CTRL/capabilities"
assert_http_status "ctrl.auth.correct"      "200" \
    -H "X-Benchmark-Secret: $SECRET" "$CTRL/capabilities"

# Local-only (US-1001): the control path on the PROXY port must NOT be the
# control plane — it routes to upstream (httpbin 404), never returns capabilities.
PROXY_CTRL=$(http_get -H "X-Benchmark-Secret: $SECRET" "$PROXY/__waf_control/capabilities")
if echo "$PROXY_CTRL" | grep -q '"features"'; then
    fail "ctrl.local-only" "control plane reachable via proxy port"
else
    pass "ctrl.local-only"
fi

# ── E10: capabilities shape (US-1003) ───────────────────────────────────────
CAPS=$(http_get -H "X-Benchmark-Secret: $SECRET" "$CTRL/capabilities")
assert_contains "ctrl.caps.ok"            '"ok":true'           "$CAPS"
assert_contains "ctrl.caps.features"      '"features"'          "$CAPS"
assert_contains "ctrl.caps.injection"     'injection_control'   "$CAPS"
assert_contains "ctrl.caps.default-mode"  '"default_mode":"enforce"' "$CAPS"

# ── E10: set_profile / reset_state / flush_cache (US-1004/1005/1006) ────────
SET=$(http_get -X POST -H "X-Benchmark-Secret: $SECRET" \
    -H "Content-Type: application/json" \
    -d '{"scope":"all","mode":"enforce"}' "$CTRL/set_profile")
assert_contains "ctrl.set_profile.ok"      '"ok":true'          "$SET"
assert_contains "ctrl.set_profile.applied" '"action":"set_profile"' "$SET"

assert_http_status "ctrl.set_profile.bad-mode" "400" -X POST \
    -H "X-Benchmark-Secret: $SECRET" -H "Content-Type: application/json" \
    -d '{"scope":"all","mode":"bogus"}' "$CTRL/set_profile"

RESET=$(http_get -X POST -H "X-Benchmark-Secret: $SECRET" "$CTRL/reset_state")
assert_contains "ctrl.reset_state.ok" '"ok":true' "$RESET"

assert_http_status "ctrl.flush_cache.ok" "200" -X POST \
    -H "X-Benchmark-Secret: $SECRET" "$CTRL/flush_cache"

# ── E11: six X-WAF-* headers on a proxied response (US-1101–1106) ───────────
HDRS=$(curl -sk -D - -o /dev/null --max-time 10 "$PROXY/get" 2>/dev/null | tr 'A-Z' 'a-z')
for h in x-waf-request-id x-waf-risk-score x-waf-action x-waf-rule-id x-waf-mode x-waf-cache; do
    if echo "$HDRS" | grep -q "^$h:"; then
        pass "headers.$h"
    else
        fail "headers.$h" "missing on proxied response"
    fi
done

# ── E13: decision classes (US-1301) ─────────────────────────────────────────
ALLOW_ACTION=$(header_value "X-WAF-Action" "$PROXY/get")
assert_eq "decision.allow.action" "allow" "$ALLOW_ACTION"
assert_http_status "decision.allow.status" "200" "$PROXY/get"

assert_http_status "decision.block.status" "403" \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    --data "name=admin' OR 1=1--" "$PROXY/post"
BLOCK_ACTION=$(header_value "X-WAF-Action" \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    --data "name=admin' OR 1=1--" "$PROXY/post")
assert_eq "decision.block.action" "block" "$BLOCK_ACTION"

# ── E14: log_only forwards instead of enforcing (US-1402/1403) ──────────────
http_get -X POST -H "X-Benchmark-Secret: $SECRET" -H "Content-Type: application/json" \
    -d '{"scope":"all","mode":"log_only"}' "$CTRL/set_profile" >/dev/null
# Same SQLi payload that was blocked under enforce must now be forwarded (200).
assert_http_status "mode.log_only.forwarded" "200" \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    --data "name=admin' OR 1=1--" "$PROXY/post"
LO_MODE=$(header_value "X-WAF-Mode" \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    --data "name=admin' OR 1=1--" "$PROXY/post")
assert_eq "mode.log_only.header" "log_only" "$LO_MODE"
# Restore enforce so later assertions and re-runs start clean.
http_get -X POST -H "X-Benchmark-Secret: $SECRET" "$CTRL/reset_state" >/dev/null
ENF_MODE=$(header_value "X-WAF-Mode" "$PROXY/get")
assert_eq "mode.enforce.restored" "enforce" "$ENF_MODE"

# ── E15: cache classification header (US-1501/1502) ─────────────────────────
# X-WAF-Cache always carries one of the three enum values, and the dynamic
# httpbin upstream (CatchAll tier, no cacheable policy) classifies as BYPASS.
# A positive MISS→HIT transition needs a tier whose cache_policy != NoCache,
# which this upstream has none of; that path is covered by the gateway
# cache_integration tests, not reproducible against httpbin here.
http_get -X POST -H "X-Benchmark-Secret: $SECRET" "$CTRL/flush_cache" >/dev/null
CACHE_CLASS=$(header_value "X-WAF-Cache" "$PROXY/get")
case "$CACHE_CLASS" in
    HIT|MISS|BYPASS) pass "cache.class.valid-enum" ;;
    *) fail "cache.class.valid-enum" "X-WAF-Cache='$CACHE_CLASS' not in {HIT,MISS,BYPASS}" ;;
esac
assert_eq "cache.dynamic.bypass" "BYPASS" "$CACHE_CLASS"

# ── E12: audit JSONL — required fields + correlation (US-1202/1204) ─────────
# Drive one request whose request-id we can correlate against the audit line.
# Audit writes are flushed asynchronously, so poll until our line lands rather
# than reading immediately (the suite is faster than the flush interval).
REQ_ID=$(header_value "X-WAF-Request-Id" "$PROXY/get?audit=probe")
if ! docker exec "$CONTAINER" test -f "$AUDIT_LOG" 2>/dev/null; then
    fail "audit.file-exists" "$AUDIT_LOG absent in $CONTAINER"
else
    pass "audit.file-exists"
    AUDIT_LINE=""
    for _ in $(seq 1 30); do
        AUDIT_LINE=$(docker exec "$CONTAINER" sh -c "grep -F -- '$REQ_ID' '$AUDIT_LOG' 2>/dev/null || true" | tail -n 1)
        [ -n "$AUDIT_LINE" ] && break
        sleep 0.5
    done
    if [ -n "$AUDIT_LINE" ]; then
        pass "audit.correlation" "request_id $REQ_ID found"
        for field in request_id ts_ms ip method path action risk_score mode; do
            assert_contains "audit.field.$field" "\"$field\"" "$AUDIT_LINE"
        done
    else
        fail "audit.correlation" "request_id $REQ_ID not in audit log after poll"
        for field in request_id ts_ms ip method path action risk_score mode; do
            fail "audit.field.$field" "audit line never flushed"
        done
    fi
fi

# ── E17: unsolved challenge submission is denied (US-1702 negative) ─────────
# A submission without a valid proof-of-work must not proceed upstream. The WAF
# denies it (403) and stamps X-WAF-Action, proving it was handled at the WAF
# layer rather than forwarded to the origin. The positive issue→solve→cookie
# path is risk-score-driven and covered by the challenge integration tests.
assert_http_status "challenge.unsolved.denied" "403" \
    -X POST -H "Content-Type: application/json" \
    -d '{"challenge_token":"deadbeef","nonce":"0"}' "$PROXY/challenge/verify"
CH_ACTION=$(header_value "X-WAF-Action" \
    -X POST -H "Content-Type: application/json" \
    -d '{"challenge_token":"deadbeef","nonce":"0"}' "$PROXY/challenge/verify")
if [ -n "$CH_ACTION" ]; then
    pass "challenge.unsolved.waf-handled" "X-WAF-Action=$CH_ACTION"
else
    fail "challenge.unsolved.waf-handled" "no X-WAF-Action on denied submission"
fi

e2e_finalize
