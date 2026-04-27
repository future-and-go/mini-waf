#!/usr/bin/env bash
# Admin API (crates/waf-api) E2E suite.
#
# Verifies authentication + the major REST surfaces a deployed operator uses
# day-to-day: hosts CRUD, allow/block IP CRUD, attack logs, stats, rules
# registry, cluster status, and unauthenticated endpoints.

set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=tests/e2e/lib.sh
source tests/e2e/lib.sh

ADMIN="http://localhost:16827"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"

e2e_init "waf-api"

# ── 0) Health (public) ──────────────────────────────────────────────────────
if ! wait_health "WAF API"  "$ADMIN/health" 90; then
    fail "health.public" "/health did not respond 200"
    e2e_finalize || true
    exit 1
fi
pass "health.public"

# ── 1) Auth ─────────────────────────────────────────────────────────────────
assert_http_status "auth.unauthenticated-rejected" "401" "$ADMIN/api/hosts"

LOGIN=$(http_get -X POST "$ADMIN/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")
# Login response shape: { "success": true, "data": { "access_token": "...", "refresh_token": "..." } }
TOKEN=$(echo "$LOGIN" | grep -o '"access_token":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")

if [[ -z "$TOKEN" ]]; then
    fail "auth.login" "no token in response: $LOGIN"
    e2e_finalize || true
    exit 1
fi
pass "auth.login"

assert_http_status "auth.bad-password" "401" -X POST "$ADMIN/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"definitely-wrong\"}"

AUTH=( -H "Authorization: Bearer $TOKEN" )

# ── 2) Hosts CRUD ───────────────────────────────────────────────────────────
# CreateHost requires *all* bool fields explicitly (serde rejects partial JSON).
HOST_NAME="e2e-${RANDOM}.test"
CREATE=$(http_get -X POST "${AUTH[@]}" "$ADMIN/api/hosts" \
    -H "Content-Type: application/json" \
    -d "{\"host\":\"$HOST_NAME\",\"port\":80,\"ssl\":false,\"guard_status\":true,\"remote_host\":\"httpbin\",\"remote_port\":80,\"start_status\":true,\"log_only_mode\":false}")
assert_contains "hosts.create" "$HOST_NAME" "$CREATE"

# Extract auto-generated host_code from create response — needed for IP/URL rules.
HOST_CODE=$(echo "$CREATE" | grep -o '"code":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")
log "created host_code=$HOST_CODE"

LIST=$(http_get "${AUTH[@]}" "$ADMIN/api/hosts")
assert_contains "hosts.list" "$HOST_NAME" "$LIST"

# ── 3) Allow / Block IP CRUD ────────────────────────────────────────────────
# CreateIpRule = { host_code, ip_cidr, remarks? }
BLOCK_RESP=$(http_get -X POST "${AUTH[@]}" "$ADMIN/api/block-ips" \
    -H "Content-Type: application/json" \
    -d "{\"host_code\":\"$HOST_CODE\",\"ip_cidr\":\"203.0.113.0/24\",\"remarks\":\"e2e-test\"}")
assert_contains "block-ips.create" "203.0.113" "$BLOCK_RESP"

ALLOW_RESP=$(http_get -X POST "${AUTH[@]}" "$ADMIN/api/allow-ips" \
    -H "Content-Type: application/json" \
    -d "{\"host_code\":\"$HOST_CODE\",\"ip_cidr\":\"198.51.100.0/24\",\"remarks\":\"e2e-allow\"}")
assert_contains "allow-ips.create" "198.51.100" "$ALLOW_RESP"

assert_http_status "allow-ips.list" "200" "${AUTH[@]}" "$ADMIN/api/allow-ips"
assert_http_status "block-ips.list" "200" "${AUTH[@]}" "$ADMIN/api/block-ips"
assert_http_status "block-urls.list" "200" "${AUTH[@]}" "$ADMIN/api/block-urls"

# ── 4) Logs + stats ─────────────────────────────────────────────────────────
# Fetch attack-logs separately first so we can log the response body if it
# fails — the bare assert_http_status only sees the status code which makes
# diagnosing 500s opaque (sqlx error messages live in the body).
ATTACK_RESP=$(curl -sk --max-time 10 -w '\n%{http_code}' "${AUTH[@]}" "$ADMIN/api/attack-logs" 2>/dev/null || echo $'\n000')
ATTACK_CODE="${ATTACK_RESP##*$'\n'}"
ATTACK_BODY="${ATTACK_RESP%$'\n'*}"
log "attack-logs HTTP $ATTACK_CODE — body: ${ATTACK_BODY:0:400}"
assert_eq "attack-logs" "200" "$ATTACK_CODE"
assert_http_status "security-events" "200" "${AUTH[@]}" "$ADMIN/api/security-events"
assert_http_status "stats.overview"  "200" "${AUTH[@]}" "$ADMIN/api/stats/overview"
assert_http_status "stats.timeseries" "200" "${AUTH[@]}" "$ADMIN/api/stats/timeseries"
assert_http_status "stats.geo"       "200" "${AUTH[@]}" "$ADMIN/api/stats/geo"

# ── 5) Rule registry + reload ───────────────────────────────────────────────
REG=$(http_get "${AUTH[@]}" "$ADMIN/api/rules/registry")
# Stream via stdin to avoid `awk -v s=…` ARG_MAX overflow on large registries.
RULES=$(printf '%s' "$REG" | awk '{ n+=gsub(/"id"/, "") } END { print n+0 }')
if (( RULES > 20 )); then
    pass "rules.registry" "$RULES rules"
else
    fail "rules.registry" "only $RULES rules (expected >20)"
fi

assert_http_status "rules.reload-registry" "200" -X POST "${AUTH[@]}" "$ADMIN/api/rules/reload"
assert_http_status "rules.reload-engine"   "200" -X POST "${AUTH[@]}" "$ADMIN/api/reload"

# ── 6) Status + cluster status ───────────────────────────────────────────────
# /api/cluster/status and /api/cluster/nodes return 404 ("cluster not enabled")
# when the running config has no [cluster] section — e2e.toml deliberately
# omits cluster, so 404 is the correct, deterministic answer here. The 404
# proves the route exists and the auth layer accepted the JWT.
assert_http_status "status.api"            "200" "${AUTH[@]}" "$ADMIN/api/status"
assert_http_status "cluster.status"        "404" "${AUTH[@]}" "$ADMIN/api/cluster/status"
assert_http_status "cluster.list-nodes"    "404" "${AUTH[@]}" "$ADMIN/api/cluster/nodes"

# ── 7) Cache management ─────────────────────────────────────────────────────
assert_http_status "cache.stats" "200" "${AUTH[@]}" "$ADMIN/api/cache/stats"

# ── 8) Misc surfaces ────────────────────────────────────────────────────────
assert_http_status "tunnels.list"        "200" "${AUTH[@]}" "$ADMIN/api/tunnels"
assert_http_status "plugins.list"        "200" "${AUTH[@]}" "$ADMIN/api/plugins"
assert_http_status "notifications.list"  "200" "${AUTH[@]}" "$ADMIN/api/notifications"
assert_http_status "audit-log.list"      "200" "${AUTH[@]}" "$ADMIN/api/audit-log"
assert_http_status "lb-backends.list"    "200" "${AUTH[@]}" "$ADMIN/api/lb-backends"
assert_http_status "certificates.list"   "200" "${AUTH[@]}" "$ADMIN/api/certificates"
assert_http_status "custom-rules.list"   "200" "${AUTH[@]}" "$ADMIN/api/custom-rules"

e2e_finalize
