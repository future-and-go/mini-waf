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
TOKEN=$(echo "$LOGIN" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")

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
HOST_NAME="e2e-${RANDOM}.test"
CREATE=$(http_get -X POST "${AUTH[@]}" "$ADMIN/api/hosts" \
    -H "Content-Type: application/json" \
    -d "{\"host\":\"$HOST_NAME\",\"port\":80,\"remote_host\":\"httpbin\",\"remote_port\":80,\"guard_status\":true}")
assert_contains "hosts.create" "$HOST_NAME" "$CREATE"

LIST=$(http_get "${AUTH[@]}" "$ADMIN/api/hosts")
assert_contains "hosts.list" "$HOST_NAME" "$LIST"

# ── 3) Allow / Block IP CRUD ────────────────────────────────────────────────
BLOCK_RESP=$(http_get -X POST "${AUTH[@]}" "$ADMIN/api/block-ips" \
    -H "Content-Type: application/json" \
    -d '{"cidr":"203.0.113.0/24","reason":"e2e-test"}')
assert_contains "block-ips.create" "203.0.113" "$BLOCK_RESP"

ALLOW_RESP=$(http_get -X POST "${AUTH[@]}" "$ADMIN/api/allow-ips" \
    -H "Content-Type: application/json" \
    -d '{"cidr":"198.51.100.0/24","reason":"e2e-allow"}')
assert_contains "allow-ips.create" "198.51.100" "$ALLOW_RESP"

assert_http_status "allow-ips.list" "200" "${AUTH[@]}" "$ADMIN/api/allow-ips"
assert_http_status "block-ips.list" "200" "${AUTH[@]}" "$ADMIN/api/block-ips"
assert_http_status "block-urls.list" "200" "${AUTH[@]}" "$ADMIN/api/block-urls"

# ── 4) Logs + stats ─────────────────────────────────────────────────────────
assert_http_status "attack-logs"     "200" "${AUTH[@]}" "$ADMIN/api/attack-logs"
assert_http_status "security-events" "200" "${AUTH[@]}" "$ADMIN/api/security-events"
assert_http_status "stats.overview"  "200" "${AUTH[@]}" "$ADMIN/api/stats/overview"
assert_http_status "stats.timeseries" "200" "${AUTH[@]}" "$ADMIN/api/stats/timeseries"
assert_http_status "stats.geo"       "200" "${AUTH[@]}" "$ADMIN/api/stats/geo"

# ── 5) Rule registry + reload ───────────────────────────────────────────────
REG=$(http_get "${AUTH[@]}" "$ADMIN/api/rules/registry")
RULES=$(echo "$REG" | grep -o '"id"' | wc -l | tr -d ' ')
if (( RULES > 20 )); then
    pass "rules.registry" "$RULES rules"
else
    fail "rules.registry" "only $RULES rules (expected >20)"
fi

assert_http_status "rules.reload-registry" "200" -X POST "${AUTH[@]}" "$ADMIN/api/rules/reload"
assert_http_status "rules.reload-engine"   "200" -X POST "${AUTH[@]}" "$ADMIN/api/reload"

# ── 6) Status + cluster status (cluster disabled in this stack but endpoint must exist) ─
assert_http_status "status.api"            "200" "${AUTH[@]}" "$ADMIN/api/status"
assert_http_status "cluster.status"        "200" "${AUTH[@]}" "$ADMIN/api/cluster/status"
assert_http_status "cluster.list-nodes"    "200" "${AUTH[@]}" "$ADMIN/api/cluster/nodes"

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
