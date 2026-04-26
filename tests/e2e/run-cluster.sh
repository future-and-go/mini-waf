#!/usr/bin/env bash
# Cluster (crates/waf-cluster) E2E suite.
#
# Brings up the 3-node cluster defined in docker-compose.cluster.yml with the
# tests/e2e/cluster-override.yml layer (which injects ADMIN_PASSWORD), then
# verifies:
#   1. cluster-init generates certificates
#   2. all 3 nodes become healthy on /health (public)
#   3. login on node-a works → JWT
#   4. /api/cluster/status (auth-protected) reports node-a=Main, node-b=Worker, node-c=Worker
#   5. stopping node-a triggers an election → node-b OR node-c becomes Main
#   6. restarting node-a lets it rejoin the cluster
#
# We deliberately do NOT call tests/e2e-cluster.sh — that script predates the
# JWT-protected cluster API and uses an outdated login path. This suite is
# self-contained and emits the JSON+JUnit+summary artefacts via lib.sh.

set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=tests/e2e/lib.sh
source tests/e2e/lib.sh

NODE_A_API="http://localhost:16827"
NODE_B_API="http://localhost:16828"
NODE_C_API="http://localhost:16829"

ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"

CLUSTER_COMPOSE="docker-compose.cluster.yml"
CLUSTER_OVERRIDE="tests/e2e/cluster-override.yml"
COMPOSE="$(detect_compose)"
[[ -n "$COMPOSE" ]] || { echo "no docker compose available" >&2; exit 1; }

COMPOSE_FILES=(-f "$CLUSTER_COMPOSE" -f "$CLUSTER_OVERRIDE")

e2e_init "cluster"

LOG_FILE="$E2E_OUT_DIR/e2e-cluster.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# NOTE: do NOT install an EXIT trap that tears down the cluster — the
# enclosing GitHub Actions job has its own `Tear down` step (if: always())
# AND a `Cluster logs (always)` step that runs AFTER this script. If we
# tear down here, the workflow's logs step runs against a vanished cluster
# and prints nothing useful (the very situation that hid the original bug).

# ── Helpers ──────────────────────────────────────────────────────────────────

# Extract `"role":"X"` from a /api/cluster/status response. Returns "unknown"
# on parse failure (401, empty body, etc.) so callers can assert deterministic
# values.
get_role() {
    local body="$1"
    echo "$body" | grep -o '"role":"[^"]*"' | head -1 | cut -d'"' -f4 \
        | tr -d '\n' || echo ""
}

login_token() {
    local url="$1"
    local body
    body=$(curl -sk --max-time 10 -X POST "$url/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
        2>/dev/null || echo "")
    echo "$body" | grep -o '"access_token":"[^"]*"' | head -1 | cut -d'"' -f4 || echo ""
}

# ── Step 1: Generate certificates (one-shot init container) ───────────────────

log "step 1: generating cluster certificates"
if $COMPOSE "${COMPOSE_FILES[@]}" run --rm cluster-init >/dev/null 2>&1; then
    pass "cluster.cert-init"
else
    fail "cluster.cert-init" "cluster-init container exited non-zero"
    e2e_finalize || true
    exit 1
fi

# ── Step 2: Bring up all 3 nodes ──────────────────────────────────────────────

log "step 2: starting node-a, node-b, node-c"
$COMPOSE "${COMPOSE_FILES[@]}" up -d node-a node-b node-c

if wait_health "node-a" "$NODE_A_API/health" 120; then pass "cluster.node-a.healthy"
else fail "cluster.node-a.healthy" "/health did not respond within 120s"; fi

if wait_health "node-b" "$NODE_B_API/health" 90; then pass "cluster.node-b.healthy"
else fail "cluster.node-b.healthy" "/health did not respond within 90s"; fi

if wait_health "node-c" "$NODE_C_API/health" 90; then pass "cluster.node-c.healthy"
else fail "cluster.node-c.healthy" "/health did not respond within 90s"; fi

# ── Step 3: Login on node-a to obtain a JWT for the protected cluster API ─────

log "step 3: authenticating against node-a"
TOKEN=""
for attempt in 1 2 3 4 5; do
    TOKEN=$(login_token "$NODE_A_API")
    [[ -n "$TOKEN" ]] && break
    log "  login attempt $attempt failed, retrying in 3s..."
    sleep 3
done

if [[ -z "$TOKEN" ]]; then
    fail "cluster.auth.login" "could not obtain access_token (admin user not seeded?)"
    e2e_finalize || true
    exit 1
fi
pass "cluster.auth.login"

AUTH_HDR="Authorization: Bearer $TOKEN"

# Give the cluster a few extra seconds to settle before reading roles — node-b
# and node-c may have just joined and the election manager needs at least one
# heartbeat round before peer roles propagate.
log "  waiting 10s for cluster to settle"
sleep 10

# ── Step 4: Verify roles on each node ─────────────────────────────────────────

log "step 4: verifying node roles"

# Helper that fetches /api/cluster/status with auth, captures both HTTP code
# and body, and dumps the raw response to stderr for debugging when assertions
# fail. The `-w "\n%{http_code}"` trick separates body and code without jq.
#
# CRITICAL: the diagnostic prints MUST go to stderr (>&2). The caller wraps
# this function in `$(...)` which captures stdout into a variable; if the
# logs went to stdout the caller would receive "[12:34:56] body: ..." mixed
# with the JSON body, breaking the role/node_id regex parsers downstream.
fetch_status() {
    local url="$1" body code resp
    resp=$(curl -sk --max-time 10 -H "$AUTH_HDR" -w '\n%{http_code}' "$url/api/cluster/status" || echo $'\n000')
    code="${resp##*$'\n'}"
    body="${resp%$'\n'*}"
    echo "[$(date +%H:%M:%S)]   GET $url/api/cluster/status -> HTTP $code" >&2
    echo "[$(date +%H:%M:%S)]   body: ${body:0:400}" >&2
    printf '%s' "$body"
}

STATUS_A=$(fetch_status "$NODE_A_API")
ROLE_A=$(get_role "$STATUS_A")
log "  node-a role=$ROLE_A"
assert_contains "cluster.node-a.status-has-node_id" '"node_id"' "$STATUS_A"
assert_eq "cluster.node-a.role" "Main" "$ROLE_A"

STATUS_B=$(fetch_status "$NODE_B_API")
ROLE_B=$(get_role "$STATUS_B")
log "  node-b role=$ROLE_B"
assert_eq "cluster.node-b.role" "Worker" "$ROLE_B"

STATUS_C=$(fetch_status "$NODE_C_API")
ROLE_C=$(get_role "$STATUS_C")
log "  node-c role=$ROLE_C"
assert_eq "cluster.node-c.role" "Worker" "$ROLE_C"

# ── Step 5: Election test — stop node-a, expect a new Main on node-b or -c ────

log "step 5: stopping node-a to trigger election"
$COMPOSE "${COMPOSE_FILES[@]}" stop node-a >/dev/null 2>&1 || true

# Election timeout is 150-300ms + phi-accrual death detection (~2s) + a few
# heartbeat rounds — give it 25s to be safe.
log "  waiting 25s for new main to be elected"
sleep 25

STATUS_B2=$(fetch_status "$NODE_B_API")
ROLE_B2=$(get_role "$STATUS_B2")
STATUS_C2=$(fetch_status "$NODE_C_API")
ROLE_C2=$(get_role "$STATUS_C2")
log "  after election: node-b=$ROLE_B2 node-c=$ROLE_C2"

if [[ "$ROLE_B2" == "Main" || "$ROLE_C2" == "Main" ]]; then
    pass "cluster.election.new-main-elected" "b=$ROLE_B2 c=$ROLE_C2"
else
    fail "cluster.election.new-main-elected" "neither node-b nor node-c became Main (b=$ROLE_B2 c=$ROLE_C2)"
fi

# ── Step 6: Rejoin — restart node-a, it should come back as Worker ────────────

log "step 6: restarting node-a to test rejoin"
$COMPOSE "${COMPOSE_FILES[@]}" start node-a >/dev/null 2>&1 || true

if wait_health "node-a-rejoin" "$NODE_A_API/health" 60; then
    pass "cluster.rejoin.node-a-healthy"
else
    fail "cluster.rejoin.node-a-healthy" "/health did not come back within 60s"
fi

sleep 5
# Re-login because the original token was issued by the (now-stopped-then-restarted)
# node-a — the JWT itself is still valid (same secret) but we want a fresh one
# anyway in case any session state was lost.
TOKEN=$(login_token "$NODE_A_API")
[[ -n "$TOKEN" ]] && AUTH_HDR="Authorization: Bearer $TOKEN"
STATUS_A2=$(fetch_status "$NODE_A_API")
ROLE_A2=$(get_role "$STATUS_A2")
log "  node-a role after rejoin=$ROLE_A2"
# After rejoin node-a may be Worker (a new main was already elected) or Main
# (if it re-asserted leadership before another election finished). Either is a
# valid recovery, we just want to confirm the cluster is consistent.
if [[ "$ROLE_A2" == "Worker" || "$ROLE_A2" == "Main" ]]; then
    pass "cluster.rejoin.node-a-has-role" "role=$ROLE_A2"
else
    fail "cluster.rejoin.node-a-has-role" "unexpected role: $ROLE_A2"
fi

e2e_finalize
