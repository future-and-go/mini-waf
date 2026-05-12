#!/usr/bin/env sh
# FR-039 Docker e2e assertions. Run inside the asserter container; `waf`,
# `hang-backend`, `healthy-backend` are docker-compose DNS names.
set -eu

PROXY="http://waf:80"
FAIL=0

assert() {
    label="$1"
    shift
    if "$@"; then
        echo "  PASS  $label"
    else
        echo "  FAIL  $label  ($*)"
        FAIL=$((FAIL + 1))
    fi
}

between() {
    # $1 lo, $2 hi, $3 value (all integers)
    [ "$3" -ge "$1" ] && [ "$3" -le "$2" ]
}

# ── E1: hang backend → 503 within (read_timeout + slack) ────────────────────
start=$(date +%s%N)
status=$(curl -s -o /dev/null -w '%{http_code}' -m 10 -H 'Host: hang.test' "$PROXY/") || status=000
elapsed_ms=$(( ( $(date +%s%N) - start ) / 1000000 ))
echo "E1 hang-backend → status=${status} elapsed=${elapsed_ms}ms"
assert "E1 status=503" [ "$status" = "503" ]
# Test-scale read_timeout is 1500ms → expect ~1.5s, allow 1.0–4.5s window.
assert "E1 elapsed in [1000, 4500]ms" between 1000 4500 "$elapsed_ms"

# ── E2: connection refused → 503 fast ───────────────────────────────────────
start=$(date +%s%N)
status=$(curl -s -o /dev/null -w '%{http_code}' -m 10 -H 'Host: refused.test' "$PROXY/") || status=000
elapsed_ms=$(( ( $(date +%s%N) - start ) / 1000000 ))
echo "E2 refused-backend → status=${status} elapsed=${elapsed_ms}ms"
assert "E2 status=503" [ "$status" = "503" ]
assert "E2 elapsed < 2500ms" [ "$elapsed_ms" -lt 2500 ]

# ── E3: healthy backend → 200 ───────────────────────────────────────────────
status=$(curl -s -o /dev/null -w '%{http_code}' -m 10 -H 'Host: ok.test' "$PROXY/") || status=000
echo "E3 healthy-backend → status=${status}"
assert "E3 status=200" [ "$status" = "200" ]

# ── E4: 503 carries Retry-After: 5 ──────────────────────────────────────────
retry=$(curl -s -o /dev/null -D - -m 10 -H 'Host: hang.test' "$PROXY/" \
        | tr -d '\r' | awk 'tolower($1)=="retry-after:" {print $2; exit}')
echo "E4 retry-after on 503 → '${retry}'"
assert "E4 retry-after=5" [ "$retry" = "5" ]

echo
echo "FR-039 e2e summary: failures=${FAIL}"
exit "$FAIL"
