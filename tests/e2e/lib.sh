#!/usr/bin/env bash
# Shared helpers for nightly E2E suites.
#
# Each suite must:
#   1. source this file
#   2. call `e2e_init <suite_name>`        — sets up output paths
#   3. call `assert_<...>` helpers         — records pass/fail
#   4. call `e2e_finalize`                 — writes JUnit XML + JSON + summary
#
# Output artefacts (under $E2E_OUT_DIR, default tests/e2e/out/<suite>):
#   - results.json   : machine-readable results
#   - junit.xml      : JUnit XML for the Checks tab
#   - summary.md     : Markdown for $GITHUB_STEP_SUMMARY
#
# All helpers are intentionally side-effect free apart from the four globals
# `E2E_SUITE`, `E2E_OUT_DIR`, `E2E_PASS`, `E2E_FAIL` and the `E2E_RESULTS`
# associative arrays that hold per-test data.

set -euo pipefail

# ── Output globals (populated by e2e_init) ────────────────────────────────────
# E2E_OUT_DIR may be set by the caller as an environment variable to override
# where artefacts land — DO NOT initialise it here, that would clobber the
# inherited value before e2e_init runs.
E2E_SUITE=""
: "${E2E_OUT_DIR:=}"
E2E_PASS=0
E2E_FAIL=0
E2E_T0=0
declare -a E2E_NAMES=()
declare -a E2E_STATUSES=()
declare -a E2E_DETAILS=()

# ── Lifecycle ─────────────────────────────────────────────────────────────────

e2e_init() {
    E2E_SUITE="$1"
    E2E_OUT_DIR="${E2E_OUT_DIR:-tests/e2e/out/$E2E_SUITE}"
    mkdir -p "$E2E_OUT_DIR"
    E2E_PASS=0
    E2E_FAIL=0
    E2E_T0=$(date +%s)
    log "[$E2E_SUITE] suite started"
}

e2e_finalize() {
    local elapsed=$(( $(date +%s) - E2E_T0 ))
    local total=$(( E2E_PASS + E2E_FAIL ))
    local status="PASS"
    [[ "$E2E_FAIL" -gt 0 ]] && status="FAIL"

    write_results_json "$elapsed" "$total"
    write_junit_xml "$elapsed"
    write_step_summary "$elapsed" "$total" "$status"

    log "[$E2E_SUITE] finished in ${elapsed}s — ${E2E_PASS}/${total} pass — ${status}"
    [[ "$E2E_FAIL" -gt 0 ]] && return 1 || return 0
}

# ── Logging ───────────────────────────────────────────────────────────────────

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { local n="$1"; shift; local d="${*:-}"; E2E_PASS=$((E2E_PASS+1)); _record "$n" "pass" "$d"; echo "  [PASS] $n"; }
fail() { local n="$1"; shift; local d="${*:-}"; E2E_FAIL=$((E2E_FAIL+1)); _record "$n" "fail" "$d"; echo "  [FAIL] $n — $d"; }

_record() {
    E2E_NAMES+=("$1")
    E2E_STATUSES+=("$2")
    E2E_DETAILS+=("$3")
}

# ── Assertions ────────────────────────────────────────────────────────────────
# Record a pass or fail with a structured name.

assert_eq() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        pass "$name"
    else
        fail "$name" "expected=$expected actual=$actual"
    fi
}

assert_ne() {
    local name="$1" forbidden="$2" actual="$3"
    if [[ "$forbidden" != "$actual" ]]; then
        pass "$name"
    else
        fail "$name" "value must not be $forbidden"
    fi
}

assert_contains() {
    local name="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -q -- "$needle"; then
        pass "$name"
    else
        fail "$name" "missing token: $needle"
    fi
}

assert_http_status() {
    local name="$1" expected="$2"; shift 2
    local code
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "$@" || echo "000")
    if [[ "$code" == "$expected" ]]; then
        pass "$name" "HTTP $code"
    else
        fail "$name" "expected HTTP $expected, got $code (curl $*)"
    fi
}

# Curl with a timeout that returns the body on success, empty on failure.
http_get() { curl -sk --max-time 10 "$@" 2>/dev/null || echo ""; }

# ── Wait for a service to become healthy ──────────────────────────────────────

wait_health() {
    local name="$1" url="$2" max="${3:-90}" elapsed=0
    log "[$E2E_SUITE] waiting for $name (max ${max}s)..."
    while (( elapsed < max )); do
        if curl -sf --max-time 3 "$url" >/dev/null 2>&1; then
            log "[$E2E_SUITE] $name is healthy after ${elapsed}s"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    return 1
}

# ── Output writers ────────────────────────────────────────────────────────────

# JSON schema used by render-report.sh:
#   { "suite": "...", "elapsed_s": N, "pass": N, "fail": N, "tests": [
#       {"name": "...", "status": "pass|fail", "detail": "..."} ... ]}
write_results_json() {
    local elapsed="$1" total="$2"
    local file="$E2E_OUT_DIR/results.json"
    {
        echo "{"
        echo "  \"suite\": \"$E2E_SUITE\","
        echo "  \"elapsed_s\": $elapsed,"
        echo "  \"total\": $total,"
        echo "  \"pass\": $E2E_PASS,"
        echo "  \"fail\": $E2E_FAIL,"
        echo "  \"tests\": ["
        local n=${#E2E_NAMES[@]} i=0
        while (( i < n )); do
            local name detail
            name=$(_json_escape "${E2E_NAMES[$i]}")
            detail=$(_json_escape "${E2E_DETAILS[$i]}")
            printf '    {"name": "%s", "status": "%s", "detail": "%s"}' \
                "$name" "${E2E_STATUSES[$i]}" "$detail"
            (( i + 1 < n )) && printf ","
            printf "\n"
            i=$((i + 1))
        done
        echo "  ]"
        echo "}"
    } > "$file"
    log "wrote $file"
}

write_junit_xml() {
    local elapsed="$1"
    local file="$E2E_OUT_DIR/junit.xml"
    local total=$(( E2E_PASS + E2E_FAIL ))
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        printf '<testsuite name="%s" tests="%d" failures="%d" time="%d">\n' \
            "$E2E_SUITE" "$total" "$E2E_FAIL" "$elapsed"
        local n=${#E2E_NAMES[@]} i=0
        while (( i < n )); do
            local name detail
            name=$(_xml_escape "${E2E_NAMES[$i]}")
            detail=$(_xml_escape "${E2E_DETAILS[$i]}")
            printf '  <testcase classname="%s" name="%s">' "$E2E_SUITE" "$name"
            if [[ "${E2E_STATUSES[$i]}" == "fail" ]]; then
                printf '<failure message="%s"/>' "$detail"
            fi
            echo '</testcase>'
            i=$((i + 1))
        done
        echo '</testsuite>'
    } > "$file"
    log "wrote $file"
}

write_step_summary() {
    local elapsed="$1" total="$2" status="$3"
    local file="$E2E_OUT_DIR/summary.md"
    local badge="✅"
    [[ "$status" == "FAIL" ]] && badge="❌"
    {
        echo "## $badge ${E2E_SUITE} suite — ${status}"
        echo
        echo "**${E2E_PASS}/${total} passed** in ${elapsed}s"
        echo
        if (( E2E_FAIL > 0 )); then
            echo "<details><summary>Failures (${E2E_FAIL})</summary>"
            echo
            local n=${#E2E_NAMES[@]} i=0
            while (( i < n )); do
                if [[ "${E2E_STATUSES[$i]}" == "fail" ]]; then
                    echo "- \`${E2E_NAMES[$i]}\` — ${E2E_DETAILS[$i]}"
                fi
                i=$((i + 1))
            done
            echo
            echo "</details>"
            echo
        fi
        echo "<details><summary>All tests</summary>"
        echo
        echo "| # | Test | Status | Detail |"
        echo "|---|------|--------|--------|"
        local n=${#E2E_NAMES[@]} i=0
        while (( i < n )); do
            local emoji="✅"
            [[ "${E2E_STATUSES[$i]}" == "fail" ]] && emoji="❌"
            local detail="${E2E_DETAILS[$i]:-}"
            detail="${detail//|/\\|}"
            echo "| $((i+1)) | \`${E2E_NAMES[$i]}\` | $emoji | $detail |"
            i=$((i + 1))
        done
        echo
        echo "</details>"
    } > "$file"

    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        cat "$file" >> "$GITHUB_STEP_SUMMARY"
    fi
}

# ── String escaping (no jq dependency) ────────────────────────────────────────

_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//	/\\t}"
    s="${s//
/\\n}"
    printf '%s' "$s"
}

_xml_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    s="${s//\'/&apos;}"
    printf '%s' "$s"
}

# ── Compose abstraction (matches existing tests/e2e-cluster.sh logic) ─────────

detect_compose() {
    if [[ -n "${COMPOSE_CMD:-}" ]]; then echo "$COMPOSE_CMD"; return; fi
    if command -v docker-compose &>/dev/null; then echo "docker-compose"; return; fi
    if docker compose version &>/dev/null 2>&1; then echo "docker compose"; return; fi
    if command -v podman-compose &>/dev/null; then echo "podman-compose"; return; fi
    echo ""
}
