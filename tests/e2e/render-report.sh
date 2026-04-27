#!/usr/bin/env bash
# Aggregates per-suite results.json files into a single report.
#
# Usage:
#   tests/e2e/render-report.sh <input_dir> <output_dir>
#
#   <input_dir>  directory containing one sub-directory per suite, each with a
#                results.json file (matches the layout produced by lib.sh).
#                Suites without results.json are reported as MISSING.
#   <output_dir> directory where summary.md and report.html are written. The
#                summary.md is also appended to $GITHUB_STEP_SUMMARY when set.

set -euo pipefail

IN_DIR="${1:?usage: render-report.sh <input_dir> <output_dir>}"
OUT_DIR="${2:?usage: render-report.sh <input_dir> <output_dir>}"
mkdir -p "$OUT_DIR"

SUITES=(rules-engine gateway waf-api cluster)

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_TIME=0
declare -a SUITE_NAMES=()
declare -a SUITE_STATUS=()
declare -a SUITE_PASS=()
declare -a SUITE_FAIL=()
declare -a SUITE_TIME=()
declare -a SUITE_TESTS_JSON=()

read_field() {
    # cheap JSON scalar reader: read_field <key> <file>
    # Matches `"<key>": <number>` and returns the digits immediately after
    # the colon (handles single-line and multi-line JSON, ignores later
    # numbers on the same line).
    grep -oE "\"$1\":[[:space:]]*[0-9]+" "$2" | head -1 | grep -oE '[0-9]+$'
}

for s in "${SUITES[@]}"; do
    f=""
    for cand in "$IN_DIR/$s/results.json" "$IN_DIR/$s-results/$s/results.json" "$IN_DIR/$s-results/results.json"; do
        if [[ -f "$cand" ]]; then f="$cand"; break; fi
    done
    SUITE_NAMES+=("$s")
    if [[ -z "$f" ]]; then
        SUITE_STATUS+=("MISSING")
        SUITE_PASS+=("0")
        SUITE_FAIL+=("0")
        SUITE_TIME+=("0")
        SUITE_TESTS_JSON+=("[]")
        continue
    fi
    p=$(read_field pass "$f");      p="${p:-0}"
    fc=$(read_field fail "$f");     fc="${fc:-0}"
    t=$(read_field elapsed_s "$f"); t="${t:-0}"
    SUITE_PASS+=("$p")
    SUITE_FAIL+=("$fc")
    SUITE_TIME+=("$t")
    if (( fc > 0 )); then
        SUITE_STATUS+=("FAIL")
    else
        SUITE_STATUS+=("PASS")
    fi
    TOTAL_PASS=$(( TOTAL_PASS + p ))
    TOTAL_FAIL=$(( TOTAL_FAIL + fc ))
    TOTAL_TIME=$(( TOTAL_TIME + t ))
    SUITE_TESTS_JSON+=("$(awk '/"tests":/{flag=1} flag{print}' "$f")")
done

OVERALL="PASS"
(( TOTAL_FAIL > 0 )) && OVERALL="FAIL"
[[ " ${SUITE_STATUS[*]} " == *" MISSING "* ]] && OVERALL="FAIL"

DATE_UTC=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
COMMIT="${GITHUB_SHA:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
RUN_URL=""
if [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "${GITHUB_RUN_ID:-}" ]]; then
    RUN_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
fi

# ── Markdown summary ────────────────────────────────────────────────────────
MD="$OUT_DIR/summary.md"
{
    badge="✅"; [[ "$OVERALL" == "FAIL" ]] && badge="❌"
    echo "# $badge PRX-WAF Nightly E2E — $OVERALL"
    echo
    echo "| Field | Value |"
    echo "|-------|-------|"
    echo "| Generated | $DATE_UTC |"
    echo "| Commit | \`$COMMIT\` |"
    [[ -n "$RUN_URL" ]] && echo "| Workflow run | [$GITHUB_RUN_ID]($RUN_URL) |"
    echo "| Total | **$TOTAL_PASS pass / $TOTAL_FAIL fail** in ${TOTAL_TIME}s |"
    echo
    echo "## Suite results"
    echo
    echo "| Suite | Status | Pass | Fail | Duration |"
    echo "|-------|--------|------|------|----------|"
    for i in "${!SUITE_NAMES[@]}"; do
        emoji="✅"
        case "${SUITE_STATUS[$i]}" in
            FAIL)    emoji="❌" ;;
            MISSING) emoji="⚠️"  ;;
        esac
        echo "| \`${SUITE_NAMES[$i]}\` | $emoji ${SUITE_STATUS[$i]} | ${SUITE_PASS[$i]} | ${SUITE_FAIL[$i]} | ${SUITE_TIME[$i]}s |"
    done
    echo
    echo "## Coverage"
    echo
    echo "- **rules-engine** — verifies every rule under \`rules/\` loads and that representative malicious payloads per category are blocked"
    echo "- **gateway** (\`crates/gateway\`) — proxy forwarding, host routing, body inspection, response cache, status pass-through"
    echo "- **waf-api** (\`crates/waf-api\`) — authentication, hosts/IP/URL CRUD, rules registry, stats, cluster status, cache management"
    echo "- **cluster** (\`crates/waf-cluster\`) — 3-node bootstrap, leader election, rule sync, node rejoin"
    echo
    echo "## Failures"
    echo
    any_fail=0
    for i in "${!SUITE_NAMES[@]}"; do
        if [[ "${SUITE_STATUS[$i]}" == "FAIL" || "${SUITE_STATUS[$i]}" == "MISSING" ]]; then
            any_fail=1
            echo "<details><summary><b>${SUITE_NAMES[$i]}</b> — ${SUITE_STATUS[$i]}</summary>"
            echo
            f="$IN_DIR/${SUITE_NAMES[$i]}/summary.md"
            if [[ -f "$f" ]]; then
                cat "$f"
            else
                echo "_no per-suite summary available_"
            fi
            echo
            echo "</details>"
            echo
        fi
    done
    if (( any_fail == 0 )); then
        echo "_None — every suite passed._"
    fi
} > "$MD"

# ── HTML artefact ───────────────────────────────────────────────────────────
HTML="$OUT_DIR/report.html"
{
    cat <<'HTML_HEAD'
<!doctype html><html><head><meta charset="utf-8">
<title>PRX-WAF Nightly E2E Report</title>
<style>
 body{font:14px -apple-system,Segoe UI,Roboto,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#222}
 h1{margin-bottom:.2em}
 .meta{color:#666;margin-bottom:1.5em}
 table{border-collapse:collapse;width:100%;margin:1em 0}
 th,td{border:1px solid #ddd;padding:.45rem .6rem;text-align:left}
 th{background:#f6f8fa}
 .pass{color:#1a7f37;font-weight:600}
 .fail{color:#c93b3b;font-weight:600}
 .miss{color:#9a6700;font-weight:600}
 details{margin:.6em 0}
 summary{cursor:pointer;font-weight:600;padding:.2em 0}
 .pill{display:inline-block;padding:.1em .5em;border-radius:99px;font-size:12px}
 .pill.pass{background:#dafbe1;color:#1a7f37}
 .pill.fail{background:#ffebe9;color:#c93b3b}
 .pill.miss{background:#fff8c5;color:#9a6700}
</style>
</head><body>
HTML_HEAD
    title_class=$(echo "$OVERALL" | tr 'A-Z' 'a-z')
    echo "<h1>PRX-WAF Nightly E2E — <span class=\"$title_class\">$OVERALL</span></h1>"
    echo "<div class=meta>"
    echo "Generated $DATE_UTC · commit <code>$COMMIT</code>"
    [[ -n "$RUN_URL" ]] && echo " · <a href=\"$RUN_URL\">workflow run</a>"
    echo "<br>Totals: <b>$TOTAL_PASS pass / $TOTAL_FAIL fail</b> · ${TOTAL_TIME}s</div>"

    echo "<h2>Suites</h2><table><tr><th>Suite</th><th>Status</th><th>Pass</th><th>Fail</th><th>Duration</th></tr>"
    for i in "${!SUITE_NAMES[@]}"; do
        cls=$(echo "${SUITE_STATUS[$i]}" | tr 'A-Z' 'a-z')
        [[ "$cls" == "missing" ]] && cls="miss"
        echo "<tr><td><code>${SUITE_NAMES[$i]}</code></td><td><span class=\"pill $cls\">${SUITE_STATUS[$i]}</span></td><td>${SUITE_PASS[$i]}</td><td>${SUITE_FAIL[$i]}</td><td>${SUITE_TIME[$i]}s</td></tr>"
    done
    echo "</table>"

    echo "<h2>Per-suite details</h2>"
    for s in "${SUITES[@]}"; do
        f="$IN_DIR/$s/results.json"
        echo "<details${OVERALL:+}><summary>$s</summary>"
        if [[ -f "$f" ]]; then
            echo "<table><tr><th>#</th><th>Test</th><th>Status</th><th>Detail</th></tr>"
            # Parse the tests array with awk (simple but adequate for this schema).
            awk '
                /"tests":/ { flag=1; next }
                flag && /^[[:space:]]*\]/ { flag=0; next }
                flag {
                    if ($0 !~ /"name":[[:space:]]*"/) next
                    line=$0
                    sub(/.*"name":[[:space:]]*"/, "", line); name=line; sub(/".*/, "", name)
                    line=$0
                    sub(/.*"status":[[:space:]]*"/, "", line); st=line; sub(/".*/, "", st)
                    line=$0
                    sub(/.*"detail":[[:space:]]*"/, "", line); det=line; sub(/"[[:space:]]*}.*/, "", det)
                    i++
                    cls=(st=="pass"?"pass":"fail")
                    printf("<tr><td>%d</td><td><code>%s</code></td><td class=\"%s\">%s</td><td>%s</td></tr>\n", i, name, cls, st, det)
                }
            ' "$f"
            echo "</table>"
        else
            echo "<p class=miss>No results.json — suite did not run.</p>"
        fi
        echo "</details>"
    done

    echo "</body></html>"
} > "$HTML"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    cat "$MD" >> "$GITHUB_STEP_SUMMARY"
fi

echo "wrote $MD"
echo "wrote $HTML"

# Exit non-zero so the workflow's "report" job still surfaces failure even
# when individual suite jobs are configured with continue-on-error.
[[ "$OVERALL" == "PASS" ]]
