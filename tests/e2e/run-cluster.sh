#!/usr/bin/env bash
# Cluster (crates/waf-cluster) E2E suite.
#
# Wraps the existing tests/e2e-cluster.sh script — it already covers the four
# cluster-critical scenarios (boot 3 nodes → roles → rule sync → election →
# rejoin) — and translates its plain-text PASS/FAIL output into the JSON +
# JUnit + step-summary artefacts the nightly workflow consumes.

set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=tests/e2e/lib.sh
source tests/e2e/lib.sh

e2e_init "cluster"

LOG_FILE="$E2E_OUT_DIR/e2e-cluster.log"

# Run the existing cluster e2e harness end-to-end and capture its tee'd output.
set +e
bash tests/e2e-cluster.sh 2>&1 | tee "$LOG_FILE"
RC=$?
set -e
log "tests/e2e-cluster.sh exited with rc=$RC"

# Re-emit each PASS/FAIL line from the harness as one structured assertion so
# the aggregated report shows individual cluster scenarios, not just the
# script's overall verdict.
NUM=0
while IFS= read -r line; do
    case "$line" in
        *"[PASS]"*)
            NUM=$((NUM+1))
            name=$(echo "$line" | sed -E 's/.*\[PASS\]\s+//; s/[^A-Za-z0-9_.: -]/_/g')
            pass "cluster.${NUM}.${name// /_}" ;;
        *"[FAIL]"*)
            NUM=$((NUM+1))
            name=$(echo "$line" | sed -E 's/.*\[FAIL\]\s+//; s/[^A-Za-z0-9_.: -]/_/g')
            fail "cluster.${NUM}.${name// /_}" "see e2e-cluster.log"
            ;;
    esac
done < "$LOG_FILE"

# Always emit a synthetic test for the harness exit status so a bare `bash exit
# 1` (e.g. compose failure) is also visible in the aggregated report.
if [[ "$RC" == "0" ]]; then
    pass "cluster.harness.exit-status" "rc=0"
else
    fail "cluster.harness.exit-status" "rc=$RC"
fi

e2e_finalize
