#!/usr/bin/env bash
# ci-local.sh — pre-push verification pipeline mirroring GitHub Actions CI.
#
# Run via docker-compose so the env matches GHA exactly:
#   docker compose -f docker-compose.ci-local.yml run --rm ci-local /workspace/scripts/ci-local.sh
#
# Or run a single phase:
#   docker compose -f docker-compose.ci-local.yml run --rm ci-local /workspace/scripts/ci-local.sh fmt
#   docker compose -f docker-compose.ci-local.yml run --rm ci-local /workspace/scripts/ci-local.sh clippy
#   docker compose -f docker-compose.ci-local.yml run --rm ci-local /workspace/scripts/ci-local.sh test
#   docker compose -f docker-compose.ci-local.yml run --rm ci-local /workspace/scripts/ci-local.sh coverage <crate>
#
# Phases mirror .github/workflows/{ci,coverage}.yml:
#   fmt        : cargo fmt --all -- --check
#   clippy     : cargo clippy --workspace --all-targets --all-features -- -D warnings
#   machete    : cargo machete                         (unused deps)
#   test       : cargo test --workspace --all-features -- --nocapture
#   build      : cargo build --workspace --release
#   admin-panel: npm ci + npm run type-check + npm run build (web/admin-panel)
#   coverage   : cargo llvm-cov --summary-only -p <crate>   (matrix gate)
#   all (default): fmt + clippy + machete + test + admin-panel
#
# Exit non-zero on the first failure; print a clear hint on which step blocked.

set -euo pipefail

phase="${1:-all}"
crate_arg="${2:-}"

red() { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue() { printf '\033[34m%s\033[0m\n' "$*"; }

run_fmt() {
    blue "[fmt] cargo fmt --all -- --check"
    cargo fmt --all -- --check
}

run_clippy() {
    blue "[clippy] cargo clippy --workspace --all-targets --all-features -- -D warnings"
    cargo clippy --workspace --all-targets --all-features -- -D warnings
}

run_machete() {
    blue "[machete] cargo machete"
    cargo machete
}

run_test() {
    blue "[test] cargo test --workspace --all-features -- --nocapture"
    cargo test --workspace --all-features -- --nocapture
}

run_build() {
    blue "[build] cargo build --workspace --release"
    cargo build --workspace --release
}

run_admin_panel() {
    blue "[admin-panel] npm ci + type-check + build"
    pushd web/admin-panel >/dev/null
    npm ci
    npm run type-check
    npm run build
    popd >/dev/null
}

run_coverage() {
    if [[ -z "$crate_arg" ]]; then
        red "coverage requires a crate name. Example: scripts/ci-local.sh coverage waf-api"
        exit 2
    fi
    # Floors from .github/workflows/coverage.yml matrix.
    declare -A floors=(
        [waf-common]=88
        [waf-storage]=84
        [waf-cluster]=82
        [waf-api]=80
        [gateway]=85
        [waf-engine]=80
        [prx-waf]=5
    )
    floor="${floors[$crate_arg]:-}"
    if [[ -z "$floor" ]]; then
        red "Unknown crate '$crate_arg'. Floors are defined for: ${!floors[*]}"
        exit 2
    fi
    blue "[coverage] cargo llvm-cov -p $crate_arg (floor ${floor}%)"
    cargo llvm-cov --summary-only -p "$crate_arg" --all-features \
        --fail-under-lines "$floor"
}

case "$phase" in
    fmt)         run_fmt ;;
    clippy)      run_clippy ;;
    machete)     run_machete ;;
    test)        run_test ;;
    build)       run_build ;;
    admin-panel) run_admin_panel ;;
    coverage)    run_coverage ;;
    all)
        run_fmt
        run_clippy
        run_machete
        run_test
        run_admin_panel
        green "[OK] All pre-push checks passed. Safe to git push."
        ;;
    *)
        red "Unknown phase: $phase"
        red "Valid phases: fmt clippy machete test build admin-panel coverage all"
        exit 2
        ;;
esac
