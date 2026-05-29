# CI-local: mirrors GitHub Actions CI environment for pre-push verification.
#
# Mirrors .github/workflows/{ci,coverage,sec-audit}.yml:
#   - Rust stable (1.96+) — same as dtolnay/rust-toolchain@stable
#   - clippy + rustfmt components
#   - llvm-tools-preview + cargo-llvm-cov for coverage gate
#   - cargo-machete for unused-dep check
#   - system deps for vendored pingora (pkg-config, libssl-dev, build-essential, cmake)
#
# Companion file: ../docker-compose.ci-local.yml (Postgres 16-alpine sidecar).
# Helper: ../scripts/ci-local.sh (runs the pre-push pipeline).
#
# Usage:
#   docker compose -f docker-compose.ci-local.yml run --rm ci-local /workspace/scripts/ci-local.sh

FROM rust:1.96-bookworm

ENV CARGO_TERM_COLOR=always \
    RUSTFLAGS="-D warnings" \
    RUST_BACKTRACE=full \
    CARGO_INCREMENTAL=0 \
    DEBIAN_FRONTEND=noninteractive

# System deps for vendored pingora + Postgres client libs for sqlx-postgres.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        cmake \
        build-essential \
        git \
        libpq-dev \
        postgresql-client \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Rust components matching the CI matrix.
RUN rustup component add clippy rustfmt llvm-tools-preview

# Cargo tools used by CI (cargo-llvm-cov for coverage, cargo-machete for unused deps).
# Install separately so a transient registry blip on one does not invalidate
# the other's cached layer. Latest stable versions; pin if drift becomes an issue.
RUN cargo install --locked cargo-llvm-cov
RUN cargo install --locked cargo-machete

# Frontend toolchain for the admin-panel job. Node 22 + npm matching ci.yml.
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Default to an interactive shell — the helper script is invoked as the
# explicit command via docker compose run.
CMD ["/bin/bash"]
