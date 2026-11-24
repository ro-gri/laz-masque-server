# E2E test client — multi-stage build
# Stage 1: build
FROM rust:1.88-bookworm AS builder

RUN apt-get update \
    && apt-get install -y cmake golang-go clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Dependency caching layer. Cargo validates every declared target before it
# builds the selected package, so the root benchmark needs a stub here too.
COPY Cargo.toml Cargo.lock ./
COPY tools/laz-masque-e2e/Cargo.toml tools/laz-masque-e2e/Cargo.toml
COPY tools/laz-masque-probe/Cargo.toml tools/laz-masque-probe/Cargo.toml
RUN mkdir -p src benches tools/laz-masque-e2e/src tools/laz-masque-probe/src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && echo "fn main() {}" > benches/core.rs \
    && echo "fn main() {}" > tools/laz-masque-e2e/src/main.rs \
    && echo "fn main() {}" > tools/laz-masque-probe/src/main.rs \
    && cargo build --release -p laz-masque-e2e 2>/dev/null || true \
    && rm -f target/release/laz-masque-e2e target/release/deps/masque* target/release/deps/laz_masque* \
    && rm -rf src benches tools/laz-masque-e2e/src tools/laz-masque-probe/src

# Copy real source and build.
COPY src/ src/
COPY benches/ benches/
COPY tools/laz-masque-e2e/ tools/laz-masque-e2e/
COPY tools/laz-masque-probe/ tools/laz-masque-probe/
RUN touch src/main.rs src/lib.rs tools/laz-masque-e2e/src/main.rs \
    && cargo build --release -p laz-masque-e2e

# Stage 2: minimal runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/laz-masque-e2e /usr/local/bin/laz-masque-e2e

ENTRYPOINT ["laz-masque-e2e"]
