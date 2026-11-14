FROM node:24.19.0-bookworm-slim AS console
WORKDIR /console
COPY apps/console/package.json apps/console/package-lock.json ./
RUN npm ci --ignore-scripts
COPY apps/console/ ./
RUN npm run build

FROM rust:1.94.1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY test/differential/ test/differential/
COPY test/matrix/ test/matrix/
COPY test/protocol/ test/protocol/
ARG FG_BUILD_REVISION=unavailable
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    RUSTFLAGS="--remap-path-prefix=/build=. --remap-path-prefix=/usr/local/cargo/registry/src=dependencies -C strip=symbols" \
    FG_GATE_BUILD_REVISION="$FG_BUILD_REVISION" cargo build --locked --release \
      -p fg-control -p fg-proxy -p fg-cli \
    && install -D target/release/fg-control /out/fg-control \
    && install -D target/release/fg-proxy /out/fg-proxy \
    && install -D target/release/forkget /out/forkget

FROM golang:1.25.12-bookworm AS tidb-tools
WORKDIR /launcher
COPY tools/dumpling/ ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache,sharing=locked \
    sh build.sh /fg-dumpling-run
RUN curl --fail --location --proto '=https' --tlsv1.2 -sS \
      https://tiup-mirrors.pingcap.com/tidb-lightning-v8.5.8-linux-amd64.tar.gz \
      -o /lightning.tar.gz \
    && mkdir /lightning && tar -xzf /lightning.tar.gz -C /lightning

FROM mongo:7.0.48 AS mongo-tools

FROM ubuntu:24.04
ARG FG_BUILD_REVISION=unavailable
LABEL org.opencontainers.image.revision=$FG_BUILD_REVISION
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates openssl util-linux postgresql-client-16 mysql-shell \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /usr/local/bin/
COPY --from=console /console/build/ /usr/share/forkget/console/
COPY --from=tidb-tools /fg-dumpling-run /usr/local/bin/fg-dumpling-run
COPY --from=tidb-tools /lightning/tidb-lightning /usr/local/bin/tidb-lightning
COPY --from=mongo-tools /usr/bin/mongodump /usr/bin/mongorestore /usr/local/bin/
COPY deploy/runtime-grants.sql /opt/forkget/runtime-grants.sql
WORKDIR /work
CMD ["fg-control", "doctor"]
