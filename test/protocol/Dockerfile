FROM rust:1.94.1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY test/differential/ test/differential/
COPY test/matrix/ test/matrix/
COPY test/protocol/Cargo.toml test/protocol/
COPY test/protocol/src/ test/protocol/src/
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --locked --bin fg-protocol-fixture \
    && install -D target/debug/fg-protocol-fixture /out/fg-protocol-fixture

FROM debian:bookworm-slim AS fixture
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/fg-protocol-fixture /usr/local/bin/
ENTRYPOINT ["fg-protocol-fixture"]

FROM python:3.12.14-slim-bookworm AS python-client
WORKDIR /suite
COPY test/protocol/clients/requirements.txt .
RUN pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: -r requirements.txt
COPY test/protocol/clients/*.py ./
ENTRYPOINT ["python", "/suite/probe.py"]

FROM golang:1.26.2-bookworm AS go-client
WORKDIR /suite
ENV GOTOOLCHAIN=local
COPY test/protocol/clients/go.mod test/protocol/clients/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY test/protocol/clients/probe.go .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -mod=readonly -o /usr/local/bin/protocol-go-probe ./probe.go
ENTRYPOINT ["/usr/local/bin/protocol-go-probe"]

FROM eclipse-temurin:21.0.11_10-jdk-noble AS java-client
WORKDIR /suite
ADD https://repo.maven.apache.org/maven2/com/mysql/mysql-connector-j/9.3.0/mysql-connector-j-9.3.0.jar /drivers/
ADD https://repo.maven.apache.org/maven2/org/postgresql/postgresql/42.7.7/postgresql-42.7.7.jar /drivers/
COPY test/protocol/clients/Probe.java .
COPY test/protocol/clients/java.sh .
ENTRYPOINT ["sh", "/suite/java.sh"]
