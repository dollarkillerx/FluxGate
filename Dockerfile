# syntax=docker/dockerfile:1
#
# Single-binary FluxGate: build the React console, embed it into the Rust binary.

# --- Stage 1: build the frontend ---------------------------------------------
FROM node:20-bookworm-slim AS web
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

# --- Stage 2: build the Rust binary (rust-embed embeds web/dist) --------------
FROM rust:1-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY --from=web /app/web/dist ./web/dist
RUN cargo build --release -p fluxgate-admin

# --- Stage 3: minimal runtime image ------------------------------------------
FROM debian:bookworm-slim
WORKDIR /data
COPY --from=build /app/target/release/fluxgate-admin /usr/local/bin/fluxgate-admin
# Bind on all interfaces inside the container. Admin is HTTPS (self-signed);
# the data plane exposes plaintext HTTP + SNI HTTPS on non-privileged ports.
ENV FLUXGATE_ADMIN_ADDR=0.0.0.0:8080 \
    FLUXGATE_PROXY_ADDR=0.0.0.0:8081 \
    FLUXGATE_PROXY_TLS_ADDR=0.0.0.0:8443 \
    RUST_LOG=info
EXPOSE 8080 8081 8443
# Config + certs + logs persist under /data (mount a volume here).
ENTRYPOINT ["fluxgate-admin"]
