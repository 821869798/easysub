FROM rust:1.96.0-alpine AS builder

RUN apk add --no-cache build-base cmake perl

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY benches ./benches
RUN test "$(rustc --version | awk '{print $2}')" = "1.96.0"
RUN cargo build --locked --release

FROM alpine:latest AS runtime

LABEL maintainer="821869798@qq.com"

RUN apk add --no-cache ca-certificates \
    && addgroup -S easysub \
    && adduser -S -G easysub easysub

WORKDIR /app
COPY workdir /app/workdir
RUN cp /app/workdir/pref.example.toml /app/workdir/pref.toml \
    && sed -i '/key = "clash.log_level"/{N;s/value = "info"/value = "warning"/}' /app/workdir/pref.toml \
    && sed -i '/key = "singbox.log_level"/{N;s/value = "info"/value = "warn"/}' /app/workdir/pref.toml \
    && chown -R easysub:easysub /app

USER easysub

ENV EASYSUB_CONFIG=/app/workdir/pref.toml \
    PORT=25500 \
    RUST_LOG=easysub_rs=info,tower_http=info

EXPOSE 25500/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:25500/healthz || exit 1

ENTRYPOINT ["/app/easysub-rs"]

# Release workflow target: packages a binary built on the native GitHub runner.
FROM runtime AS release
COPY --chown=easysub:easysub container-binary/easysub-rs /app/easysub-rs

# Default target: keep regular Docker and Railway builds source-based.
FROM runtime AS source-build
COPY --from=builder --chown=easysub:easysub /build/target/release/easysub-rs /app/easysub-rs
