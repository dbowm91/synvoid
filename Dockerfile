# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Node toolchain for the Yew/WASM admin UI (Trunk + Tailwind).
# ---------------------------------------------------------------------------
FROM node:22-bookworm-slim AS node

# ---------------------------------------------------------------------------
# Builder: pinned Rust (rust-toolchain.toml), protoc, Node, Trunk, wasm-pack.
# ---------------------------------------------------------------------------
FROM rust:1.98.1-bookworm AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      clang \
      cmake \
      curl \
      git \
      libclang-dev \
      liblzma-dev \
      libssl-dev \
      nasm \
      pkg-config \
      protobuf-compiler \
      python3 \
      unzip \
 && rm -rf /var/lib/apt/lists/*

# Node is only needed to build the admin UI. Copy it into the Rust image so
# one stage owns the whole build and the source tree is not copied twice.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -sf /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -sf /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# wasm32 is required by both Trunk (admin UI) and wasm-pack (PoW challenge).
# Trunk is pinned to the version recorded in the phase plan/CI.
RUN rustup target add wasm32-unknown-unknown \
 && cargo install --locked --version 0.21.14 trunk \
 && cargo install --locked --version 0.13.1 wasm-pack

WORKDIR /src
COPY . .

# WASM proof-of-work module. wasm-pack names the artifacts after the crate
# (`synvoid-wasm-pow`), not the old `wasm_pow` module path used by build.sh.
RUN wasm-pack build crates/synvoid-wasm-pow --target web --out-dir pkg --release \
 && cp crates/synvoid-wasm-pow/pkg/synvoid_wasm_pow_bg.wasm static/pow.wasm \
 && cp crates/synvoid-wasm-pow/pkg/synvoid_wasm_pow_bg.wasm static/mesh_pow.wasm \
 && sed 's|synvoid_wasm_pow_bg.wasm|pow.wasm|g' \
        crates/synvoid-wasm-pow/pkg/synvoid_wasm_pow.js > static/pow_wasm.js

# Admin UI (Tailwind CSS -> Trunk/Yew -> SRI bootstrap extraction).
RUN cd admin-ui && npm ci && npm run build

# Root Supervisor binary plus the jail binaries that must ship atomically with
# it (resolve_jail_binary searches the executable's directory).
RUN cargo build --locked --release --bin synvoid \
 && cargo build --locked --release -p synvoid-jail-runtime --bins

# ---------------------------------------------------------------------------
# Runtime: minimal Debian/glibc, non-root service account, read-only install
# tree, writable state/log/cache/runtime directories.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      liblzma5 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 synvoid \
 && useradd --system --uid 10001 --gid synvoid \
      --home-dir /var/lib/synvoid --shell /usr/sbin/nologin synvoid \
 && install -d -o root -g root -m 0755 \
      /opt/synvoid /opt/synvoid/admin-ui /opt/synvoid/config \
 && install -d -o synvoid -g synvoid -m 0700 \
      /etc/synvoid /var/lib/synvoid /var/log/synvoid /var/cache/synvoid /run/synvoid

# Main binary and jail binaries stay together: the jail resolver only looks
# next to the executable, never in PATH or the working directory.
COPY --from=builder /src/target/release/synvoid /usr/local/bin/synvoid
COPY --from=builder /src/target/release/synvoid-wasm-jail /usr/local/bin/synvoid-wasm-jail
COPY --from=builder /src/target/release/synvoid-yara-jail /usr/local/bin/synvoid-yara-jail

# Read-only install tree.
COPY --from=builder /src/admin-ui/dist /opt/synvoid/admin-ui/dist
COPY --from=builder /src/static /opt/synvoid/static
COPY --from=builder /src/rules /opt/synvoid/rules
COPY --from=builder /src/root.hints /opt/synvoid/root.hints

# Default relative paths (`config/error_pages`, `config/mimes`, the legacy
# `honeypot_endpoints.txt` lookup) resolve against WORKDIR /opt/synvoid.
COPY --from=builder /src/config/error_pages /opt/synvoid/config/error_pages
COPY --from=builder /src/config/mimes /opt/synvoid/config/mimes
COPY --from=builder /src/config/honeypot_endpoints.txt /opt/synvoid/config/honeypot_endpoints.txt
COPY --from=builder /src/config/honeypot_endpoints.txt /opt/synvoid/honeypot_endpoints.txt

# Default configuration directory consumed by `--config-path /etc/synvoid`.
# Owned by the service user so the admin config editor can rewrite main.toml
# and sites/. Override with a bind mount for production configuration.
COPY --from=builder /src/config /etc/synvoid
RUN chown -R synvoid:synvoid /etc/synvoid \
 && find /etc/synvoid -type d -exec chmod 0700 {} + \
 && find /etc/synvoid -type f -exec chmod 0600 {} +

LABEL org.opencontainers.image.title="SynVoid" \
      org.opencontainers.image.description="High-performance WAF and reverse proxy" \
      org.opencontainers.image.source="https://github.com/dbowm91/synvoid" \
      org.opencontainers.image.licenses="MIT"

ENV RUST_LOG=info \
    XDG_DATA_HOME=/var/lib/synvoid \
    SYNVOID_ADMIN_UI_DIR=/opt/synvoid/admin-ui/dist

WORKDIR /opt/synvoid

# Only the data-plane port is published by default. Admin (127.0.0.1:8081) and
# metrics (127.0.0.1:9090) stay loopback inside the container; publish them
# only through an explicit, authenticated decision.
EXPOSE 8080

VOLUME ["/var/lib/synvoid", "/var/log/synvoid"]

STOPSIGNAL SIGTERM

# The Supervisor has no public HTTP health route of its own. `--status` uses
# the private pidfile/IPC socket, so the check works whether or not the admin
# listener is enabled and never exposes the admin API.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD /usr/local/bin/synvoid --status | grep -q "Supervisor PID" || exit 1

USER synvoid

# `--foreground` keeps the Supervisor as PID 1 so Docker can deliver SIGTERM.
# Passing a command (for example `--configtest`) replaces the default command.
ENTRYPOINT ["/usr/local/bin/synvoid"]
CMD ["--foreground", "--config-path", "/etc/synvoid"]
