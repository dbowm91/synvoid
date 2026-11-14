# Getting Started

This guide builds SynVoid, configures one site, and verifies that requests reach an upstream. Use [DEPLOYMENT.md](./DEPLOYMENT.md) for production, systemd, and container setup.

## What SynVoid does

SynVoid is a reverse proxy and web application firewall. A Supervisor manages process lifecycle, while a unified worker handles HTTP, WAF inspection, and proxying. Selected CPU-intensive work runs in separate CPU workers. Optional features add DNS, mesh networking, and other services.

## Prerequisites

- A supported Rust toolchain.
- `protoc` (Protocol Buffers compiler). The default build enables mesh and runs protobuf code generation.
- An upstream application to proxy, such as one listening on `127.0.0.1:8000`.

On Debian or Ubuntu, install `protoc` with:

```bash
sudo apt-get install -y protobuf-compiler
```

## Build

```bash
git clone https://github.com/dbowm91/synvoid.git
cd synvoid
cargo build --release
```

The main binary is `target/release/synvoid`. The default feature set is `socket-handoff, mesh, dns, erased_pool, swagger-ui`.

## Configure one site

Generate an admin token and an IPC key in the shell where SynVoid will run:

```bash
export SYNVOID_ADMIN_TOKEN="$(./target/release/synvoid --generatetoken)"
export SYNVOID_IPC_KEY="$(openssl rand -hex 32)"
```

The admin token must be at least 32 characters and must not contain a rejected placeholder pattern. `--generatetoken` prints a 64-character hexadecimal token. The IPC key must be 32 random bytes encoded as 64 hexadecimal characters.

Create `config/main.toml`:

```toml
[server]
host = "127.0.0.1"
port = 8080

[fallback]
mode = "return_404"

[admin]
enabled = true
port = 8081
token_env_var = "SYNVOID_ADMIN_TOKEN"

[logging]
level = "info"

[metrics]
enabled = true
port = 9090

[http]
strict_protocol_validation = true

[security]
ipc_enforce_signing = true
ipc_session_key_env = "SYNVOID_IPC_KEY"

[defaults]
[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 10
per_minute = 60

[defaults.ratelimit.global]
per_second = 500
per_minute = 5000
max_connections = 1000

[honeypot_port]
enabled = false
```

The six required top-level sections are `server`, `fallback`, `admin`, `logging`, `metrics`, and `defaults`. The other sections in this example are optional.

Create `config/sites/example.com.toml`:

```toml
[site]
domains = ["example.com", "www.example.com"]

[site.upstream]
default = "http://127.0.0.1:8000"

[attack_detection]
enabled = true
paranoia_level = 2
action = "block"
```

`--config-path` takes the directory containing `main.toml` and `sites/`, not the path to `main.toml` itself. The default is `./config/` relative to the current working directory.

## Validate and start

Run the config test from the repository root:

```bash
./target/release/synvoid --configtest --config-path ./config
```

Then start the Supervisor in the foreground:

```bash
./target/release/synvoid --foreground --config-path ./config
```

`--foreground` keeps the Supervisor attached to the terminal. Without it, the Supervisor daemonizes.

## Verify the proxy

With the upstream listening on `127.0.0.1:8000`, send a request with a browser-like user agent:

```bash
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
curl -i -A "$UA" -H "Host: example.com" http://127.0.0.1:8080/
```

A successful request returns the upstream response. The default bot scraper patterns include `curl`, so plain `curl` requests may be tarpitted instead. A host that matches no configured site receives the `[fallback]` response.

## Default endpoints

| Service | Default address | Notes |
|---|---|---|
| HTTP data plane | `127.0.0.1:8080` in this example | Configurable in `[server]` |
| Admin UI and API | `127.0.0.1:8081` | Keep restricted to a trusted management network |
| Prometheus metrics | `127.0.0.1:9090` | Non-loopback binds are rejected |

## Build profiles

The default build enables `socket-handoff, mesh, dns, erased_pool, swagger-ui`. To build the minimal WAF and proxy data plane without default features:

```bash
cargo build --release --no-default-features
```

A reduced-feature binary rejects configuration sections for capabilities it was not built to support, including `[dns]`, `[mesh]`, `[tunnel.mesh]`, and `[icmp_filter]`. Remove unsupported sections or rebuild with the required feature. See [FEATURE_STATUS.md](./FEATURE_STATUS.md) for current capability status.

## Common gotchas

- `--config-path` is a directory. It must contain `main.toml` and, when used, a `sites/` directory.
- `--configtest` checks only the selected configuration directory.
- The port honeypot is enabled by default. This example disables it; see [HONEYPOT.md](./HONEYPOT.md) to configure it.
- The shipped config writes logs under `/var/log/synvoid` and data under `/var/lib/synvoid`. Create those paths for a service install; `--configtest` rejects a missing `logging.access_log_dir`.
- The admin token and IPC key must be available in the process environment. Exporting them in a shell does not configure a system service; see [DEPLOYMENT.md](./DEPLOYMENT.md) for service configuration.
- Keep the auxiliary `synvoid-wasm-jail` and `synvoid-yara-jail` binaries beside the main binary. The Supervisor starts them when needed; do not run them manually.

## Next steps

- [CONFIGURATION.md](./CONFIGURATION.md) for the full configuration reference.
- [DEPLOYMENT.md](./DEPLOYMENT.md) for production hardening, systemd, and containers.
- [ADMIN_UI.md](./ADMIN_UI.md) and [API_REFERENCE.md](./API_REFERENCE.md) for administration.
- [FASTCGI.md](./FASTCGI.md) for PHP-FPM integration.
- [WAF_MESH.md](./WAF_MESH.md) for mesh setup.
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for common problems.
