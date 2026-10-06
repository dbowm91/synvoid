# Getting Started with SynVoid

This guide builds SynVoid, runs it in front of a real upstream, and points at the deeper configuration and operations references.

For the design rationale and performance tuning, see [ARCHITECTURE.md](./ARCHITECTURE.md) and [DEVELOPER.md](./DEVELOPER.md).

## Table of Contents

- [What is SynVoid?](#what-is-synvoid)
- [Quick Start](#quick-start)
- [Verifying it works](#verifying-it-works)
- [Practical Workflows](#practical-workflows)
  - [Protect a PHP Application](#workflow-1-protect-a-php-application)
  - [Set Up a High-Availability Mesh](#workflow-2-set-up-a-high-availability-mesh)
- [Build Profiles](#build-profiles)
- [Configuration Gotchas](#configuration-gotchas)
- [Command Line Options](#command-line-options)
- [Next Steps](#next-steps)

## What is SynVoid?

- **Unified Data Plane** — one latency-sensitive unified worker per process group, plus bounded CPU offload workers.
- **Supervisor Control Plane** — centralizes process lifecycle and control-plane state.
- **WAF Protection** — multi-layer detection against common web attacks, evaluated inline on the request path.
- **Reverse Proxy** — HTTP/1.1 and HTTP/2 upstream support, plus HTTP/3 over QUIC.
- **Application Server** — FastCGI (PHP), Python/Granian app handlers, and static files.

## Quick Start

### 1. Install build dependencies

The default feature set includes `mesh`, which runs protobuf codegen at build time. Without `protoc` the build fails with a confusing error:

```bash
# Debian/Ubuntu (what CI does); use the equivalent elsewhere.
sudo apt-get install -y protobuf-compiler
```

### 2. Build

```bash
git clone https://github.com/dbowm91/synvoid.git
cd synvoid
cargo build --release
```

The binary lands at `./target/release/synvoid`. Paths below assume that location.

### 3. Generate secrets

```bash
export SYNVOID_ADMIN_TOKEN="$(./target/release/synvoid --generatetoken)"
export SYNVOID_IPC_KEY="$(openssl rand -hex 32)"
```

The admin token must be **at least 32 characters** and must not contain obvious placeholder words such as `changeme`, `password`, or `admin`. A shorter token is rejected during config validation. `--generatetoken` emits a 64-character hex token.

### 4. Write `config/main.toml`

Six top-level sections are required because they carry no serde default: `server`, `fallback`, `admin`, `logging`, `metrics`, and `defaults`. Everything else is optional.

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

[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 10
per_minute = 60

[defaults.ratelimit.global]
per_second = 500
per_minute = 5000
max_connections = 1000
```

### 5. Add a site: `config/sites/example.com.toml`

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

### 6. Validate

```bash
./target/release/synvoid --configtest --config-path ./config
```

`--configtest` validates `<dir>/main.toml` and `<dir>/sites/*.toml`, where `<dir>` is `--config-path` when given and `./config/` relative to the current directory otherwise. A passing test covers only that directory.

### 7. Start

```bash
./target/release/synvoid --foreground --config-path ./config
```

`--foreground` keeps the Supervisor attached to your terminal; without it, the Supervisor daemonizes itself.

## Verifying it works

With an upstream listening on `127.0.0.1:8000`:

```bash
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

# Proxied to your upstream -> 200
curl -A "$UA" -H "Host: example.com" http://127.0.0.1:8080/

# SQL injection -> 403 "Attack Detected"
curl -A "$UA" -H "Host: example.com" \
  'http://127.0.0.1:8080/?id=1%20OR%201=1%20UNION%20SELECT%20u,p,3%20FROM%20users--'

# XSS -> 403
curl -A "$UA" -H "Host: example.com" \
  'http://127.0.0.1:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E'

# Host matching no site -> 404 from [fallback]
curl -A "$UA" -H "Host: nope.invalid" http://127.0.0.1:8080/

# Prometheus metrics -> 200
curl http://127.0.0.1:9090/metrics
```

Use a browser-like `User-Agent`. The default bot `scraper_patterns` include `curl`, so an unmodified `curl` is tarpitted and returns HTTP 200 with the body `Tarpit active` instead of your upstream's response.

## Practical Workflows

### Workflow 1: Protect a PHP Application

Ensure PHP-FPM is running:

```bash
systemctl status php-fpm
```

Then create `config/sites/myapp.toml`:

```toml
[site]
domains = ["myapp.local"]

[site.fastcgi]
enabled = true
socket = "/var/run/php/php-fpm.sock"

[attack_detection]
enabled = true
paranoia_level = 2
```

See [FASTCGI.md](./FASTCGI.md) for FastCGI routing and streaming options.

### Workflow 2: Set Up a High-Availability Mesh

Supervisors coordinate through Raft consensus, which is the authoritative distributed state; the DHT is advisory and is never a resolution fallback. Quorum loss surfaces as `PropagationStatus::QuorumUnavailable` rather than a silent success.

On each node in `config/main.toml`:

```toml
[mesh]
enabled = true
node_id = "node-1"   # unique per node
seeds = ["10.0.0.1:5001", "10.0.0.2:5001"]
```

Then start and check status:

```bash
./target/release/synvoid --foreground --config-path ./config
./target/release/synvoid --status
```

See [WAF_MESH.md](./WAF_MESH.md) and [THREAT_INTEL.md](./THREAT_INTEL.md).

## Build Profiles

| Command | Result |
|---|---|
| `cargo build --release` | Defaults: `socket-handoff, mesh, dns, erased_pool, swagger-ui` |
| `cargo build --release --no-default-features` | Minimal hardened profile: data plane only |
| `cargo build --release --no-default-features --features mesh` | Mesh without DNS |
| `cargo build --release --no-default-features --features dns` | DNS without mesh |

The minimal profile is a supported, continuously compiled and tested target: no mesh (DHT/Raft/gRPC), no DNS (hickory/DNSSEC), no socket-handoff FD passing, no Swagger UI. It is the right choice for single-node deployments that do not need distributed coordination or DNS serving.

A reduced-feature binary **rejects** capability-bearing sections it was not built with — `[dns]`, `[mesh]`, `[tunnel.mesh]`, `[icmp_filter]` — instead of ignoring them, and it refuses them even when they are inert (`enabled = false`). Rebuild with the named feature, or remove the unsupported section.

Defaults are deliberately left full-featured for operator compatibility. Prefer enabling only what a deployment needs rather than treating `--all-features` as a deployment profile. The complete flag list is in the root `Cargo.toml`; [FEATURE_STATUS.md](./FEATURE_STATUS.md) records which are live, beta, or unreachable.

## Configuration Gotchas

- **Rate-limit defaults are optional and correct.** `[defaults.ratelimit.ip]` used to be effectively required: omitting it resolved `per_second = 0` (a derived `Default` behind a struct-level `#[serde(default)]`) and answered every request with HTTP 429. That is fixed and pinned by `crates/synvoid-config/tests/serde_defaults_match_rust_defaults.rs`; the explicit values in the config above are good practice, not a workaround.
- **Set `[http] strict_protocol_validation = true`** unless you have a specific reason not to. With it off, the data plane accepts the connection but writes no response (observed on macOS/darwin x86_64; curl exits 56 with an empty reply).
- **A short admin token is rejected.** `admin.token` must be at least 32 characters and free of placeholder words. Prefer `token_env_var` over writing a token into `main.toml`.
- **Metrics binds loopback only.** A non-loopback `metrics.bind_address` is rejected at config load.
- **The shipped `config/main.toml` does not validate on a clean machine** — it points `logging.access_log_dir` and the persistence `data_dir` at `/var/log/synvoid` and `/var/lib/synvoid`. Create those directories, or override the paths, before running `--configtest`.
- **`--config-path` is a directory**, not a path to `main.toml`.
- **eBPF/XDP flood protection is not a working capability.** `EbpfFlood` has no construction site, `flood-ebpf` is not a default feature, and `ebpf-flood/` is not a workspace member. See [FLOOD_PROTECTION.md](./FLOOD_PROTECTION.md) for what is actually installed.

## Command Line Options

SynVoid uses flags rather than positional subcommands (see the [README](../README.md) for the full common-command table).

```bash
./target/release/synvoid                       # start Supervisor (default mode)
./target/release/synvoid --foreground          # stay attached to the terminal
./target/release/synvoid --status              # status of a running instance
./target/release/synvoid --rehash              # reload config, propagate to workers
./target/release/synvoid --restart             # stop, then start again
./target/release/synvoid --stop                # stop a running instance
./target/release/synvoid --configtest          # validate config and exit
./target/release/synvoid --config-path ./config  # DIRECTORY with main.toml + sites/
./target/release/synvoid --version
./target/release/synvoid --help                 # complete flag set
```

Internal worker and sandbox modes (`--unified-server-worker`, `--cpu-worker`, `--wasm-jail`, `--yara-jail`) are spawned by the Supervisor, not run by hand — a worker started standalone fails to reach its Supervisor and exits.

### Test Modes

`--test` requires `--force`; it is refused without it:

```bash
./target/release/synvoid --test all-off --force
```

## Next Steps

- [CONFIGURATION.md](./CONFIGURATION.md) — the full configuration reference
- [DEPLOYMENT.md](./DEPLOYMENT.md) — production deployment and hardening
- [ADMIN_UI.md](./ADMIN_UI.md) / [API_REFERENCE.md](./API_REFERENCE.md) — operator interface
- [ARCHITECTURE.md](./ARCHITECTURE.md) — how SynVoid works
- [PROCESS_MANAGEMENT.md](./PROCESS_MANAGEMENT.md) — Supervisor and worker detail
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) — common problems