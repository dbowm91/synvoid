# SynVoid

**A multi-process Web Application Firewall and reverse proxy written in Rust.**

SynVoid sits in front of web applications and services. It combines reverse proxying, streaming WAF inspection, rate limiting, bot controls, an operator admin API and UI, and feature-gated DNS and mesh services — in one Rust workspace.

Linux is the primary deployment target.

## Quick start

### 1. Prerequisites

A Rust toolchain. The default feature set includes `mesh`, which runs protobuf codegen at build time, so `protoc` is required:

```bash
# Debian/Ubuntu; use the equivalent elsewhere.
sudo apt-get install -y protobuf-compiler
```

### 2. Build

```bash
git clone https://github.com/dbowm91/synvoid.git
cd synvoid
cargo build --release
```

The binary is `./target/release/synvoid`.

### 3. Generate secrets

```bash
export SYNVOID_ADMIN_TOKEN="$(./target/release/synvoid --generatetoken)"
export SYNVOID_IPC_KEY="$(openssl rand -hex 32)"
```

The admin token must be **at least 32 characters** and must not contain obvious placeholder words; anything shorter is rejected at config validation. `--generatetoken` prints a 64-character hex token.

### 4. Write a configuration tree

`main.toml` — global policy. Six sections are required (`server`, `fallback`, `admin`, `logging`, `metrics`, `defaults`); the rest are optional:

```toml
[server]
host = "127.0.0.1"   # data plane bind address
port = 8080

[fallback]
mode = "return_404"  # response for a Host that matches no site

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

`sites/example.com.toml` — one file per site:

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

### 5. Validate before starting

```bash
./target/release/synvoid --configtest --config-path ./config
```

`--config-path` takes the **directory** holding `main.toml` and `sites/` — not the TOML file. It defaults to `./config/` relative to the current directory.

### 6. Run

```bash
./target/release/synvoid --foreground --config-path ./config
```

`--foreground` keeps the Supervisor attached to your terminal; without it the Supervisor daemonizes itself. The Supervisor starts the data-plane worker processes, which own HTTP/TLS, WAF evaluation, routing, and proxy streaming.

### 7. Verify it works

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

> **Send a browser-like `User-Agent`.** The default bot `scraper_patterns` include `curl`, so a plain `curl` is tarpitted and you will get HTTP 200 with the body `Tarpit active` instead of your upstream's response.

### Default endpoints

| Service | Default bind | Notes |
|---|---|---|
| HTTP data plane | `127.0.0.1:8080` (configurable) | The proxy/WAF listener |
| Admin UI/API | `127.0.0.1:8081` | Defaults to loopback |
| Prometheus metrics | `127.0.0.1:9090` | A non-loopback metrics bind is **rejected** at config load |

## Common commands

SynVoid uses flags, not subcommands. `synvoid --help` lists everything.

| Command | Purpose |
|---|---|
| `synvoid --foreground` | Run the Supervisor in the foreground |
| `synvoid --status` | Query a running Supervisor |
| `synvoid --rehash` | Reload config and propagate it to workers |
| `synvoid --restart` | Stop the running instance, then start again |
| `synvoid --stop` | Stop a running instance |
| `synvoid --configtest` | Validate `main.toml` and site files, then exit |
| `synvoid --generatetoken` | Print an admin token without saving it |
| `synvoid --generatenewtoken` | Generate a token and write it into `main.toml` |
| `synvoid --hash-token TOKEN` | bcrypt-hash an admin token |
| `synvoid --checkregex PATTERN` | Run the built-in ReDoS safety check |
| `synvoid --export-api-spec` | Print the admin OpenAPI spec as JSON |

The sandboxed WASM/YARA jails (`synvoid-wasm-jail`, `synvoid-yara-jail`) are separate binaries resolved beside the main executable. A release package must ship all three together.

## Build profiles

Defaults are `socket-handoff, mesh, dns, erased_pool, swagger-ui`. `--no-default-features` is the supported minimal profile (WAF/proxy data plane only). A reduced-feature binary **rejects** capability-bearing config sections it lacks — `[dns]`, `[mesh]`, `[tunnel.mesh]`, `[icmp_filter]` — rather than ignoring them, and it refuses to start on them even when they say `enabled = false`.

See [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) for build profiles and the full feature-flag inventory, and [`docs/FEATURE_STATUS.md`](docs/FEATURE_STATUS.md) for which capabilities are live, partial, or deliberately unreachable.

## Documentation

Start at [`docs/README.md`](docs/README.md) for the full index.

| I want to… | Read |
|---|---|
| Get running | [GETTING_STARTED.md](docs/GETTING_STARTED.md) |
| Configure a deployment | [CONFIGURATION.md](docs/CONFIGURATION.md) |
| Deploy to production | [DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Use the admin UI | [ADMIN_UI.md](docs/ADMIN_UI.md) |
| Call the admin API | [API_REFERENCE.md](docs/API_REFERENCE.md) |
| Understand WAF detection | [ATTACK_DETECTION.md](docs/ATTACK_DETECTION.md) |
| Understand the architecture | [ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Develop or contribute | [DEVELOPER.md](docs/DEVELOPER.md) |
| Check a capability's status | [FEATURE_STATUS.md](docs/FEATURE_STATUS.md) |
| Harden a deployment | [SECURITY.md](docs/SECURITY.md) |
| Debug a problem | [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) |

Binding design records live in [`architecture/`](architecture/overview.md); [`SECURITY.md`](SECURITY.md) covers the security policy and threat model.

## Before deploying

The configuration above is a working starting point, not a production policy.

- Keep the admin service on loopback or a restricted management network.
- Supply the admin token via `SYNVOID_ADMIN_TOKEN` or a secrets manager. `--generatenewtoken` deliberately writes the token **in plaintext** into `main.toml` (restricted to `0600` on Unix).
- Use a stable 32-byte `SYNVOID_IPC_KEY` (64 hex characters) so workers reconnect predictably across restarts.
- Treat configuration-load warnings as failures and validate before deploying.
- Linux gives the strictest sandbox isolation (Landlock). macOS Seatbelt is experimental and deprecated; Windows sandboxing is process-limits-only. See [SANDBOXING.md](docs/SANDBOXING.md).
- Authentication is CPU-isolated and fails closed: the auth store persists atomically and a corrupt store fails startup rather than starting empty.

## License

MIT. See [`LICENSE`](LICENSE).