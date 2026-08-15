# SynVoid

**A multi-process Web Application Firewall and reverse proxy written in Rust.**

SynVoid is a security gateway for placing in front of web applications and services. It combines reverse proxying, streaming WAF inspection, rate limiting and bot controls, operator-facing administration, and feature-gated distributed services in one Rust workspace.

The default build includes the WAF/proxy data plane plus mesh networking, DNS, socket handoff, the erased HTTP client pool, and Swagger UI support. Linux is the primary deployment target; the codebase contains platform abstractions for other operating systems, but kernel-specific features and service behavior are not equivalent across platforms.

## What SynVoid provides

- **Reverse proxy and modern HTTP transport** — HTTP/1.1 and HTTP/2 handling, HTTP/3 over QUIC, TLS, upstream routing, streaming proxying, static-file delivery, FastCGI, and application-handler paths.
- **Web application firewall** — request inspection for SQL injection, XSS, path traversal, RFI, SSRF, SSTI, command injection, XXE, JWT abuse, request smuggling, LDAP injection, XPath injection, and open redirects.
- **Abuse and bot controls** — rate limiting, blocked-path rules, threat levels, CSS and proof-of-work challenges, bot classification, honeypot endpoints, tarpitting, and deception listeners.
- **Administration and observability** — a browser admin UI, authenticated REST API, WebSocket-backed live state, request/system logs, Prometheus-oriented metrics, site and upstream management, alert webhooks, and OpenAPI discovery.
- **Distributed security services** — the `mesh` feature provides DHT/Raft-backed coordination and threat-intelligence distribution. The `dns` feature provides the DNS subsystem, including DNSSEC and encrypted DNS transports.
- **Extensibility and auxiliary services** — sandboxed WASM plugins, serverless/app handlers, tunnel/VPN components, YARA integration, and bounded CPU-worker execution paths are present in the workspace and can be enabled/configured as required.

## Runtime model

A normal `synvoid` invocation starts the **Supervisor**. The Supervisor loads the selected configuration directory, owns process lifecycle and control-plane state, and starts the configured number of `UnifiedServerWorker` data-plane processes. Those workers keep connection handling, HTTP/TLS processing, WAF evaluation, routing, and proxy streaming on the request path. Dedicated CPU-worker and sandbox modes exist for work that should not run directly on the latency-sensitive path.

With the default `mesh` feature enabled, the Supervisor also owns the gRPC control API used by operational commands and mesh coordination.

## Build from source

A Rust toolchain with Cargo is required.

```bash
git clone https://github.com/dbowm91/synvoid.git
cd synvoid
cargo build --release
```

The default Cargo feature set is:

```text
socket-handoff, mesh, dns, erased_pool, swagger-ui
```

For a smaller build without default feature-gated services:

```bash
cargo build --release --no-default-features
```

Mesh-only and DNS-only examples:

```bash
cargo build --release --no-default-features --features mesh
cargo build --release --no-default-features --features dns
```

Additional opt-in feature flags currently include `wireguard`, `icmp-filter`, `flood-ebpf`, `origin_key_exchange`, `audit`, `post-quantum`, `verify-pq`, `tun-rs`, `macos-sandbox`, and `fastcgi_streaming`. See `Cargo.toml` for the complete current feature surface. Prefer enabling only the features required by a deployment rather than treating `--all-features` as a deployment profile; several opt-ins are platform- or environment-specific.

## Quick start

The repository contains a working configuration tree under `config/`. Before starting SynVoid, review `config/main.toml` and the files in `config/sites/`: the tracked configuration binds the public data plane to `0.0.0.0:8080` and includes Linux-oriented logging/persistence settings and example sites.

Generate an admin token and a stable IPC signing key for the current shell:

```bash
export SYNVOID_ADMIN_TOKEN="$(./target/release/synvoid --generatetoken)"
export SYNVOID_IPC_KEY="$(openssl rand -hex 32)"
```

Then start the Supervisor in the foreground:

```bash
./target/release/synvoid --foreground
```

`--foreground` is recommended while testing or running under an external service manager. Without it, the normal Supervisor path daemonizes itself.

With the tracked configuration and source defaults, the principal local endpoints are:

| Service | Default/Example endpoint | Notes |
|---|---|---|
| HTTP data plane | `0.0.0.0:8080` | From `config/main.toml`; change for your deployment |
| Admin UI/API | `127.0.0.1:8081` | Admin bind defaults to loopback |
| Metrics | port `9090` | When metrics are enabled |

To use another configuration tree, pass the **directory** containing `main.toml` and `sites/`:

```bash
./target/release/synvoid --foreground --config-path /etc/synvoid
```

`--config-path` is a directory path, not a path to `main.toml` itself.

## Configure a protected site

Per-site TOML files live under `config/sites/`. A minimal reverse-proxy site looks like this:

```toml
[site]
domains = ["example.com", "www.example.com"]

[site.upstream]
default = "http://127.0.0.1:3000"
```

Global defaults in `main.toml` supply WAF, rate-limit, bot, challenge, worker-pool, persistence, and other policy unless a site overrides them. The repository ships example site files; replace or remove them when preparing a real deployment.

See `config/main.toml.example`, `config/sites/example.com.toml`, and `docs/CONFIGURATION.md` for the broader configuration surface.

## Admin UI and API

The admin service is enabled by the tracked configuration and defaults to `127.0.0.1:8081`. Browser login exchanges the configured admin bearer token for an HttpOnly session cookie; subsequent browser mutations use CSRF protection rather than persisting the long-lived bearer token in browser storage.

The source tree includes built browser assets in `admin-ui/dist`. At runtime SynVoid resolves the admin UI assets in this order:

1. `SYNVOID_ADMIN_UI_DIR`
2. `admin-ui/dist` beside the running executable
3. `admin-ui/dist` under the compile-time repository root
4. `./admin-ui/dist` relative to the current working directory

If you install or copy only the binary, also install the admin UI assets or set `SYNVOID_ADMIN_UI_DIR` to their location.

The API specification can be exported without starting the server:

```bash
./target/release/synvoid --export-api-spec > synvoid-admin-openapi.json
```

See `docs/ADMIN_UI.md` and `docs/API_REFERENCE.md` for the operator interface and API details.

## Operational CLI

SynVoid currently uses flags rather than positional subcommands. Common operations are:

| Command | Purpose |
|---|---|
| `synvoid --status` | Query a running Supervisor |
| `synvoid --rehash` | Reload configuration and propagate it to workers |
| `synvoid --restart` | Stop the running instance, then launch the Supervisor again |
| `synvoid --stop` | Stop a running instance |
| `synvoid --configtest` | Validate `main.toml` and site TOML files |
| `synvoid --generatetoken` | Generate and print an admin token without saving it |
| `synvoid --generatenewtoken` | Generate an admin token and write it into `main.toml` |
| `synvoid --hash-token TOKEN` | Generate a bcrypt hash for an admin token |
| `synvoid --checkregex PATTERN` | Run the built-in ReDoS safety check against a regex |
| `synvoid --export-api-spec` | Print the admin OpenAPI specification as JSON |
| `synvoid --genesis` | Generate a mesh genesis key (`mesh` build required) |
| `synvoid --show-node-info` | Show mesh node identity information (`mesh` build required) |

Use `synvoid --help` for the complete current flag set, including internal worker/sandbox modes and control-API overrides.

### Configuration-test path caveat

The current `--configtest` implementation validates `./config/main.toml` and `./config/sites/*.toml` relative to the current working directory. It does **not** currently redirect that validation with `--config-path`. Run it from the intended configuration root/layout and do not assume a successful test covered another directory.

## Security and deployment notes

The shipped configuration is a starting point, not a universal production policy. In particular:

- Keep the admin service on loopback or a restricted management network unless you have deliberately secured remote access.
- Prefer `SYNVOID_ADMIN_TOKEN` or another secrets-management mechanism over committing an admin token. `--generatenewtoken` intentionally stores the generated token in plaintext in `main.toml` (and restricts the file to mode `0600` on Unix where possible).
- The tracked config enables signed IPC and names `SYNVOID_IPC_KEY` as the session-key environment variable. Use a stable 32-byte key encoded as 64 hexadecimal characters when workers must survive/reconnect predictably across restarts.
- Supervisor startup currently logs a warning and falls back to built-in defaults if `main.toml` cannot be loaded. Treat configuration-load warnings as operational failures and validate configuration before deployment.
- Linux provides the broadest networking/kernel feature coverage. Features such as eBPF filtering and some service/runtime integrations have additional OS, privilege, or kernel requirements.
- Restrict admin and metrics exposure with host firewalling or equivalent network policy. Do not expose management surfaces merely because the data plane is internet-facing.

## Documentation

Useful user/operator references include:

- [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) — full configuration reference
- [`docs/ADMIN_UI.md`](docs/ADMIN_UI.md) — browser administration
- [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) — admin API
- [`docs/ATTACK_DETECTION.md`](docs/ATTACK_DETECTION.md) — WAF detection behavior
- [`docs/BOT_PROTECTION.md`](docs/BOT_PROTECTION.md) — bot controls and challenges
- [`docs/HTTP3.md`](docs/HTTP3.md) — HTTP/3/QUIC
- [`docs/HONEYPOT.md`](docs/HONEYPOT.md) — deception listeners and storage
- [`docs/TARPIT.md`](docs/TARPIT.md) — anti-scraping tarpit behavior
- [`docs/TUNNELS.md`](docs/TUNNELS.md) — tunnel routing
- [`SECURITY.md`](SECURITY.md) — security policy and model
- [`CHANGELOG.md`](CHANGELOG.md) — notable changes

Internal architecture records and implementation plans remain in `architecture/` and `plans/`; they are development artifacts rather than the primary user documentation.

## License

SynVoid is licensed under the MIT License. See [`LICENSE`](LICENSE).
