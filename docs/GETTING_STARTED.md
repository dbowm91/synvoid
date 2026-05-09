# Getting Started with SynVoid

Welcome to SynVoid - a production-ready WAF and reverse proxy built for performance and ease of use.

## Table of Contents

- [What is SynVoid?](#what-is-synvoid)
- [Quick Start](#quick-start)
- [Practical Workflows](#practical-workflows)
  - [Protect a Simple PHP Application](#workflow-1-protect-a-simple-php-application)
  - [Deploy Python Application with Granian](#workflow-2-deploy-python-application-with-granian)
  - [Set Up HTTPS with HTTP/3](#workflow-3-set-up-https-with-http3)
  - [Configure Rate Limiting for API Protection](#workflow-4-configure-rate-limiting-for-api-protection)
  - [Set Up Bot Protection](#workflow-5-set-up-bot-protection)
  - [High Availability Setup](#workflow-6-high-availability-setup)
- [Common Use Cases](#common-use-cases)
- [Next Steps](#next-steps)
- [Getting Help](#getting-help)
- [Command Line Options](#command-line-options)

## What is SynVoid?

SynVoid is an all-in-one web application firewall and reverse proxy that provides:

- **Shared-Nothing Data Plane** - Isolated workers with `SO_REUSEPORT` and core affinity.
- **Supervisor Control Plane** - Centralized management via a gRPC API.
- **WAF Protection** - Multi-layer defense against common web attacks.
- **Reverse Proxy** - HTTP/1.1, HTTP/2, and HTTP/3 support.
- **Application Server** - Built-in support for PHP, Python, and static files.

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/synvoid/synvoid.git
cd synvoid

# Build
cargo build --release

# Run
./target/release/synvoid
```

### 2. Basic Configuration

Create a minimal `config/main.toml`:

```toml
[server]
host = "0.0.0.0"
port = 80
worker_processes = "auto"

[admin]
enabled = true
grpc_port = 50051
token = "your-secure-token-here"

[logging]
level = "info"
```

### 3. Add a Site

Create `config/sites/example.com.toml`:

```toml
[site]
domains = ["example.com", "www.example.com"]

[site.upstream]
default = "http://127.0.0.1:8000"
```

### 4. Start SynVoid

```bash
./synvoid
```

## Practical Workflows

### Workflow 1: Protect a Simple PHP Application

**Step 1: Ensure PHP-FPM is Running**
```bash
systemctl status php-fpm
```

**Step 2: Create Site Configuration**
Create `config/sites/myapp.toml`:
```toml
[site]
domains = ["myapp.local"]

[site.fastcgi]
enabled = true
socket = "/var/run/php/php-fpm.sock"
```

**Step 3: Enable WAF Protection**
```toml
[site.attack_detection]
enabled = true
paranoia_level = 2
```

### Workflow 6: High Availability Setup

SynVoid Supervisors use Raft consensus to maintain a globally synchronized state.

**Step 1: Configure Supervisor Cluster**
On each node in `config/main.toml`:
```toml
[mesh]
enabled = true
node_id = "node-1" # Unique per node
seeds = ["10.0.0.1:5001", "10.0.0.2:5001"]
```

**Step 2: Start Supervisors**
```bash
./synvoid
```

**Step 3: Verify Status via gRPC**
```bash
./synvoid status
```

## Command Line Options

### Operational Commands

SynVoid uses a gRPC-based `CommandClient` for management.

```bash
./synvoid                  # Start Supervisor (default mode)
./synvoid status           # Show status of running instance via gRPC
./synvoid reload           # Gracefully reload configuration and rotate workers
./synvoid stop             # Stop running instance
./synvoid configtest       # Validate configuration files and exit
./synvoid --foreground     # Run in foreground (don't daemonize)
```

### Test Modes

Disable specific protections for load testing:

```bash
./synvoid --test all-off --force
```

### Other Options

```bash
./synvoid --config /path/to/main.toml   # Custom config path
./synvoid --version                      # Print version
./synvoid --help                         # Print help
```

## Next Steps

- [Architecture Overview](./ARCHITECTURE.md) - Learn how SynVoid works
- [Process Management](./PROCESS_MANAGEMENT.md) - Supervisor & Worker details
- [Developer Guide](./DEVELOPER.md) - Technical deep-dive
