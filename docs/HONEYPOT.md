# SynVoid Port Honeypot — Operator Guide

The port honeypot is a deception layer that deploys fake service endpoints to detect and study attacker behavior in real time. It catches scanners, credential stuffers, exploit attempts, and lateral movement by presenting realistic-looking services that log every interaction.

The honeypot operates alongside the WAF and proxy, feeding intelligence to the mesh for cross-node correlation.

## Table of Contents

1. [Overview](#1-overview)
2. [Enabling the Honeypot](#2-enabling-the-honeypot)
3. [Port Configuration](#3-port-configuration)
4. [Connection Handling](#4-connection-handling)
5. [Protocol Detection](#5-protocol-detection)
6. [Response Modes](#6-response-modes)
7. [AI Responder (Experimental)](#7-ai-responder-experimental)
8. [Storage and Retention](#8-storage-and-retention)
9. [Storage Writer and Backpressure](#9-storage-writer-and-backpressure)
10. [Payload Retention Modes](#10-payload-retention-modes)
11. [Threat Intelligence and Scoring](#11-threat-intelligence-and-scoring)
12. [Mesh Propagation](#12-mesh-propagation)
13. [Metrics Reference](#13-metrics-reference)
14. [Configuration Reference](#14-configuration-reference)
15. [Security Considerations](#15-security-considerations)

---

## 1. Overview

SynVoid's port honeypot is a deception layer that deploys fake service endpoints to detect and study attacker behavior. It works by:

- **Catching scanners** — Port scanners and service enumeration tools hit the honeypot and reveal their methodology.
- **Catching credential stuffers** — Brute-force attempts against fake SSH, MySQL, Redis, and other services are logged and scored.
- **Catching exploit attempts** — SQL injection, command injection, path traversal, and other attack payloads are detected and classified.
- **Catching lateral movement** — Internal hosts probing other services trigger alerts.

The honeypot operates alongside the WAF and proxy, feeding intelligence to the mesh network for cross-node correlation and coordinated defense.

### What it is NOT

- The honeypot is **not** a production service. It does not serve real traffic or store real data.
- The honeypot is **not** a replacement for the WAF. It complements the WAF by catching traffic that slips past or never reaches the WAF.
- The honeypot is **not** an enforcement point by default. It observes and scores; enforcement (blocking) requires explicit opt-in via threat-intel thresholds.

---

## 2. Enabling the Honeypot

The honeypot is **disabled by default**. No ports are opened, no resources consumed, until you explicitly enable it.

```toml
[honeypot_port]
enabled = true
bind_address = "0.0.0.0"   # All interfaces (default)
```

When `enabled = false` (the default), the entire honeypot subsystem is skipped during startup. No storage database is created, no listeners are bound, and no background tasks are spawned.

### Bind address

| Setting | Default | Description |
|---------|---------|-------------|
| `bind_address` | `0.0.0.0` | IP address to bind honeypot listeners to |

Binding to `0.0.0.0` exposes the honeypot on all network interfaces. For internal-only deception, bind to a specific interface or `127.0.0.1`.

> **Note:** Honeypot ports are completely separate from production service ports. The honeypot will never bind to a port already in use by another service.

---

## 3. Port Configuration

The honeypot uses a range-based port selection system with configurable rotation to make port enumeration harder for attackers.

### Port range and count

| Setting | Default | Description |
|---------|---------|-------------|
| `min_port` | `10000` | Start of the port range |
| `max_port` | `60000` | End of the port range |
| `num_honeypot_ports` | `3` | Number of simultaneous fake ports |

Ports are selected randomly from within the range `[min_port, max_port]`. The number of simultaneously active ports is controlled by `num_honeypot_ports`.

### Port rotation

| Setting | Default | Description |
|---------|---------|-------------|
| `min_rotation_interval_secs` | `600` (10 min) | Minimum time before rotating ports |
| `max_rotation_interval_secs` | `3600` (1 hour) | Maximum time before rotating ports |
| `rotation_interval_secs` | `1800` (30 min) | Fixed rotation interval (if used) |

The actual rotation interval is randomized between `min_rotation_interval_secs` and `max_rotation_interval_secs` on each rotation cycle. This prevents attackers from predicting when a port will change.

### Stable ports

You can pin specific ports to specific services using `stable_ports`:

```toml
[[honeypot_port.stable_ports]]
port = 10022
service = "ssh"
responder = "vulnerable"

[[honeypot_port.stable_ports]]
port = 103306
service = "mysql"
responder = "template"
```

Stable ports are **not rotated** and always serve the specified service. Use this for predictable deception on known scanner targets.

### Default services (11)

The honeypot ships with 11 pre-configured service banners:

| Service | Protocol | Ports | Banner |
|---------|----------|-------|--------|
| HTTP | `http` | 80, 8080, 8888 | `Apache/2.4.41` response |
| HTTPS | `tls` | 443, 8443 | TLS ServerHello |
| SSH | `ssh` | 22, 2222 | `OpenSSH_8.9p1` banner |
| MySQL | `mysql` | 3306 | Protocol v10 greeting |
| Redis | `redis` | 6379 | `+OK` RESP |
| FTP | `ftp` | 21 | `vsFTPd 3.0.3` banner |
| PostgreSQL | `postgresql` | 5432, 5433 | SSLRequest packet |
| SMB | `smb` | 139, 445 | SMB marker |
| RDP | `rdp` | 3389 | TPKT header |
| VNC | `vnc` | 5900, 5901, 5902 | `RFB 003.008` |
| SMTP | `smtp` | 25, 465, 587 | `ESMTP Postfix` banner |

Custom services can be added via the `services` config array.

---

## 4. Connection Handling

The honeypot enforces strict resource limits to prevent abuse and protect the host system.

### Concurrency limits

| Setting | Default | Description |
|---------|---------|-------------|
| `max_concurrent_connections` | `256` | Global concurrent connection limit (semaphore) |
| `max_connections_per_ip` | `10` | Per-IP concurrent connection limit |

The global limit uses a Tokio semaphore. When the semaphore is exhausted, new connections are immediately rejected and counted via `honeypot_connections_rejected_global_limit`.

Per-IP tracking uses an RAII guard (`IpConnGuard`). The guard increments the per-IP count on connection and decrements it (removing the entry when zero) on drop. This ensures accurate tracking even if connections terminate unexpectedly.

### Timeouts

| Setting | Default | Description |
|---------|---------|-------------|
| `connection_timeout_ms` | `5000` (5 sec) | Timeout for the initial read after connection |
| `read_timeout_ms` | `10000` (10 sec) | Timeout for subsequent reads |

The initial read timeout determines how long to wait for the attacker to send their first data. If no data arrives within `connection_timeout_ms`, the connection is closed and counted via `honeypot_connections_timed_out_initial`.

Subsequent reads use `read_timeout_ms`. If no additional data arrives within this window, the connection is logged and closed.

### Payload capture

| Setting | Default | Description |
|---------|---------|-------------|
| `max_payload_size` | `8192` bytes | Maximum bytes captured per connection |

Payloads exceeding `max_payload_size` are truncated. The `payload_truncated` flag is set on the record, and a penalty is applied during threat-intel scoring.

---

## 5. Protocol Detection

The honeypot automatically detects the protocol of incoming connections by inspecting the initial payload. Detection is binary-safe (no UTF-8 dependency for binary protocols) and runs in two phases:

1. **Binary fixed-prefix checks** — Magic bytes, record headers, protocol markers
2. **Text protocol checks** — Method verbs, command prefixes, banner patterns

### Supported protocols (15+)

| Protocol | Confidence | Detection Method |
|----------|-----------|-----------------|
| TLS/SSL | **High** | Record header `0x16 0x03` with valid version |
| SSH | **High** | `SSH-` banner prefix |
| VNC | **High** | `RFB ` banner prefix |
| SMB | **High** | `\xffSMB` or `\xfeSMB` marker |
| PostgreSQL | **High** | SSLRequest packet (`0x00 0x00 0x00 0x08 0x04 0xd2`) |
| HTTP | **High** | Method verb (`GET`, `POST`, etc.) with request-line syntax |
| SMTP | **High** | `EHLO`/`HELO` command, `MAIL FROM:`, or `220` banner with ESMTP |
| FTP | **High** | `USER`/`PASS` command or `220` banner with FTP |
| POP3 | **High** | `+OK` response prefix |
| MySQL | **Medium** | Protocol v10 handshake (`0x0a` first byte) |
| Redis | **High/Medium** | RESP array prefix (`*N\r\n`) or inline commands (`PING`, `SET`, `GET`) |
| MongoDB | **Medium/Low** | `opmsg` header or JSON `ismaster` wire protocol |
| RDP | **Low** | TPKT header (`0x03 0x00`) |
| DNS | **Low** | Standard query header shape (12-byte, QR=0, QDCOUNT=1) |

### Confidence levels

| Level | Meaning | Impact on scoring |
|-------|---------|------------------|
| **High** | Strong magic/prefix (SSH banner, TLS header, HTTP method) | Full severity, no cap |
| **Medium** | Recognizable text command with common protocol token | Critical capped to High |
| **Low** | Weak shape-only binary checks | All Critical/High capped to Medium |

Confidence levels directly affect threat-intel scoring. A Low-confidence detection of an SSH brute-force will score lower than a High-confidence detection of the same activity.

### Banner lookup

After detection, the protocol identifier is mapped to a service banner via a static lookup table. The banner is sent to the attacker to continue the deception. The banner map includes protocol-appropriate response patterns for multi-step protocols (e.g., FTP `USER` → `331 Please specify the password`, FTP `PASS` → `530 Login authentication failed`).

---

## 6. Response Modes

The honeypot supports multiple response strategies, selected via the `response_mode` config.

### Mode: `cycling` (default)

Rotates through available responders on each connection. This provides variety and makes fingerprinting the honeypot harder.

### Responder types

#### VulnerableApp (default `responder_type`)

Stateful multi-step interaction simulating realistic login flows, command execution, and data exfiltration. This is the most realistic deception mode and is designed to engage attackers in extended sessions.

- Simulates multi-step authentication flows
- Provides realistic command output
- Tracks session state across reads
- Feeds detailed interaction data to threat-intel scoring

#### TemplateResponder

Deterministic, zero-external-calls responses. Pre-built per service with no dynamic behavior. Useful for:

- Low-overhead deception
- Environments where AI/AI providers are not available
- Services that only need a banner exchange

Template responders are created for: `ssh`, `http`, `mysql`, `redis`, `postgresql`, `ftp`, `smtp`.

#### StaticResponder

Pattern-matching with banner + response patterns. Responds to specific attacker input patterns with pre-configured responses. Defined per-service in the `response_patterns` config.

#### AI Responder

Uses an external or local AI provider to generate dynamic, context-aware responses. See [Section 7: AI Responder](#7-ai-responder-experimental) for details.

### Response type classification

| Type | Description |
|------|-------------|
| `Static` | Pre-configured banner or pattern response |
| `Dynamic` | Stateful multi-step interaction |
| `AiGenerated` | AI provider-generated response |
| `VulnerableApp` | Realistic vulnerable application simulation |

---

## 7. AI Responder (Experimental)

The AI responder uses external or local AI providers to generate dynamic, context-aware responses that adapt to attacker input in real time.

> **Default mode: `Disabled`** — AI is off unless explicitly enabled. No external calls are made, no provider credentials are required.

### AI modes

| Mode | Description | External calls |
|------|-------------|---------------|
| `Disabled` | No AI responses; template/vulnerable-app only | None |
| `TemplateOnly` | Deterministic protocol banners, no external calls | None |
| `LocalModelOnly` | Local model (e.g., Ollama) with strict budgets | Local only |
| `ExternalProvider` | External API (OpenAI/Anthropic) — **experimental** | Yes |

### Configuration

```toml
[[honeypot_port.ai_config]]
mode = "disabled"           # Disabled, TemplateOnly, LocalModelOnly, ExternalProvider
provider = "ollama"         # "ollama", "openai", or "anthropic"
endpoint = "http://localhost:11434"
api_key = ""                # Required for ExternalProvider
model = "llama3"
timeout_secs = 30
```

### Budget limits

Hard budgets prevent unbounded cost, prompt injection amplification, and provider abuse:

| Budget | Default | Description |
|--------|---------|-------------|
| `max_prompt_bytes` | 4096 | Maximum bytes sent to provider |
| `max_response_bytes` | 2048 | Maximum bytes retained from provider |
| `max_generation_duration_secs` | 10 | Timeout per generation |
| `max_turns_per_connection` | 5 | Maximum AI turns per connection |
| `max_concurrent_requests` | 4 | Maximum concurrent AI requests globally |
| `max_provider_failures` | 3 | Consecutive failures before circuit breaker opens |

### Circuit breaker

The circuit breaker protects against provider outages:

- Opens after `max_provider_failures` (default 3) consecutive failures
- 60-second cooldown before retry
- When open, connections receive fallback responses instead of calling the provider
- Success resets the failure counter

### Concurrency limiter

A semaphore-based limiter enforces `max_concurrent_requests`. When at capacity, new AI requests are rejected and fall back to template responses.

### Turn counter

Each connection gets a per-connection turn counter. After `max_turns_per_connection` AI interactions, the connection falls back to static responses for the remainder.

### Error fallback

On any provider error (timeout, API failure, budget exceeded), the AI responder returns a **protocol-specific static fallback**. Error details are **never** leaked to the attacker or to logs in a way that could be useful to them.

### Security

- System prompts include `[SYSTEM — HONEYPOT SIMULATION]` header
- Explicit `[CONTAINMENT]` blocks instruct the model it is a simulation
- Prompt injection resistance: attempts to override the simulation are ignored
- "NO real" disclaimers prevent the model from providing actual credentials or access
- Provider errors never leak to attacker connections

### AI output is NOT an authoritative block signal

AI-generated responses feed the threat-intel scoring pipeline. They are **not** used as direct enforcement signals for blocking. The scoring system applies confidence weighting and thresholds before any action is taken.

---

## 8. Storage and Retention

Honeypot connection records are stored in a local SQLite database.

### Database configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `database_path` | `/var/lib/synvoid/honeypot.db` | SQLite database path |
| `max_records` | `1,000,000` | Maximum records (oldest deleted when exceeded) |
| `retention_days` | `90` | Days before records are pruned |
| `flush_interval_secs` | `60` | Pruning check interval |

### SQLite PRAGMAs

The database is configured for write-heavy workloads:

```sql
PRAGMA journal_mode = WAL;       -- Write-Ahead Logging for concurrent reads
PRAGMA synchronous = NORMAL;     -- Balanced durability/performance
PRAGMA cache_size = -64000;      -- 64 MB page cache
PRAGMA temp_store = MEMORY;      -- Temp tables in memory
PRAGMA mmap_size = 268435456;    -- 256 MB memory-mapped I/O
```

### Record lifecycle

1. **Pruning**: Runs hourly. Records older than `retention_days` are deleted.
2. **Max records enforcement**: Runs hourly. If total records exceed `max_records`, the oldest records are deleted until within limit.

### Schema

The `honeypot_connections` table stores:

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-incrementing primary key |
| `timestamp` | INTEGER | Unix timestamp of connection |
| `remote_ip` | TEXT | Attacker IP address |
| `remote_port` | INTEGER | Attacker source port |
| `local_port` | INTEGER | Honeypot port hit |
| `protocol` | TEXT | Detected protocol identifier |
| `service` | TEXT | Detected service name |
| `confidence` | TEXT | Detection confidence level |
| `payload` | BLOB | Captured payload bytes |
| `payload_hex` | TEXT | Hex-encoded payload |
| `detected_pattern` | TEXT | Detection evidence field |
| `bytes_received` | INTEGER | Total bytes received |
| `bytes_sent` | INTEGER | Total bytes sent |
| `duration_ms` | INTEGER | Connection duration |
| `connection_info` | TEXT | `ip:port` string |
| `payload_truncated` | INTEGER | Whether payload was truncated |
| `payload_hash` | TEXT | SHA-256 hash of original payload |
| `payload_length` | INTEGER | Original payload length (before truncation) |

Indexes exist on `timestamp`, `remote_ip`, and `service`.

---

## 9. Storage Writer and Backpressure

The honeypot uses an async bounded channel between listener tasks and a background SQLite batch writer. This decouples connection handling from storage I/O.

### Writer configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `queue_capacity` | `4096` | Bounded channel capacity (records) |
| `batch_size` | `64` | Records per flush batch |
| `flush_interval_ms` | `1000` | Time-based flush interval |
| `write_timeout_ms` | `500` | Per-write timeout |

### Pipeline

```
Listener task → try_write_record() → [bounded channel] → writer_task → batch INSERT
```

1. **Listener tasks** call `try_write_record()` which is **non-blocking** (`try_send`).
2. If the channel is full, the record is **dropped** and counted via `honeypot_storage_drops`.
3. The background `writer_task` drains the channel into a batch buffer.
4. When the batch reaches `batch_size` or `flush_interval_ms` elapses, the batch is flushed to SQLite in a single transaction.

### Backpressure behavior

- **Non-blocking writes**: `try_write_record` never blocks the listener. If the queue is full, records are dropped.
- **Drop counting**: Dropped records are counted via the `honeypot_storage_drops` metric. Monitor this metric to detect storage lag.
- **Error counting**: SQLite write failures are counted via `honeypot_storage_write_errors`.

### Shutdown

On shutdown, the writer drains any remaining records in the channel before closing the database connection.

---

## 10. Payload Retention Modes

The honeypot supports four payload retention modes, controlling how much of the attacker's payload is stored.

### Modes

| Mode | Description | Storage cost |
|------|-------------|-------------|
| `None` | No payload stored; only metadata | Minimal |
| `HashOnly` | SHA-256 hash stored; payload discarded | Low |
| `Truncated` (default) | Payload truncated to 256 bytes; hex to 512 bytes; SHA-256 always computed | Medium |
| `Full` | Entire payload stored with hash | High |

### Configuration

```toml
[honeypot_port.storage.writer]
payload_retention_mode = "truncated"
max_stored_payload_bytes = 256      # Truncation limit for binary payload
max_stored_payload_hex_bytes = 512  # Truncation limit for hex payload
```

### Behavior details

- **`None`**: `payload` and `payload_hex` are cleared. `payload_hash` is set (SHA-256 of original). `payload_length` records original size.
- **`HashOnly`**: Same as `None` but the hash is the primary identifier. Useful for deduplication.
- **`Truncated`**: Payload is truncated to `max_stored_payload_bytes`. Hex is truncated to `max_stored_payload_hex_bytes`. Hash and original length are always computed.
- **`Full`**: No truncation. Hash and length are still computed.

### Important notes

- **Raw payload storage is NOT enabled by default.** The default `Truncated` mode stores at most 256 bytes.
- `payload_length` always records the original size, regardless of retention mode. This is used for scoring (larger payloads may indicate more sophisticated attacks).
- SHA-256 hashes are always computed and stored, regardless of mode.

---

## 11. Threat Intelligence and Scoring

The honeypot extracts threat indicators from connection records and scores them using a bounded model.

### Signal classes

| Signal class | Base score | Description |
|-------------|-----------|-------------|
| `ProtocolProbe` | 0.1 | Simple connection with no attack payload |
| `ScannerFingerprint` | 0.3 | Connection matching known scanner patterns |
| `KnownAttackPattern` | 0.5 | Recognized attack pattern in payload |
| `CredentialAttempt` | 0.6 | Login attempt against a service |
| `ExploitPayload` | 0.7 | Exploit code or command injection detected |
| `MalwareCorrelation` | 0.7 | Payload matching known malware signatures |

### Attack pattern detection

The extractor uses regex-based detection for:

- SQL Injection (`SELECT ... FROM`)
- XSS (`<script>`, `javascript:`)
- Path Traversal (`../`, `..\`)
- Local File Inclusion (`/etc/passwd`, `/etc/shadow`)
- Remote Code Execution (`wget`, `curl`, `nc` with HTTP URLs)
- Shell Command Injection (`bash -i`, `sh -c`)
- PHP Exploitation (`<?php`, `phpinfo`)
- WordPress Attacks (`/wp-admin`, `/wp-login.php`)
- Admin Panel Probes (`/admin/login`, `/administrator`)
- Version Control Leaks (`/.git/`, `/.svn/HEAD`)
- AWS Credential Theft (`aws_access_key`, `secret_access_key`)
- Redis Attacks (`redis config set`)
- MongoDB Attacks (`mongo.*db`)

### Confidence levels

| Level | Multiplier | Description |
|-------|-----------|-------------|
| `High` | 1.0× | Strong protocol signature detected |
| `Medium` | 0.8× | Recognizable but not definitive |
| `Low` | 0.5× | Weak signal, shape-only |

### Severity capping by confidence

| Confidence | Severity cap |
|-----------|-------------|
| Low | Critical/High → Medium |
| Medium | Critical → High |
| High | No cap |

### Score computation

```
score = base_score × confidence_multiplier
      + repeat_bonus (capped at 0.3)
      + port_diversity_bonus (capped at 0.2)
      + attack_pattern_bonus (capped at 0.3)
      - truncation_penalty (0.2, if payload truncated)

score = clamp(score, 0.0, 1.0)
```

### Bonus breakdown

| Bonus | Factor | Max | Description |
|-------|--------|-----|-------------|
| Repeat | 0.1 per event | 0.3 | Diminishing returns per additional event |
| Port diversity | 0.05 per distinct port | 0.2 | More ports = higher score |
| Attack pattern | 0.1 per pattern | 0.3 | More distinct patterns = higher score |
| Truncation penalty | -0.2 | — | Applied when payload was truncated |

### Action classes

| Action class | Score threshold | Description |
|-------------|----------------|-------------|
| `Observe` | < 0.3 | Telemetry only, no action |
| `LocalRateLimitCandidate` | ≥ 0.3 | Consider rate limiting |
| `LocalBlockCandidate` | ≥ 0.6 | Consider local block |
| `MeshShareCandidate` | ≥ 0.75 | Consider sharing with mesh |
| `MeshBlockCandidate` | ≥ 0.9 | Consider mesh-wide block |

### Time decay

Scores decay exponentially with a 1-hour half-life:

```
decayed_score = score × 0.5^(elapsed_secs / 3600)
```

After 1 hour, a score is halved. After 2 hours, quartered. This prevents stale events from driving action indefinitely.

### Dedupe keys

Dedupe keys use the format `"{IndicatorType}:{value}"` (e.g., `SourceIp:10.0.0.1`, `AttackPattern:SQLi`). Published indicators are tracked to prevent duplicate mesh announcements.

### Important: Low-confidence events

**Low-confidence single events are telemetry by default, not block events.** The scoring model ensures that a single Low-confidence probe scores 0.05 — well below any action threshold. Multiple events, higher confidence, or diverse attack patterns are required to escalate to action classes.

---

## 12. Mesh Propagation

Mesh propagation shares threat indicators with other SynVoid nodes in the mesh network for coordinated defense.

### Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `mesh_enabled` | `false` | Enable mesh propagation |
| `min_confidence_for_mesh` | `Medium` | Minimum confidence to propagate |
| `min_events_for_mesh` | `3` | Minimum events before propagation |
| `mesh_ttl_secs` | `86400` (24 hours) | Time-to-live for mesh indicators |

### Requirements for mesh propagation

An indicator must satisfy ALL of the following to be published to the mesh:

1. **Action class**: Must be `MeshShareCandidate` or `MeshBlockCandidate` (score ≥ 0.75)
2. **Minimum confidence**: `Medium` or higher
3. **Minimum events**: At least 3 events from the same source
4. **Dedupe key**: Must have a valid dedupe key (`{IndicatorType}:{value}`)
5. **Not previously announced**: The dedupe key must not exist in the `honeypot_announced_indicators` table

### Publishing mechanism

The mesh publisher uses cursor-based polling from storage:

1. A background task reads records since the last published timestamp (`mesh_publish_cursor` metadata key).
2. For each record, indicators are extracted and scored.
3. Indicators meeting propagation requirements are published via `ThreatIntelligenceManager::announce_honeypot_indicator()`.
4. The cursor is advanced to the latest processed timestamp.
5. Published indicator keys are persisted to prevent duplicate announcements.

### Metadata minimization

Only the **payload hash** (SHA-256) is propagated to the mesh, never raw payload bytes. This prevents sensitive data leakage across nodes while still enabling correlation.

### Mesh TTL

Mesh indicators expire after `mesh_ttl_secs` (default 24 hours). This prevents indefinite propagation of stale indicators.

---

## 13. Metrics Reference

All metrics use the `honeypot_` prefix and are emitted via the `metrics` crate.

### Connection metrics

| Metric | Type | Description |
|--------|------|-------------|
| `honeypot_connections_accepted` | counter | Connections accepted by the honeypot |
| `honeypot_connections_rejected_global_limit` | counter | Rejected by global semaphore (max concurrent) |
| `honeypot_connections_rejected_per_ip_limit` | counter | Rejected by per-IP limit |
| `honeypot_connections_timed_out_initial` | counter | Initial read timed out (no data received) |
| `honeypot_connections_timed_out_read` | counter | Subsequent read timed out |
| `honeypot_handler_errors` | counter | Handler read errors (I/O failures) |
| `honeypot_payload_truncated` | counter | Payload exceeded max_payload_size |

### Storage metrics

| Metric | Type | Description |
|--------|------|-------------|
| `honeypot_storage_drops` | counter | Records dropped due to full queue |
| `honeypot_storage_write_errors` | counter | SQLite write failures |

### AI metrics

| Metric | Type | Description |
|--------|------|-------------|
| `honeypot_ai_turns_exceeded` | counter | AI turn budget exhausted for connection |
| `honeypot_ai_responses_success` | counter | AI provider returned a successful response |
| `honeypot_ai_responses_fallback` | counter | AI provider error, fallback response sent |

### Monitoring recommendations

- **`honeypot_storage_drops`**: Alert if non-zero. Indicates the storage writer cannot keep up with connection volume. Consider increasing `queue_capacity` or investigating storage I/O.
- **`honeypot_connections_rejected_global_limit`**: Monitor for capacity planning. Sustained rejections indicate the need to increase `max_concurrent_connections`.
- **`honeypot_ai_responses_fallback`**: Alert if ratio exceeds 50% of total AI responses. Indicates provider instability.

---

## 14. Configuration Reference

Full TOML example with all fields and their defaults:

```toml
# =============================================================================
# PORT HONEYPOT
# =============================================================================

[honeypot_port]
# Enable the honeypot (default: false)
enabled = false

# Bind address for honeypot listeners (default: "0.0.0.0")
bind_address = "0.0.0.0"

# Port range for random selection (default: 10000-60000)
min_port = 10000
max_port = 60000

# Number of simultaneous honeypot ports (default: 3)
num_honeypot_ports = 3

# Port rotation intervals (default: 600-3600 seconds)
min_rotation_interval_secs = 600
max_rotation_interval_secs = 3600
rotation_interval_secs = 1800

# Connection limits (defaults: 256 global, 10 per-IP)
max_concurrent_connections = 256
max_connections_per_ip = 10

# Timeouts (defaults: 5000ms initial, 10000ms read)
connection_timeout_ms = 5000
read_timeout_ms = 10000

# Maximum payload captured per connection (default: 8192 bytes)
max_payload_size = 8192

# Site scope for mesh propagation (default: "global")
site_scope = "global"

# Stable ports — pin specific ports to specific services
# [[honeypot_port.stable_ports]]
# port = 10022
# service = "ssh"
# responder = "vulnerable"

# Response mode (default: cycling with vulnerable responder)
[honeypot_port.response_mode]
mode = "cycling"
responder_type = "vulnerable"

# Storage configuration
[honeypot_port.storage]
database_path = "/var/lib/synvoid/honeypot.db"
max_records = 1000000
retention_days = 90
flush_interval_secs = 60

# Async writer pipeline
[honeypot_port.storage.writer]
queue_capacity = 4096
batch_size = 64
flush_interval_ms = 1000
write_timeout_ms = 500
payload_retention_mode = "truncated"  # None, HashOnly, Truncated, Full
max_stored_payload_bytes = 256
max_stored_payload_hex_bytes = 512

# AI responder (experimental, disabled by default)
# [[honeypot_port.ai_config]]
# mode = "disabled"              # Disabled, TemplateOnly, LocalModelOnly, ExternalProvider
# provider = "ollama"            # ollama, openai, anthropic
# endpoint = "http://localhost:11434"
# api_key = ""
# model = "llama3"
# timeout_secs = 30
# system_prompt = ""

# AI budget limits
# [honeypot_port.ai_config.budget]
# max_prompt_bytes = 4096
# max_response_bytes = 2048
# max_generation_duration_secs = 10
# max_turns_per_connection = 5
# max_concurrent_requests = 4
# max_provider_failures = 3

# Threat intelligence
[honeypot_port.threat_intel]
enabled = true
mesh_enabled = false

# Scoring configuration
[honeypot_port.threat_intel.scoring]
base_score_protocol_probe = 0.1
base_score_attack_pattern = 0.5
base_score_exploit_payload = 0.7
base_score_credential_attempt = 0.6
base_score_scanner_fingerprint = 0.3
repeat_bonus_factor = 0.1
repeat_max_bonus = 0.3
distinct_port_bonus = 0.05
distinct_port_max_bonus = 0.2
attack_pattern_bonus = 0.1
attack_pattern_max_bonus = 0.3
truncation_penalty = 0.2
decay_half_life_secs = 3600
threshold_rate_limit = 0.3
threshold_local_block = 0.6
threshold_mesh_share = 0.75
threshold_mesh_block = 0.9
min_events_for_mesh = 3
min_confidence_for_mesh = "medium"
mesh_ttl_secs = 86400
```

---

## 15. Security Considerations

### Port isolation

- Honeypot ports are **completely separate** from production services.
- The honeypot will never bind to a port already in use.
- Honeypot ports do not appear in service discovery or health checks.

### AI containment

- AI responses never contain real credentials, access tokens, or production data.
- System prompts enforce `[SYSTEM — HONEYPOT SIMULATION]` with explicit containment blocks.
- Prompt injection attacks are resisted: override attempts are ignored.
- "NO real" disclaimers prevent the model from providing actual system access.
- Provider errors never leak details to attacker connections.

### Payload protection

- Payload retention defaults to `Truncated` (256 bytes max). Raw payloads are **not** stored by default.
- SHA-256 hashes are used for deduplication, not raw bytes.
- Mesh propagation only sends payload hashes, never raw bytes.

### Mesh propagation safeguards

- Mesh propagation is **disabled by default** (`mesh_enabled = false`).
- Minimum confidence (`Medium`) and minimum events (3) are required before propagation.
- Dedupe keys prevent duplicate announcements.
- TTL (24 hours) prevents indefinite propagation of stale indicators.

### Resource limits

- Global semaphore prevents connection exhaustion.
- Per-IP limits prevent single-source abuse.
- Storage queue backpressure drops records under load rather than blocking connection handling.
- AI budgets prevent unbounded cost from provider interactions.
- Circuit breaker prevents cascading failures during provider outages.

### Defense in depth

The honeypot is one layer in a defense-in-depth strategy:

1. **WAF** blocks known attack patterns at the HTTP layer
2. **Honeypot** catches traffic that bypasses or never reaches the WAF
3. **Threat-intel scoring** correlates activity across layers
4. **Mesh propagation** coordinates defense across nodes

The honeypot does not replace the WAF or any other security layer. It provides additional visibility into attacker behavior that would otherwise go undetected.
