# Honeypot Architecture

## 1. Purpose and Responsibility

The Honeypot system consists of two complementary modules for **attack capture and threat intelligence extraction**:

- **Port Honeypot** (`src/honeypot_port/`): Multi-protocol honeypot with configurable ports, AI responses, and protocol detection
- **Unified Honeypot** (`src/honeypot_unified/`): Global IP-based threat profiling correlating URL and port hits

**Core Responsibilities:**
- Multi-protocol honeypot deployment
- AI-powered dynamic responses
- Protocol fingerprinting and detection
- Threat intelligence extraction
- Port rotation for evasion
- Cross-vector correlation

---

## 2. Key Data Structures

### Port Honeypot

```rust
pub struct PortHoneypotController {
    runner: Arc<RwLock<Option<Arc<PortHoneypotRunner>>>>,
    config: Arc<RwLock<HoneypotPortConfig>>,
}

pub struct ProtocolDetector { /* fingerprinting logic */ }
pub struct AiHoneypotResponder { /* AI backends */ }
pub struct HoneypotIntelExtractor { /* threat intel */ }
```

### Unified Honeypot

The unified honeypot module (`src/honeypot_unified/`) provides global IP-based threat profiling. It does not currently exist as a standalone module — threat profiling is handled within the port honeypot subsystem via `HoneypotIntelExtractor`.

---

## 3. Public API

### Port Honeypot

| Method | Description |
|--------|-------------|
| `PortHoneypotController::new(config)` | Constructor |
| `start().await` | Start all port listeners |
| `stop().await` | Stop all listeners |
| Protocol detection | Auto-detect service protocols |
| AI responses | Dynamic attacker engagement |

### Unified Honeypot

| Method | Description |
|--------|-------------|
| `HoneypotIntelExtractor` | Extracts threat indicators from port honeypot interactions |

---

## 4. Integration Points

- **WAF**: URL honeypot path detection
- **Challenge**: Honeypot tracking in challenge system
- **Mesh**: Distributed honeypot control and intel sharing
- **Admin API**: Honeypot status and configuration
- **Threat Intel**: Extracted indicators shared via mesh

---

## 5. Key Implementation Details

- **AI Responder**: Supports Anthropic, OpenAI, Ollama backends
- **Protocol Detection**: Fingerprints SSH, HTTP, MySQL, etc.
- **Port Rotation**: Configurable port modes (static, sequential, random)
- **Cross-vector Correlation**: URL + port hits combined for threat scoring
- **Mesh Integration**: Honeypot control commands via mesh protocol

## 6. Listener Concurrency and Accounting (Milestone B Phase 3)

### Admission Control

- **Global admission**: `tokio::Semaphore` gates total concurrent honeypot connections. Capacity is configurable.
- **Per-IP admission**: RAII guard (`PermitGuard`) tracks active connections per IP. Guard drop automatically decrements and releases the per-IP slot when count reaches zero. Rejected when per-IP limit exceeded.

### Payload Handling

- **max_payload_size**: Enforced read loop. Connection reads until `max_payload_size` bytes are received, EOF, or error. If `max_payload_size` is exceeded, a truncation flag is set and remaining data is drained but not stored.

### Byte Accounting

- **Total received**: Summed across all read loops for the connection.
- **Total sent**: Summed across all write operations for the connection.
- Corrected from pre-Phase 3 accounting which did not aggregate across multiple reads.

### Timeout Semantics

- `connection_timeout_ms`: Applied to the first data read (initial engagement).
- `read_timeout_ms`: Applied to subsequent reads after initial data received.
- On timeout, the semaphore permit is released via RAII guard drop.

### Protocol/Service Normalization

- Protocol field is lowercased before banner lookup to ensure consistent matching.
- Service is derived from protocol when not explicitly set.

### Metrics (8 counters)

| Counter | Description |
|---------|-------------|
| `accepted` | Connections admitted and processed |
| `rejected_global` | Rejected by global semaphore capacity |
| `rejected_per_ip` | Rejected by per-IP connection limit |
| `timeout_initial` | Timed out waiting for initial data |
| `timeout_read` | Timed out on subsequent reads |
| `truncated` | Payload exceeded max_payload_size |
| `errors` | I/O or protocol errors |
| `storage_failures` | Failed to persist interaction data |

### Structured Logging

All connection fields (src_ip, src_port, dst_port, protocol, bytes_received, bytes_sent, truncated, outcome) are emitted via structured `tracing::info!` on connection completion.

### Tests

12 new tests covering: global admission guard, per-IP guard with drop cleanup, multi-read byte accounting, byte sent tracking, payload truncation, timeout permit release, and protocol normalization.
