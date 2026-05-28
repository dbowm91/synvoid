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
