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
    listeners: Vec<PortHoneypotListener>,
    port_manager: PortManager,
    responder_registry: HoneypotResponderRegistry,
    intel_extractor: HoneypotIntelExtractor,
    mesh_controller: HoneypotMeshController,
}

pub struct ProtocolDetector { /* fingerprinting logic */ }
pub struct AiHoneypotResponder { /* AI backends */ }
pub struct HoneypotIntelExtractor { /* threat intel */ }
```

### Unified Honeypot

```rust
pub struct UnifiedHoneypotManager {
    profiles: HashMap<IpAddr, IpHoneypotProfile>,
}

pub struct IpHoneypotProfile {
    pub url_hits: AtomicU32,
    pub port_connections: AtomicU32,
    pub protocols_probed: RwLock<HashSet<String>>,
    pub threat_level: AtomicU8,
}

pub enum ThreatLevel {
    None, Low, Medium, High, Critical,
}
```

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
| `UnifiedHoneypotManager::get()` | Singleton access |
| `record_url_hit(ip)` | Track URL honeypot hit |
| `record_port_connection(ip, protocol)` | Track port connection |
| `get_profile(ip) -> Option<IpHoneypotProfile>` | Get IP profile |
| `get_combined_threat_score(ip) -> u8` | Composite threat score |
| `get_corrrelated_ips(ip) -> Vec<IpAddr>` | Find related IPs |
| `clear_expired(max_age_secs)` | Cleanup old profiles |

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
