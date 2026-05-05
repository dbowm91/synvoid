# Honeypot Architecture

## Overview

The SynVoid honeypot system provides deception-based detection with two main components: URL honeypot and port honeypot. Both integrate with the threat intelligence mesh for sharing indicators.

## Components

### UnifiedHoneypotManager

The `UnifiedHoneypotManager` at `src/honeypot_unified/mod.rs` correlates URL and port honeypot data:

```rust
pub struct UnifiedHoneypotManager {
    url_honeypot: Arc<UrlHoneypot>,
    port_honeypot: Arc<PortHoneypotRunner>,
    profiles: RwLock<HashMap<IpAddr, IpHoneypotProfile>>,
}
```

### IpHoneypotProfile

Tracks activity from a single IP across both honeypot types:

```rust
pub struct IpHoneypotProfile {
    pub ip: IpAddr,
    pub url_hits: u32,
    pub port_connections: u32,
    pub protocols_probed: HashSet<String>,
    pub threat_level: u8,
    pub first_seen: Instant,
    pub last_seen: Instant,
}
```

### Threat Level Calculation

Combined threat scoring considers:
- URL trap hits (higher weight - more intentional)
- Port connections (probing behavior)
- Protocol diversity
- Time-based decay (recent activity weighted higher)

## URL Honeypot (`src/challenge/honeypot.rs`)

### Path Generation

Generates deceptive paths that should never be accessed legitimately:

```rust
pub fn generate_trap_paths(config: &HoneypotConfig) -> Vec<String> {
    // Common attack vectors
    // Admin interfaces
    // Known CVE paths
    // Sensitive file lookups
}
```

### Detection Logic

```rust
pub fn check_is_trap(path: &str, config: &HoneypotConfig) -> bool {
    config.enabled && config.trap_paths.iter().any(|p| path == *p)
}
```

### Threat Announcement

When a trap is hit, the IP can be announced to the mesh:

```rust
pub async fn announce_to_mesh(&self, ip: IpAddr, threat_indicators: &[u8]) {
    let message = MeshMessage::ThreatAnnounce {
        ip,
        indicator_type: ThreatIndicatorType::UrlTrap,
        // ...
    };
    // Broadcast to mesh peers
}
```

## Port Honeypot (`src/honeypot_port/runner.rs`)

### Runner Lifecycle

```rust
pub struct PortHoneypotRunner {
    ports: HashSet<u16>,
    join_handles: Arc<RwLock<Vec<JoinHandle<()>>>>,  // Added in Wave 7.3 for graceful shutdown
}

impl PortHoneypotRunner {
    pub async fn run(&self) {
        // Spawn listeners for configured ports
        // Track connections with connection duration tracking
    }
    
    pub async fn stop(&self) {
        self.wait_for_completion().await;
    }
}
```

### Connection Tracking

- Record connection timestamps
- Track protocol probing (TCP vs UDP)
- Measure Time-To-First-Byte (TTFB) to identify scanning vs exploitation

### Mesh Publishing

Port honeypot indicators can be published via:
- `publish_threat_indicator()` - Direct announcement
- DHT record storage with `honeypot_port:` prefix

## Integration Patterns

### With Attack Detection

URL honeypot integrates with WAF at the request handling stage:

```rust
// In request handler
if url_honeypot.check_is_trap(&path) {
    record_url_trap_hit(ip);
    return handle_trap_hit(ip);
}
```

### With Threat Level

The unified manager feeds into the threat level system:

```rust
pub fn calculate_combined_threat(ip: &IpHoneypotProfile) -> u8 {
    let base = (ip.url_hits * 3 + ip.port_connections) as u8;
    let recency = calculate_recency_bonus(ip.last_seen);
    base.saturating_add(recency).min(100)
}
```

## Testing

```bash
# Run honeypot tests
cargo test --lib honeypot

# Run integration tests
cargo test --test integration_test -- honeypot
```

## Common Issues

### Silent Failures

**Problem**: Port honeypot spawns fire-and-forget tasks with `.ok()`.

**Solution**: Wave 7.3/7.4 fixed - tasks now store JoinHandles and use proper error handling.

### No Correlation

**Problem**: URL and port honeypot are tracked separately.

**Solution**: UnifiedHoneypotManager provides cross-correlation.