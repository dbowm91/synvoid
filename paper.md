# MaluNet: A Peer-to-Peer Web Application Firewall and Content Delivery Network

## Executive Summary

MaluNet is a novel approach to web application security and content delivery that combines a high-performance Web Application Firewall (WAF) built in Rust with an experimental peer-to-peer (P2P) CDN architecture. The project addresses critical limitations in traditional CDN-based DDoS mitigation by enabling collaborative defense through a mesh network of MaluWAF nodes. This white paper provides a comprehensive technical overview of the system, its architecture, and its innovative approach to distributed web security.

---

## 1. Introduction

### 1.1 Background

Modern web infrastructure faces unprecedented security challenges. The threat landscape has evolved dramatically in recent years, with attack vectors becoming both more sophisticated and more accessible to malicious actors.

#### The DDoS Threat Landscape

Distributed Denial of Service (DDoS) attacks have grown in scale and sophistication:

**Attack Scale**:
- Modern DDoS attacks routinely exceed 100 Gbps
- Record-breaking attacks have reached 46 million requests per second
- IoT botnets like Mirai demonstrated the power of compromised devices

**Attack Vectors**:
- **Volumetric**: UDP floods, ICMP floods overwhelming bandwidth
- **Protocol**: SYN floods, connection exhaustion targeting stateful infrastructure
- **Application Layer**: HTTP floods, slowloris, cache-busting attacks

**Economic Impact**:
- Average DDoS attack costs $50,000-$100,000 in damages for businesses
- Downtime during attacks results in lost transactions, reputation damage
- Mitigation services charge premium prices for adequate protection

**Accessibility**:
- DDoS-for-hire services ("booters") available for as little as $10/hour
- Attack tools freely available in underground forums
- Even small groups can launch significant attacks

#### The AI Scraper Problem

Simultaneously, the proliferation of automated scrapers—particularly those powered by artificial intelligence—has created new challenges:

**Scale of Scraping**:
- AI companies now scrape the entire internet to train models
- Crawlers like GPTBot, ClaudeBot, and Common Crawl make billions of requests daily
- Some sites receive more traffic from AI scrapers than human visitors

**AI Scraping Characteristics**:
- Rotate through millions of IP addresses to bypass rate limits
- Masquerade as legitimate browsers (fake User-Agent, JavaScript execution)
- Use residential proxies to appear as normal consumer traffic
- Execute JavaScript to pass JavaScript challenges

**Impact on Website Operators**:
- Server costs escalate from scraping traffic
- Bandwidth bills increase dramatically
- Content scraped without consent for AI training
- Competitive intelligence gathered by competitors

**Legal Gray Areas**:
- No clear legal framework for AI scraping consent
- Terms of Service often ignored
- Robots.txt increasingly ignored by AI crawlers

#### Why Traditional Solutions Fall Short

Traditional Content Delivery Networks (CDNs) address these challenges through massive infrastructure investments, deploying hundreds or thousands of Points of Presence (PoPs) globally. While effective, this approach presents several limitations:

- **Centralization**: Traditional CDNs require trust in a single entity to handle all traffic
- **Cost**: Entry barriers are high, making collaborative defense difficult
- **Encryption Trade-offs**: Effective caching and attack inspection require sacrificing end-to-end encryption
- **Opacity**: Customers have limited visibility into how their traffic is being processed

### 1.2 Project Overview

MaluNet was conceived as a response to these limitations. At its core, MaluWAF serves as a WAF with special considerations for modern threats, including elevated levels of abusive scraping. The system is built on a reverse proxy architecture heavily inspired by Nginx, implemented in Rust for memory safety and performance.

The experimental P2P component—MaluNet—proposes a collaborative alternative to traditional CDNs. By enabling individual WAF nodes to coordinate through a mesh network, the system aims to provide DDoS mitigation capabilities traditionally only available to large organizations, while maintaining trust guarantees through cryptographic verification.

---

## 2. Technology Foundation

### 2.1 Rust as the Implementation Language

Rust was chosen as the implementation language for several compelling reasons that align directly with the project's security and performance requirements.

Memory safety represents the most fundamental motivation for using Rust. Traditional systems programming languages like C and C++ allow developers to manually manage memory, which introduces an entire class of vulnerabilities including buffer overflows, use-after-free bugs, and double-free errors. These memory safety issues are particularly dangerous in network-facing security applications where attackers actively probe for vulnerabilities. Rust's ownership model enforces memory safety at compile time without garbage collection, eliminating entire categories of bugs while maintaining predictable runtime performance. The borrow checker ensures that references are always valid and that memory is freed exactly once, making it impossible to introduce many common security flaws through oversight or accident.

Performance was another critical consideration. Rust achieves performance comparable to C and C++ because it compiles to native machine code without runtime overhead. Unlike languages with garbage collectors that introduce pause times and unpredictable latency, Rust's zero-cost abstractions mean that high-level code transforms into efficient machine code. For a high-throughput reverse proxy handling thousands of simultaneous connections, this performance matters significantly. The difference between handling 10,000 connections versus 100,000 connections can be the difference between requiring expensive hardware versus commodity servers.

The language's concurrency model enables what Rust developers call "fearless concurrency." Because Rust's type system enforces data race prevention at compile time, developers can write concurrent code with confidence that subtle timing bugs won't introduce security vulnerabilities. In network applications where thousands of connections may be processed concurrently across multiple threads, this guarantee is invaluable. The async/await syntax, combined with the Tokio runtime, makes writing concurrent network code almost as straightforward as synchronous code while maintaining Rust's safety guarantees.

The Rust ecosystem provides mature libraries for networking that have proven themselves in production environments. Tokio serves as the asynchronous runtime, handling efficient I/O across multiple concurrent tasks through cooperative scheduling. It provides the foundation for all network operations, managing epoll/kqueue/IOCP system calls transparently across platforms while offering utilities for working with asynchronous code. Hyper implements HTTP/1.1, HTTP/2, and HTTP/3 protocols with a focus on correctness and performance, and serves as the HTTP implementation for major projects including AWS's IoT runtime and TiKV. Quinn provides QUIC protocol implementation, enabling the modern transport that powers HTTP/3. While some parts of the Rust ecosystem remain immature compared to more established languages, the core libraries required for this project—tokio and hyper—are production-grade and widely deployed in critical infrastructure.

### 2.2 Reverse Proxy Architecture

MaluWAF implements an nginx-inspired reverse proxy architecture using Tokio and Hyper, fundamentally changing how network requests are processed compared to traditional thread-per-connection models.

Traditional web servers often use a thread-per-connection or process-per-connection model, where each incoming request is assigned its own execution context. This approach is conceptually simple but introduces significant overhead when handling thousands of concurrent connections. Each thread or process consumes memory, requires context switching, and introduces latency when switching between tasks. Modern high-traffic sites may need to handle tens of thousands of simultaneous connections, making the traditional approach impractical.

MaluWAF instead employs non-blocking I/O combined with cooperative multitasking. Rather than dedicating a thread to each connection, a single thread can manage thousands of connections by registering interest in I/O events and resuming tasks only when their data is ready. When a connection is waiting for data, the thread can process other connections. This approach dramatically increases the number of connections a single server can handle, limited primarily by file descriptor limits rather than available threads.

Connection pooling and HTTP keep-alive work together to reduce the overhead of establishing new connections. When MaluWAF proxies requests to upstream servers, it maintains a pool of persistent connections rather than creating a new connection for each request. This eliminates the TCP handshake and TLS negotiation latency for the majority of requests, significantly improving response times. The keep-alive mechanism allows multiple HTTP requests to reuse the same underlying TCP connection, with the connection being returned to the pool when idle and reused when needed.

HTTP/2 multiplexing builds on this foundation by allowing multiple requests to be sent concurrently over a single connection. Unlike HTTP/1.1, which requires responses to be received in the order requests were sent, HTTP/2 can interleave multiple request and response streams. This eliminates head-of-line blocking where a slow request delays subsequent requests on the same connection. For proxying multiple simultaneous client requests to the same upstream, this represents a significant performance improvement.

HTTP/3 support introduces QUIC as the transport protocol, building on UDP rather than TCP. QUIC eliminates the head-of-line blocking that can occur at the transport layer, provides built-in encryption, and supports 0-RTT connection establishment that allows resumed connections to begin transmitting data immediately without waiting for a handshake. For mobile clients that frequently switch networks or experience intermittent connectivity, QUIC's connection migration capabilities maintain sessions across network changes.

The architecture supports multiple upstream protocols to accommodate diverse application stacks. FastCGI provides a standard interface for communicating with external application servers, particularly common with PHP deployments through PHP-FPM. For Python applications, Granian enables direct integration with WSGI, ASGI, and RSGI applications, allowing Python frameworks like Django, Flask, FastAPI, and Starlette to run with MaluWAF handling the HTTP layer while Granian manages the Python runtime. This integration eliminates the need for a separate application server process, reducing deployment complexity and improving performance through shared-memory communication.

---

## 3. The P2P Problem and MaluNet Solution

### 3.1 Limitations of Traditional P2P Networks

P2P networking excels at issues of scale. Massive networks like those supporting cryptocurrency (Bitcoin, Ethereum) and file sharing (BitTorrent) demonstrate P2P architecture's ability to operate efficiently at enormous scale. DDoS attack coordination itself often relies on underlying P2P architectures.

However, P2P networks face a fundamental challenge: **trust**. Without established governance structures, participants cannot verify:

- Data integrity
- Node identity
- Behavior of other participants

Traditional CDNs address these concerns through centralized governance—customers trust the CDN operator to maintain integrity. This trust model doesn't translate directly to P2P networks.

### 3.2 MaluNet's Hierarchical Trust Model

MaluNet proposes a P2P CDN composed of individual MaluWAF nodes with a hierarchical structure:

```
┌─────────────────────────────────────────────────────────────┐
│                    MaluNet Network                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────────┐                                          │
│   │ Global Nodes │ ← Single source of truth                │
│   │  (CA Level)  │   Directory authorities                │
│   └──────┬──────┘                                          │
│          │                                                 │
│   ┌──────┴──────┐                                          │
│   │ Mesh Nodes   │                                          │
│   ├─────────────┤                                          │
│   │ Edge Nodes   │ ← Accept client connections             │
│   │ Origin Nodes │ ← Connect to origin servers            │
│   └─────────────┘                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Global Nodes**: Serve as the single source of truth in the network. They maintain the complete network topology, act as directory servers for peer discovery, and aggregate routes to upstream services. Global nodes function analogously to Tor's directory authorities, though the purpose is nearly opposite—exposing services rather than providing anonymity.

**Mesh Nodes**: Function either as edge nodes (accepting client connections) or origin nodes (connecting to backend servers). Any MaluWAF instance can operate in either role, enabling flexible deployment topologies.

### 3.3 Gossip Protocol and DHT Overlay

MaluNet uses a gossip protocol for Distributed Hash Table (DHT) overlay, providing two distinct access levels. The gossip protocol enables scalable, fault-tolerant information dissemination without centralized coordination.

#### How Gossip Protocols Work

Gossip protocols are inspired by the spread of information in social networks:

```
Traditional Push Model:              Gossip Model:

┌──────────┐                        ┌──────────┐
│ Node A   │───push──►┌──────────┐ │ Node A   │───gossip──►┌──────────┐
│          │          │ Node B   │ │          │            │ Node B   │
└──────────┘          └──────────┘ └──────────┘            │ Node C   │
       │                     │                                 │ Node D   │
       │         vs         │                                 └──────────┘
       ▼                     ▼
┌──────────┐          ┌──────────┐
│          │◄──push───│ Node A   │
│ Node C   │          │ Node D   │
└──────────┘          └──────────┘

Single source of propagation         Redundant, random dissemination
```

**Core Properties**:
- **Eventual Consistency**: All nodes eventually receive all updates
- **Fault Tolerance**: Node failures don't break propagation
- **Scalability**: O(log N) rounds to reach entire network
- **Simplicity**: No complex coordination needed

#### DHT Overlay Architecture

MaluNet's DHT is built on a Kademlia-inspired design:

**Node Identification**:
- Each node has a 256-bit node ID (derived from public key)
- Node IDs determine "closeness" in the overlay network
- Distance measured by XOR metric: `distance(A, B) = A XOR B`

```
XOR Distance Metric:

Node A: 0b10110101...
Node B: 0b10110011...
              └── differs here
XOR:    0b00000100... = small distance (close nodes)

Node A: 0b10110101...
Node C: 0b01001010...
              └── differs early
XOR:    0b11111111... = large distance (far nodes)
```

**Routing Table**:
Each node maintains links to "k-buckets" of nearby nodes:
- Bucket 0: Nodes with distance 2^0 to 2^1
- Bucket 1: Nodes with distance 2^1 to 2^2
- ... and so on

This enables efficient lookup: finding a node requires O(log N) queries.

#### Message Types

| Message | Purpose | Propagation |
|---------|---------|------------|
| **Ping** | Liveness check | Direct |
| **Store** | Store key-value pair | Gossip |
| **FindNode** | Locate closest nodes | Recursive |
| **FindValue** | Retrieve value for key | Recursive (or return) |
| **Publish** | Announce new information | Gossip |

#### Access Levels

MaluNet provides two distinct gossip channels:

| Level | Description | Use Cases |
|-------|------------|-----------|
| **Private** | Broadcast only to global nodes | Sensitive routing decisions, trust decisions, key ceremonies |
| **Public** | Broadcast to all mesh nodes | Blocklist propagation, health information, route announcements |

**Why Separate Channels**:

1. **Trust Boundaries**: Organizations may not want sensitive routing shared outside their infrastructure
2. **Bandwidth**: Public gossip can be high-volume; private gossip stays small
3. **Confidentiality**: Some routing information reveals infrastructure topology

```
Private Gossip:                    Public Gossip:

  Global                              All Mesh Nodes
     │                                    │
     │  ┌────────┐                   ┌────┼────┐
     │  │        │                   │    │    │
     └──┤ Node A │                   │Node│Node│Node
        │        │                   │ A  │ B  │ C
        └────────┘                   └────────────┘

   Only global nodes see         Entire mesh participates
   routing secrets
```

#### Information Propagation

**Blocklist Propagation**:
When a node detects an attack and adds an IP to the blocklist:

```
T=0: Node A detects attack from 192.168.1.100
     │
T=1: A gossips to 3 random peers (B, C, D)
     │
T=2: B, C, D add to local blocklist
     │   Each gossips to 3 more peers
     │
T=3: Network-wide propagation complete
     │   All nodes block 192.168.1.100
     │
     ▼
Attack source globally blocked
```

**Propagation Parameters**:
```toml
[tunnel.mesh.gossip]
fanout = 3              // Peers to notify per round
gossip_interval = "5s"  // How often to gossip
max_propagation_hops = 4 // Maximum propagation rounds
```

#### Anti-Entropy

Gossip protocols can lose updates if nodes are offline. MaluNet uses anti-entropy to repair:

**Merkle Tree Sync**:
- Nodes maintain Merkle trees of their blocklists
- Periodically, nodes compare tree roots
- Mismatches trigger incremental sync

```
Merkle Tree Example:

        [Root Hash]
       /          \
   [Hash AB]     [Hash CD]
   /    \         /    \
 [A]   [B]      [C]    [D]

If A and B agree on Hash AB, don't transfer A or B
If A and B disagree on Hash AB, transfer both and find difference
```

#### Hybrid Approach Benefits

This gossip+DHT hybrid enables organizations to:

- **Control physical nodes within their infrastructure**: Private gossip stays within trust boundaries
- **Manage trust within their organizational boundaries**: Only share routing with trusted global nodes
- **Allow controlled third-party participation for edge capacity**: Public gossip for collaborative defense

**Private CDN Deployment**:
Organization runs private global nodes, uses public gossip for blocklist sharing but keeps topology private.

**Federated Deployment**:
Multiple organizations share blocklists while keeping internal routes confidential.

---

## 4. Identity and Trust Architecture

### 4.1 Genesis Key and Network Bootstrap

The trust hierarchy begins with a **genesis key**—a cryptographically generated keypair that serves as the root of trust for the entire network. The bootstrap process works as follows:

1. **Genesis Key Creation**: The network operator generates a genesis keypair
2. **Global Node Signing**: The genesis key signs the first global node's mesh_id (a unique network identifier)
3. **Organization Creation**: The global node's mesh_id signs the organization key
4. **Node Enrollment**: Additional nodes join through keysigning ceremonies

### 4.2 Organizations and Trust Levels

Organizations provide a mechanism for entities to group nodes together under a unified identity. Rather than managing trust on a per-node basis, which becomes unwieldy in large deployments, the organization abstraction allows operators to establish identity and trust at a higher level. When an organization registers with the network, it receives a unique organization identifier and cryptographic credentials that prove its identity. All nodes belonging to that organization can then be verified as legitimately operated by that entity.

This organizational structure enables several important capabilities. Trust verification becomes more practical because nodes can check whether other nodes belong to organizations that have established reputations, rather than evaluating each node individually. A node that belongs to a well-known, trusted organization inherits that trust without requiring direct verification. Trusted path routing becomes possible when sensitive traffic needs to traverse only nodes operated by organizations that meet certain trust thresholds—this is particularly important for regulatory compliance where data must pass through trusted infrastructure. Organizations naturally accumulate reputation based on the behavior of their nodes over time, creating accountability structures that incentivize operators to maintain secure, reliable infrastructure.

### 4.3 Certificate Authority Function

Global nodes in the MaluNet hierarchy serve a Certificate Authority function, providing the cryptographic infrastructure that establishes trust throughout the network. The CA function operates similarly to how traditional public key infrastructure works in the broader internet, but adapted for the specific needs of a mesh network.

Node certificates represent the most fundamental CA function. When a new node joins the network, it must obtain a certificate signed by a global node that attests to the node's identity and organizational affiliation. This certificate contains the node's public key, its unique identifier, the organization it belongs to, and validity dates. Any node in the network can verify this certificate by checking the signature against the global node's public key, establishing trust in the presenting node's identity.

Route signatures provide integrity for network path information. When global nodes or edge nodes announce routes to origin servers, these announcements can be signed to prevent malicious actors from injecting false routing information. A signed route attestation allows receiving nodes to verify that the route information originated from a legitimate node and hasn't been tampered with in transit. This is essential for maintaining the integrity of the mesh network's routing infrastructure.

The CA function also includes revocation capabilities for handling compromised or misbehaving nodes. When a node's private key is compromised or when an operator determines that a node should no longer be trusted, the global node can issue a certificate revocation. Nodes throughout the network check revocation status before trusting certificates, ensuring that compromised nodes cannot continue participating in the network. Using the genesis organization as the root of trust, global node operators can add other nodes through keysigning ceremonies that provide cryptographic proof of identity. This allows global nodes to mark certain nodes with a "trusted" flag that enables them to participate in high-sensitivity requests where only nodes meeting elevated verification standards are permitted.

---

---

## 5. Transport Design

### 5.1 Dual-Transport Strategy

MaluNet employs QUIC as its primary transport protocol, optimized for modern network requirements. QUIC provides built-in encryption, 0-RTT connection resumption, and stream multiplexing, making it suitable for all mesh communication use cases.

#### QUIC (HTTP/3)

QUIC is a modern transport protocol built on UDP that addresses long-standing limitations of TCP:

**Core Advantages**:

| Feature | Benefit |
|---------|---------|
| **0-RTT Connection** | Resume previous connections instantly, reducing latency by 1-2 RTTs |
| **Stream Multiplexing** | Multiple independent streams over single connection; no head-of-line blocking |
| **Connection Migration** | Switch between network interfaces (WiFi → cellular) without reconnecting |
| **Built-in TLS 1.3** | Encryption integrated into transport; no separate TLS handshake |

**Connection Establishment**:
```
Traditional TCP + TLS:        QUIC:

Client    Server              Client    Server
  │         │                  │         │
  │────SYN─►│                  │────SYN─►│
  │◄──SYN-ACK│                 │         │  (combined with data)
  │────ACK──►│                  │         │
  │────TLS──►│                  │         │
  │◄──TLS───►│                  │         │
  │◄───DATA─│                  │◄──HANDSHAKE + 0-RTT data
  (3 RTT)                       │────HANDSHAKE + DATA─►
                                 (1 RTT, maybe 0)
```

**When to Use QUIC**:

- **HTTP/3 Traffic**: Native protocol support means no protocol negotiation overhead
- **Short-lived Connections**: 0-RTT makes it ideal for request-response patterns
- **Mesh Proxying**: TCP services proxied through QUIC streams—each stream is independent
- **Mobile Users**: Connection migration maintains sessions during network changes
- **Low-Latency Applications**: API gateways, real-time applications

**Mesh Proxying Through QUIC**:
One of QUIC's most powerful features for MaluNet is TCP proxying through streams:

```
Traditional TCP Proxy:              QUIC Stream Proxy:

Client → Edge WAF → Origin         Client → Edge WAF → Origin
   │          │                        │          │
   │    ┌─────┴─────┐                 │    ┌─────┴─────┐
   │    │ Port      │                 │    │ Stream 1  │ (example.com)
   │    │ Conflicts │                 │    │ Stream 2  │ (api.example.com)
   │    │ occur     │                 │    │ Stream 3  │ (admin.example.com)
   └────┘ per node  └────           └────┘ no conflicts
```

With traditional TCP proxying, each edge node must bind to unique ports. With QUIC, multiple services tunnel through independent streams on a single UDP port.

#### Historical: WireGuard (Removed)

**Note**: The WireGuard transport was removed from MaluWAF in 2025. All mesh communication now uses QUIC exclusively. This section is retained for historical context.

WireGuard was a simpler, faster VPN protocol designed for modern security requirements. It featured:
- **Minimal Codebase**: ~4,000 lines vs tens of thousands for OpenVPN/IPsec
- **Cryptographic Tunnels**: Every packet encrypted with ChaCha20-Poly1305
- **Kernel Integration**: Linux kernel implementation for native performance
- **Modern Cryptography**: Curve25519 for key exchange, Blake2s for hashing

All WireGuard use cases are now served by QUIC, which provides equivalent or better performance for mesh backhaul communication while offering additional benefits like stream multiplexing and connection migration.

#### Protocol Selection Guidelines

Use this decision matrix to choose the appropriate transport:

| Requirement | Recommended |
|-------------|-------------|
| HTTP/3 traffic | QUIC |
| Short-lived connections | QUIC |
| Mobile clients | QUIC |
| Mesh TCP proxying | QUIC |
| All mesh backhaul | QUIC |
| Linux/macOS/Windows | QUIC |

QUIC serves all transport needs, providing consistent behavior across platforms without platform-specific implementations.

### 5.2 Post-Quantum Cryptography

The advent of quantum computers threatens current asymmetric cryptography. MaluNet prepares for this transition through hybrid key exchange.

#### The Quantum Threat

Current public-key systems rely on mathematical problems that quantum computers can solve efficiently:
- **RSA**: Factoring large numbers (Shor's algorithm)
- **ECDSA/ECDHE**: Discrete logarithm (Shor's algorithm)

A large enough quantum computer could:
- Decrypt historical traffic (store now, decrypt later)
- Forge signatures on new connections

#### Hybrid Key Exchange

MaluNet uses **hybrid** key exchange combining classical and post-quantum algorithms:

```
Classical:    ECDH (Curve25519)        → 128-bit security
Post-Quantum: ML-KEM (Kyber-1024)      → 256-bit security
                                   ↓
                        Combined: 256-bit security
                        (both must be broken)
```

**Implementation**:
```toml
[tunnel.quic.tls]
# Enable hybrid post-quantum
pq_signature_schemes = true

# MaluNet uses Kyber-1024 for key encapsulation
kem_schemes = [
    "x25519-kyber-1024-draft00",  # Hybrid
    "kyber-1024",                  # Post-quantum only (experimental)
]
```

**Why Hybrid?**:
- Post-quantum algorithms are relatively new
- Hybrid provides defense-in-depth: attacker must break both
- No performance penalty compared to classical-only
- Future: can transition to PQ-only when confidence grows

#### Algorithm Selection

| Algorithm | Type | Security Level | Status |
|-----------|------|----------------|--------|
| X25519 | Classical ECDH | 128-bit | Mature |
| ML-KEM-768 | Post-quantum | 128-bit | Standardized (2024) |
| ML-KEM-1024 | Post-quantum | 192-bit | Standardized (2024) |
| X25519+ML-KEM-768 | Hybrid | 256-bit | Recommended |

### 5.3 Protocol Buffers

MaluNet uses Protocol Buffers (protobuf) for efficient wire format:

**Why Protocol Buffers**:

1. **Compact Encoding**: Binary format smaller than JSON/XML
2. **Schema Evolution**: Add optional fields without breaking compatibility
3. **Code Generation**: Type-safe code from schema definitions
4. **Performance**: Faster parsing than text formats

**Schema Example**:
```protobuf
message MeshMessage {
    enum MessageType {
        HELLO = 0;
        ROUTE_QUERY = 1;
        ROUTE_RESPONSE = 2;
        HEALTH_CHECK = 3;
        BLOCKLIST_SYNC = 4;
    }
    
    MessageType type = 1;
    string source_node = 2;
    uint64 timestamp = 3;
    
    oneof payload {
        Hello hello = 10;
        RouteQuery route_query = 11;
        HealthCheck health_check = 12;
    }
}

message Hello {
    string node_id = 1;
    string role = 2;  // edge, origin, global
    repeated string capabilities = 3;
}
```

**Serialization Flow**:
```rust
// Serialize
let msg = MeshMessage {
    type: MessageType::HELLO,
    source_node: "waf-1".to_string(),
    // ...
};
let bytes = msg.encode();

// Deserialize  
let msg = MeshMessage::decode(&bytes)?;
```

---

## 6. Pass-Over Keypass: End-to-End Integrity

### 6.1 The Problem of Untrusted Edge Nodes

In a P2P CDN network, nodes cannot assume other nodes are trustworthy. A malicious edge node could inject malicious content into responses. Traditional CDNs solve this through trust in the CDN operator; MaluNet requires a different approach.

**The Threat Model**:

```
Traditional CDN:                      MaluNet P2P:

┌──────────┐                         ┌──────────┐
│  Client  │                         │  Client  │
└────┬─────┘                         └────┬─────┘
     │                                      │
     │ HTTPS (TLS)                          │ HTTPS to Edge
     │    │                                 │    │
     ▼    ▼                                 ▼    ▼
┌──────────┐                              ┌──────────┐
│   CDN    │                              │  Edge    │ (untrusted)
│ (trusted)│                              │   WAF    │
└────┬─────┘                              └────┬─────┘
     │                                           │
     │ HTTPS (TLS)                               │ QUIC
     │    │                                      │    │
     ▼    ▼                                      ▼    ▼
┌──────────┐                              ┌──────────┐
│  Origin  │                              │  Origin  │
│  Server  │                              │   WAF    │
└──────────┘                              └──────────┘

Client trusts CDN operator           Client must verify
by default                          integrity at each hop
```

In traditional CDNs, you trust the CDN because you contract with them. In MaluNet's P2P model, edge nodes are not necessarily trusted—they could be compromised or malicious.

### 6.2 Out-of-Band Key Exchange

The Pass-Over Keypass system provides end-to-end integrity verification through an out-of-band key exchange that establishes a verified channel between client and origin, bypassing trust in intermediate nodes.

#### Protocol Overview

```
┌─────────────────────────────────────────────────────────────────┐
│              Pass-Over Keypass Flow                             │
└─────────────────────────────────────────────────────────────────┘

Client → Edge Node (requesting example.com)
    │
    │ 1. HTTP request with X-MaluNet-Origin header
    │
    ▼
Edge Node → Client (inject client.js with origin node ID)
    │
    │ 2. JavaScript/WASM challenge response
    │    Contains: origin_node_id, global_node_hint
    │
    ▼
Client → Global Node (direct QUIC connection)
    │
    │ 3. KeyExchangeRequest
    │    - Client generates ephemeral keypair
    │    - Signs session_key with temp identity
    │
    ▼
Global Node → Origin Node (proxy key exchange)
    │
    │ 4. Forward key exchange request
    │    - Verifies client identity
    │    - Looks up origin node
    │
    ▼
Origin Node → Global Node (sign session key)
    │
    │ 5. KeyExchangeResponse
    │    - Signs session_key with origin's mesh_id
    │    - Returns origin node certificate chain
    │
    ▼
Client ← Global Node (proxied response)
    │
    │ 6. Signed session_key + certificates
    │
    ▼
Client verifies signature chain
    │
    │ 7. Establishes verified connection to origin
    │    - All future traffic uses session_key
    │    - Edge node cannot modify/delay traffic
    │
    ▼
End-to-End Encrypted + Integrity-Verified Session
```

#### Step-by-Step Protocol

**Step 1: Initial Request**

The client requests a resource through the edge node:
```http
GET / HTTP/1.1
Host: example.com
X-MaluNet-Origin: example.com
```

The edge node responds with injected JavaScript that will perform the key exchange:
```html
<script src="/malu-net-client.js" 
        data-origin="node-12345"
        data-global="global-1.mesh.example.com:5001">
</script>
```

**Step 2: Client Generates Ephemeral Keys**

The client-side JavaScript generates an ephemeral keypair:
```javascript
// Client generates ephemeral keypair
const clientKeyPair = await crypto.subtle.generateKey(
    { name: "ECDHE", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
);

// Generate session identifier
const sessionId = crypto.randomUUID();

// Create key exchange request
const keyExchangeRequest = {
    session_id: sessionId,
    client_public_key: exportKey(clientKeyPair.publicKey),
    target_origin: "example.com",
    timestamp: Date.now()
};
```

**Step 3: Global Node Verification**

Client connects directly to a global node (bypassing edge):
```http
POST /_malu/keyexchange HTTP/3
Content-Type: application/json

{
    "session_id": "abc-123",
    "client_public_key": "base64-encoded-key",
    "target_origin": "example.com",
    "client_signature": "base64-encoded-sig"
}
```

The global node:
1. Verifies the client's signature
2. Looks up which node hosts `example.com`
3. Forwards the request to the origin node

**Step 4: Origin Node Signing**

The origin node receives the key exchange request:
```rust
struct KeyExchangeRequest {
    session_id: [u8; 16],
    client_public_key: [u8; 65],  // P-256 uncompressed
    timestamp: u64,
}

// Origin node signs the session key
fn sign_session_key(&self, request: &KeyExchangeRequest) -> KeyExchangeResponse {
    let mut data = Vec::new();
    data.extend_from_slice(&request.session_id);
    data.extend_from_slice(&request.client_public_key);
    data.extend_from_slice(&request.timestamp.to_le_bytes());
    
    // Sign with origin's mesh_id private key
    let signature = self.mesh_id_key.sign(&data);
    
    KeyExchangeResponse {
        session_id: request.session_id,
        signed_session_key: signature,
        origin_certificate: self.certificate.clone(),
        origin_node_id: self.mesh_id.clone(),
    }
}
```

**Step 5: Response Verification**

Client receives and verifies the response:
```javascript
// Verify origin signature
const originPublicKey = await importKey(origin.certificate.public_key);
const isValid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    originPublicKey,
    origin.signature,
    sessionData
);

if (isValid) {
    // Derive shared secret
    const sharedSecret = await deriveSharedSecret(
        clientKeyPair.privateKey,
        origin.publicKey
    );
    
    // Establish encrypted channel
    await establishSecureChannel(sharedSecret);
}
```

#### Why This Works

**Even if edge node is malicious**:

1. **Cannot Read Traffic**: Session key is established directly between client and origin
2. **Cannot Modify Traffic**: Responses are signed with origin's mesh_id
3. **Cannot Impersonate Origin**: Global node verifies origin's certificate chain
4. **Cannot Forward Fake Response**: Client verifies signature before trusting

**Trust Anchors**:

- **Genesis Key**: Root of trust for the entire network
- **Global Nodes**: Certificate authorities for mesh nodes
- **Origin Certificates**: Issued by global nodes, prove origin identity

### 6.3 Session Management

**Session Lifetime**:
- Session keys expire after configurable duration (default: 1 hour)
- Clients must re-authenticate for long-lived sessions
- Origin nodes can revoke sessions (compromise response)

**Session Resumption**:
Clients can resume previous sessions:
```http
GET / HTTP/1.1
Host: example.com
Cookie: malu_sess=resumption_token
```

The origin verifies the resumption token and issues a fresh session key without full key exchange.

### 6.4 Performance Considerations

**Latency Impact**:
- Full key exchange: 2-3 RTT (one to global, one to origin)
- Session resumption: 0 RTT (using stored session token)

**Caching**:
- Origin certificates cached by clients
- Global node responses can be cached for same-origin requests

**Optimization for Known Origins**:
- Clients can pin origin certificates for known-good origins
- Skip full key exchange for pinned origins

---

## 7. Attack Detection

MaluWAF provides comprehensive attack detection across multiple vulnerability categories, implemented as a multi-layer protection pipeline.

### 7.1 Detection Methods

MaluWAF implements a multi-layered detection approach, combining pattern matching, grammar analysis, and protocol validation. The detection pipeline processes requests through distinct stages, each optimized for specific vulnerability classes.

#### SQL Injection Detection (libinjection)

SQL injection detection leverages **libinjection**, a library that analyzes input for SQL syntax patterns by testing candidate strings against a SQL grammar. Unlike simple pattern matching, libinjection performs true syntactic analysis:

1. **Input Normalization**: The request payload undergoes normalization before analysis—this includes URL decoding, removing redundant whitespace, and handling various encoding schemes (double-encoding, UTF-8 malformed sequences)

2. **Grammar-Based Analysis**: Libinjection tests normalized input against SQL grammar rules. It doesn't look for specific attack strings; instead, it identifies whether the input *would alter the intended SQL query structure* if interpreted as part of a query parameter

3. **Fingerprint Generation**: When an attack is detected, libinjection returns a **fingerprint**—a compact identifier describing the attack type:
   - `sqli-boolean-based`: Tautologies like `' OR '1'='1`
   - `sqli-union-based`: UNION SELECT attempts
   - `sqli-tautology`: Always-true conditions in WHERE clauses
   - `sqli-comment`: Query termination with `--` or `/*`

4. **Coverage Areas**: SQL injection checks apply to query strings, POST body content, HTTP headers (including cookies), providing defense-in-depth across all input vectors

This approach achieves significantly lower false positive rates than regex-based alternatives because it understands SQL structure rather than matching individual keywords.

#### Cross-Site Scripting (XSS) Detection

XSS detection employs **context-aware HTML parsing**, recognizing that the same payload can be dangerous in one HTML context but harmless in another:

**Parsing Contexts**: The HTML5 parsing specification defines multiple contexts where user input might appear:
- **Data State**: Plain text between tags (`<div>user input</div>`)
- **Unquoted Attributes**: `<input value=userinput>`
- **Single-Quoted Attributes**: `<input value='userinput'>`
- **Double-Quoted Attributes**: `<input value="userinput">`
- **JavaScript Context**: `<script>var x="userinput"</script>`
- **URL Context**: `<a href="userinput">`
- **CSS Context**: `<style>div { color: userinput }</style>`

**Why Context Matters**: The string `javascript:alert(1)` is harmless in data state but dangerous in an href attribute. Similarly, `<img onerror=alert(1)>` requires an event handler attribute context to execute. MaluWAF's parser determines the exact context and validates accordingly.

**Detection Techniques**:
- Tag detection: Identifying HTML tags in user input (`<script>`, `<iframe>`, `<object>`)
- Event handler analysis: Looking for `on*` attributes that trigger JavaScript execution
- Protocol handler detection: Identifying `javascript:`, `data:`, `vbscript:` URIs
- DOM-based analysis: For reflected XSS, examining how input propagates through client-side JavaScript

#### Path Traversal Detection

Path traversal detection uses the **Aho-Corasick automaton**, a string matching algorithm that simultaneously searches for multiple patterns in single pass through the input:

**Why Aho-Corasick**: Traditional approaches test each pattern sequentially (O(n × m) where n is input length and m is pattern count). Aho-Corasick builds a finite state machine from all patterns, enabling O(n) matching regardless of pattern count—critical when defending against thousands of attack variants.

**Pattern Categories**:
- Basic traversal: `../`, `..\`, `..%2f`, `..%5c`
- Double-encoded: `%252e%252e%252f`, `%252e%252e%255c`
- Unicode variants: `..%c0%af` (overlong UTF-8), Unicode normalization
- Sensitive files: `/etc/passwd`, `/windows/system32/config`, `.htaccess`
- Protocol handlers: `file://`, `php://`, `expect://`, `phar://`

The detector maintains separate pattern sets for each encoding variant, ensuring that URL-decoded input, double-decoded input, and raw input are all checked appropriately.

#### Server-Side Request Forgery (SSRF) Detection

SSRF detection focuses on identifying requests that target internal infrastructure:

**Internal IP Recognition**: The detector recognizes numerous representations of loopback and private addresses:
- IPv4: `127.0.0.1` through `127.255.255.255`, `0.0.0.0`, `localhost`
- IPv6: `::1`, `[::1]`, IPv4-mapped IPv6 addresses
- Private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`

**Cloud Metadata Endpoints**: Modern cloud providers expose metadata services at well-known IPs:
- AWS: `169.254.169.254` (EC2, Lambda, ECS)
- GCP: `metadata.google.internal` / `169.254.169.254`
- Azure: `169.254.169.254` (IMDS)
- Kubernetes: `kubernetes.default.svc`

**Protocol Detection**: Dangerous protocols that could enable server-side exploitation:
- `gopher://`: Gopher protocol allows crafting complex requests to internal services
- `dict://`: Dictionary protocol, can probe internal services
- `file://`: Local file access
- `ftp://`: FTP for internal network scanning

#### Command Injection Detection

Command injection detection identifies shell metacharacters and dangerous command patterns:

**Shell Metacharacters**: Characters that have special meaning to Unix shells (`;`, `|`, `&`, `&&`, `||`, `$`, `` ` ``, `(`, `)`, `<`, `>`)

**Command Substitution**: Patterns that execute commands:
- Backticks: `` `command` ``
- Dollar syntax: `$(command)`, `${command}`
- Newlines in certain contexts

**Dangerous Commands**: Common attack commands are flagged with higher suspicion:
- File operations: `cat`, `ls`, `wget`, `curl`, `nc`, `ncat`
- Shell spawning: `bash`, `sh`, `zsh`, `dash`
- Network tools: `curl`, `wget`, `nc`, `nmap`, `ftp`
- Text processing: `awk`, `sed`, `grep`

The detector uses a weighted scoring system—a single `;` might trigger medium suspicion, while `;ls` triggers high suspicion due to the command name.

#### Additional Detection Categories

| Attack Type | Detection Approach |
|-------------|-------------------|
| **RFI** | URL parameter analysis detecting external URLs, IP addresses in parameters, PHP wrappers |
| **JWT Validation** | Algorithm confusion (alg:none), weak secret detection, expiration validation, key confusion attacks |
| **LDAP Injection** | Filter manipulation detection (`*)(uid=*))(|(uid=*)`), DN manipulation, special character handling |
| **Open Redirect** | Protocol validation (blocking javascript:, data:, vbscript:), domain allowlisting |
| **SSTI** | Template syntax detection (Jinja2: `{{`, `{%`, Twig: `{{`, Rails: `<%=`) |
| **XXE** | Entity declaration detection (`<!ENTITY>`, `<!DOCTYPE>`), external entity references |
| **XPath Injection** | XPath expression injection, predicate manipulation (`[1]`, `[position()]`) |
| **Request Smuggling** | Content-Length vs Transfer-Encoding conflict detection, H2 CL/TE handling |

### 7.2 Paranoia Levels

Paranoia levels provide configurable sensitivity thresholds, allowing operators to balance security against false positive tolerance. Each level adjusts multiple detection parameters simultaneously.

**Level 1 (Low Sensitivity)**: Designed for production environments where availability is paramount. This level employs conservative detection that prioritizes minimizing false positives:

- **SQL Injection**: Only detects obvious tautologies and UNION-based attacks; doesn't analyze encoded payloads
- **XSS**: Only blocks clear tag-based attacks (`<script>`, `<iframe>`); attribute-based and event handler injections are ignored
- **Path Traversal**: Only detects raw `../` sequences; encoded variants are not checked
- **SSRF**: Only blocks direct requests to `127.0.0.1` and `localhost`; cloud metadata endpoints require Level 2+
- **Command Injection**: Only detects command separators combined with known dangerous commands

**Level 2 (Medium Sensitivity)**: The recommended default for most deployments. This level adds:

- **SQL Injection**: Analyzes URL-decoded payloads, detects comment-based bypass attempts
- **XSS**: Blocks event handler injections (`onerror=`, `onload=`, `onclick=`), attribute-based payloads
- **Path Traversal**: Detects URL-encoded (`%2e%2e%2f`) and UTF-8 variants
- **SSRF**: Blocks cloud metadata endpoints, recognizes alternative localhost representations
- **Command Injection**: Detects standalone metacharacters, environment variable access

**Level 3 (High Sensitivity)**: For high-security environments where blocking potential attacks takes priority over occasional false positives:

- **SQL Injection**: Aggressive matching including partial keywords, time-based blind SQL indicators, database-specific syntax
- **XSS**: Context-aware validation across all HTML contexts, DOM-based detection, CSS injection attempts
- **Path Traversal**: Double-encoded variants, Unicode normalization bypasses, null-byte handling
- **SSRF**: All private IP ranges, DNS resolution-based detection (resolving URLs to internal IPs), FTP passive mode
- **Command Injection**: Even single metacharacters may trigger blocks, extensive command name dictionary
- **Additional Checks**: Enables extra detections like header injection, response splitting

**Transitioning Between Levels**: When deploying MaluWAF, we recommend:

1. Begin at Level 1 with `action = "log"` for 48-72 hours
2. Review logs for false positives and adjust rules accordingly
3. Transition to Level 2 with `action = "log"` for another 24 hours
4. Finally, enable `action = "block"` at Level 2
5. Consider Level 3 only if facing sophisticated attacks and can tolerate investigation of false positives

The threat level system can automate paranoia level adjustments based on attack volume, dynamically escalating when sustained attack traffic is detected.

### 7.3 Response Actions

When an attack is detected, MaluWAF can respond in several ways. Each response type serves different operational goals and has distinct implementation characteristics.

**Log**: The request proceeds normally after recording detection details. This mode serves several purposes:

- Initial deployment tuning to identify false positives before enabling blocking
- Security monitoring and incident response analysis
- Compliance requirements demanding audit trails
- Threat hunting and attack pattern research

Logged detections include: timestamp, client IP, attack type, payload snippet, fingerprint, paranoia level, and action taken.

**Block**: The request is denied with an HTTP error response:

- **Default Response**: HTTP 403 Forbidden
- **Customizable**: Operators can configure custom error pages, different status codes (404, 400), or redirect URLs
- **Response Headers**: Includes security headers and optionally the attack fingerprint for debugging
- **Logging**: Full request details are logged for incident analysis

**Stall (Stealth Mode)**: The connection is held open indefinitely without any response:

- **Implementation**: The connection is placed in a non-blocking wait state with no timeout
- **Effect**: Attackers cannot distinguish between "server not responding" and "you've been blocked"
- **Resource Usage**: Minimal—stalled connections consume a file descriptor but no CPU or memory beyond initial allocation
- **Detection Evasion**: Prevents attackers from iterating through different payloads to identify WAF rules
- **Warning**: Legitimate users whose requests trigger false positives will hang indefinitely; use only when confident detection is accurate

**Tarpit**: The connection receives convincing but fake responses:

- **Purpose**: Waste attacker time and resources while gathering intelligence
- **Implementation**: Generates plausible-looking but fabricated responses
- **Content Simulation**: Fake admin panels, vulnerable forms, or误导 content
- **Connection Recycling**: Tarpit connections can be recycled to gather additional information about attacker tools
- **Intelligence Gathering**: Response timing, follow-up requests, and behavior can reveal attacker infrastructure and objectives

**Challenge**: The client must prove it's a legitimate browser before request proceeds:

- **JavaScript Challenge**: Client must execute JavaScript that computes a result and resubmits
- **Proof-of-Work Challenge**: Client must perform computational work (see Bot Mitigation section)
- **Cookie-Based**: Sets a verification cookie that expires after successful browser execution
- **See Section 9.2 for detailed challenge mechanics**

The response action can be configured globally or per-attack-type, enabling fine-grained control (e.g., log SQL injection attempts while blocking command injection).

---

## 8. Flood Protection

MaluWAF implements multi-layer flood protection against volumetric attacks. Unlike application-layer attack detection which inspects request content, flood protection operates at connection and packet levels to prevent resource exhaustion before request processing begins.

### 8.1 SYN Flood Protection

SYN floods exploit the TCP three-way handshake by sending SYN packets without completing the handshake, accumulating half-open connections that consume server resources.

#### SYN Proxy Implementation

MaluWAF implements a SYN proxy that shields upstream servers from SYN flood attacks:

```
Standard TCP Handshake:          MaluWAF SYN Proxy:

Client    Server                 Client    MaluWAF    Upstream
  │         │                      │          │          │
  │────SYN─►│                      │────SYN─►│          │
  │         │                      │◄──SYN-ACK│          │
  │◄──SYN-ACK│                     │────ACK──►│          │
  │────ACK──►│                     │          │────SYN─►│
  │         │                      │          │◄──SYN-ACK│
  │◄───DATA─│                      │          │────ACK──►│
                                  │◄───DATA─│
```

**How the SYN Proxy Works**:
1. Client sends SYN to MaluWAF (not the upstream)
2. MaluWAF responds with SYN-ACK (completing handshake with client)
3. MaluWAF establishes its own connection to the upstream
4. Once both connections are established, MaluWAF transparently forwards traffic

This approach ensures that even if thousands of malicious SYN packets arrive, the upstream server only sees legitimate completed connections.

#### Half-Open Connection Tracking

MaluWAF maintains a connection table tracking half-open connections:

- **Per-IP Limits**: Maximum half-open connections per source IP (default: 10)
- **Global Limits**: Total half-open connections across all IPs (default: 1,000)
- **Tracking Table**: Hash table indexed by source IP for O(1) lookup
- **Timeout**: Half-open connections expire if not completed within 30 seconds (configurable)

#### Stale Entry Cleanup

To prevent memory accumulation from expired connections:

- **Background Cleanup**: Periodic scan removes entries older than timeout threshold
- **Lazy Cleanup**: Entries cleaned on next access attempt
- **Aggressive Mode**: During attacks, more frequent cleanup prevents table exhaustion

### 8.2 Connection Rate Limiting

Beyond SYN floods, MaluWAF limits connection rates to prevent connection exhaustion attacks.

#### Token Bucket Algorithm

Connection rate limiting uses the **token bucket algorithm**, which allows burst capacity while enforcing average rate limits:

```
┌─────────────────────────────────────────────────────────┐
│              Token Bucket Algorithm                     │
└─────────────────────────────────────────────────────────┘

    Bucket Capacity (B): Maximum burst allowed
    ┌────────────────────────────────────────┐
    │                                        │
    │    ╔═══════════════════════════════╗   │
    │    ║  Tokens (removed on each      ║   │
    │    ║  new connection)              ║   │
    │    ╚═══════════════════════════════╝   │
    │              │                          │
    │              ▼ Refill Rate (R)          │
    └────────────────────────────────────────┘

Key Properties:
- Bucket Size (B): Connections allowed in sudden burst
- Refill Rate (R): Connections added per time unit
- Average Rate: R connections/second sustained
- Burst Handling: Up to B connections instantly
```

**Configuration Parameters**:
```toml
[defaults.rate_limit]
connections_per_minute = 60    # Refill rate
burst_capacity = 10            # Bucket size
```

This allows a client to open 10 connections immediately, then 1 per second thereafter.

#### Per-IP vs Global Limits

MaluWAF implements hierarchical rate limiting:

| Level | Scope | Purpose |
|-------|-------|---------|
| **Per-IP** | Individual client | Prevent single-source exhaustion |
| **Global** | All clients | Protect overall system capacity |

Both levels operate independently—a client can be blocked by either limit.

### 8.3 UDP Flood Protection

UDP floods amplify attack traffic by exploiting the connectionless nature of UDP. MaluWAF provides per-port UDP rate limiting to mitigate these attacks.

#### The O(1) Slotted Counter Design

Traditional rate limiting often uses per-IP hash tables requiring O(n) operations. MaluWAF's **slotted counter** design achieves O(1) performance:

```
Slotted Counter Architecture:

Time Window: 1 second divided into slots
┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
│  0  │  1  │  2  │  3  │  4  │  5  │  6  │  7  │  ... (1000 slots)
└─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘
  ▲
  │
Current slot (advances every window/1000)

Each IP maps to a slot via hash:
IP: 192.168.1.1 → hash() → slot 347
IP: 10.0.0.1    → hash() → slot 892
```

**Why O(1)**:
- No hash table lookups: Slot determined by hash(IP) mod slot_count
- No traversal: Only current slot accessed for rate checking
- Atomic increments: Single CPU instruction to increment counter

**Per-Port Rate Limiting**:
UDP services like DNS are common amplification targets. MaluWAF tracks per-port packet rates:

```
UDP Port Rate Tracking:

Port 53 (DNS)    ┌────────────────────────────────┐
                 │ Port-specific counters         │
Port 123 (NTP)   │ ┌────────┐ ┌────────┐        │
                 │ │ Port 53│ │Port 123│ ...     │
Port 161 (SNMP)  │ └────────┘ └────────┘        │
                 └────────────────────────────────┘

Each port has independent limits:
- Per-IP packet rate: 100 pps
- Per-port packet rate: 10,000 pps  
- Global packet rate: 100,000 pps
```

This prevents a single client from flooding any specific port while allowing legitimate multi-port traffic.

#### DNS Amplification Prevention

DNS amplification attacks exploit the difference between query and response sizes:

1. Attacker spoofs source IP to victim's address
2. Attacker sends small DNS queries with "ANY" type
3. DNS server sends large responses to victim

MaluWAF's per-port limiting prevents this by:
- Limiting responses per second to each port
- Blocking queries to closed DNS resolvers
- Tracking suspicious query patterns

### 8.4 Blackhole Mode

During sustained DDoS attacks, even sophisticated filtering can be overwhelmed. Blackhole mode provides last-resort protection by silently discarding traffic.

#### How Blackhole Mode Works

```
Normal Operation:                    Blackhole Mode:

Internet ──► MaluWAF ──► Upstream    Internet ──► MaluWAF (╳) ──► Upstream
              │                              │
              └── Valid requests             └── All traffic dropped
                   forwarded

Attack traffic:                      Attack traffic:
- Processed normally                 - Silently discarded
- Blocks applied                     - No response (ICMP unreachable)
- Logged                              - No logging (stealth)
```

#### Implementation Details

**Connection Handling**:
- Existing connections continue normally (no disruption to established sessions)
- New connections are dropped at TCP layer (no SYN-ACK response)
- UDP packets are dropped (no ICMP response)

**Activation Triggers**:
- Manual: Administrator enables via API or config
- Automatic: Sustained attack exceeds threshold (configurable)
- Automatic: CPU/memory exceeds critical levels

**Gradual Restoration**:
When blackhole duration expires:
1. Begin accepting connections at 10% capacity
2. Gradually increase over 30 seconds
3. Return to normal operation if traffic remains reasonable
4. Re-enter blackhole if attack resumes

#### Use Cases

**When to Use Blackhole Mode**:
- Attack volume exceeds filtering capacity
- Upstream servers are overwhelmed
- Buying time while upstream providers activate mitigation
- Attack targets non-critical services

**Risks**:
- All traffic blocked, including legitimate users
- Last-resort measure; use sparingly
- Coordinate with upstream providers before activation

---

## 9. Bot Mitigation

### 9.1 AI Crawler Blocking

The proliferation of AI-powered web scrapers has created new challenges for website operators. Unlike traditional crawlers that identify themselves through standard user-agent strings, AI scrapers often disguise as browsers or use rapidly rotating identities. MaluWAF addresses this through multiple detection strategies.

#### The isbot Integration

MaluWAF integrates with **isbot**, a comprehensive crawler detection library that maintains an up-to-date database of known bot signatures:

**How isbot Works**:
1. Parses the User-Agent HTTP header
2. Matches against a curated database of crawler patterns
3. Returns classification: bot, human, or unknown

**Classification Categories**:
- **Known Bots**: Search engine crawlers (Googlebot, Bingbot), social media crawlers, archive bots
- **AI Scrapers**: Detected AI crawler signatures (ClaudeBot, GPTBot, Common Crawl, various data harvesting agents)
- **Human Browsers**: Standard browser user-agents
- **Unknown**: Ambiguous user-agents that don't match known patterns

#### AI Crawler Identification

Beyond isbot, MaluWAF employs additional heuristics to identify AI scrapers:

**Behavioral Signals**:
- **Request Pattern Analysis**: AI scrapers often exhibit uniform timing between requests (mechanical precision unlike human browsing patterns)
- **Page Coverage**: Scrapers systematically request every accessible URL rather than following typical human navigation patterns
- **Header Analysis**: Missing or inconsistent headers that browsers normally include (Accept-Language, Accept-Encoding, Referer)
- **JavaScript Disabled**: Requests that never execute JavaScript, indicating programmatic rather than browser-based access

**Signature Updates**: The AI crawler landscape evolves rapidly. MaluWAF's detection signatures are regularly updated to address new scrapers, and operators can add custom patterns for specific unwanted crawlers.

#### Blocking Strategies

When an AI crawler is detected, several response options are available:

1. **Block**: Return HTTP 403, completely denying access
2. **Challenge**: Present a CAPTCHA or proof-of-work challenge (see 9.2)
3. **Rate Limit**: Allow limited access while throttling excessive requests
4. **Log Only**: Monitor crawler activity without blocking (useful for assessing impact)

**Considerations**:
- Some AI tools (search engines) provide SEO benefits—operators should whitelist beneficial crawlers
- AI crawler user-agents can be spoofed; behavioral analysis provides defense-in-depth
- Legal and ethical considerations vary by jurisdiction regarding blocking AI scrapers

### 9.2 Challenge Systems

Challenge systems provide interactive verification that the client is a legitimate browser rather than an automated script. Each challenge type exploits capabilities (or limitations) specific to real browsers.

#### CSS Challenges

CSS-based challenges leverage differences in how browsers render CSS compared to how HTTP libraries and bots parse HTML:

**How It Works**:
1. Server embeds hidden links in the response that are visually concealed (using `display: none`, `visibility: hidden`, or positioning off-screen)
2. Legitimate browsers will not follow these links—the CSS hides them from users
3. HTTP clients, scrapers, and many bots parse raw HTML and may attempt to follow any link they find
4. Requests to the hidden link endpoint indicate bot behavior

**Detection Mechanics**:
- Links with suspicious hrefs that don't appear in visible content
- Links with obviously fake or random-looking URLs
- Links that would require JavaScript execution to become valid

**Advantages**:
- No JavaScript required
- Minimal server-side computation
- Transparent to users (they never see the hidden content)

**Limitations**:
- Sophisticated bots can parse CSS and avoid following hidden links
- Some legitimate bots (search engine crawlers) may follow links without rendering CSS

#### JavaScript Challenges

JavaScript challenges verify browser capabilities by requiring client-side code execution:

**Navigator API Detection**:
The challenge includes JavaScript that queries browser properties unavailable to most HTTP libraries:
- `navigator.userAgent`: Browser identification
- `navigator.webdriver`: Automation detection (Selenium, Puppeteer set this to `true`)
- `navigator.plugins`: Browser plugin list
- `window.chrome`: Chrome-specific object (Chrome reports this, other browsers don't)
- `navigator.languages`: User's language preferences

**Canvas Fingerprinting**:
The challenge renders hidden content to a canvas and extracts the resulting image data:
- Different browsers and operating systems render graphics slightly differently
- The resulting hash serves as a "fingerprint" identifying the browser environment
- Headless browsers and automation tools often render differently than real browsers

**WebGL Analysis**:
Similar to canvas fingerprinting, WebGL rendering differences can distinguish real browsers:
- Renderer strings (`WEBGL_debug_renderer_info`)
- Available extensions
- Rendering precision

**Execution Flow**:
```
Challenge Response (200 OK)
         │
         ▼
    JavaScript Executes
         │
         ├── Query Navigator APIs
         ├── Render Canvas (hidden)
         ├── Hash result
         │
         ▼
    Resubmit with Challenge Cookie
         │
         ▼
    Verify Hash & Cookies
         │
         ▼
    Allow / Block
```

**Cookie-Based State**:
Successful challenges set cookies with:
- Expiration timestamps
- Challenge solution verification data
- Hashed client identifiers

The cookie prevents challenges from being re-presented on each request while still ensuring the client executed JavaScript.

#### Proof-of-Work (PoW) Challenges

Proof-of-work challenges require computational effort before serving content, raising the cost of automated requests:

**Hashcash-Style PoW**:
The server issues a challenge containing:
- **Salt/Nonce**: Random data unique to each challenge
- **Difficulty Target**: How many leading bits of the hash must be zero
- **Resource URI**: The resource being requested

The client must find a value that, when combined with the salt and hashed (typically SHA-256), produces a hash meeting the difficulty target:

```
Hash(salt + client_nonce) < Target
```

This is a brute-force search—the client must try many nonce values until finding one that works. The expected work is 2^difficulty operations.

**Difficulty Parameters**:
- **Iterations**: Number of hash computations required (default ~10,000-100,000)
- **Target Bits**: Number of leading zeros required in the hash
- **Time Window**: How long the computed solution remains valid

**Difficulty Calibration**:
- Legitimate browsers can compute PoW solutions in 100-500ms
- Large-scale attackers face multiplied computational costs
- Difficulty can be dynamically adjusted based on client behavior

**Advantages**:
- Language-agnostic: Works with any HTTP client willing to compute hashes
- Progressive: Can increase difficulty for repeat offenders
- Server-Verifiable: Solution can be verified instantly without lookup

**Limitations**:
- Adds latency for legitimate users (though typically under 1 second)
- Mobile devices may struggle with high difficulty
- Sophisticated attackers can deploy GPU clusters (though costs remain significant)

**Implementation Considerations**:
- Solutions should be time-limited (expire after 1-10 minutes)
- Cache PoW solutions for subsequent requests to the same resource
- Consider offering reduced difficulty for authenticated users or known good IPs

**Challenge Stacking**:
For high-value resources, challenges can be combined:
- CSS challenge first (low cost)
- JavaScript challenge second (medium cost)
- PoW challenge third (high cost, only for remaining suspects)

### 9.3 Honeypot Endpoints

Honeypots are decoy resources designed to detect and categorize automated access. Since legitimate human users never access honeypots, any request to these endpoints indicates bot activity.

#### How Honeypots Work

**The Fundamental Principle**:
Human users navigate websites by following visible links and interacting with displayed content. They cannot see or access content that isn't rendered in their browser. Automated scrapers, however, parse raw HTML and may follow any URL they encounter—including hidden ones.

MaluWAF creates honeypot endpoints that:
1. Appear as valid links in the HTML source
2. Are invisible to human users through CSS styling
3. Trigger bot detection when accessed

#### Honeypot Types

**Hidden Link Honeypots**:
Links embedded in page content but hidden from users:
```html
<a href="/admin/login.php" style="display: none;"> </a>
<a href="/wp-admin/" class="hidden"> </a>
<!-- Invisible navigation -->
```

Any request to these paths immediately flags the client as a bot.

**Form Honeypots**:
Forms with hidden fields that legitimate users won't fill:
```html
<input type="text" name="email_confirm" style="display: none;">
<input type="text" name="website" placeholder="Leave empty">
```

If the honeypot field contains any value, the submission came from a bot that auto-fills all form fields.

**Attribute-Based Detection**:
Links with specific attributes that distinguish them from real navigation:
- Links with `rel="nofollow"` that aren't from user-generated content
- Links to administrative paths that shouldn't be linked from public pages
- URLs containing obvious bait patterns (e.g., `/admin`, `/login`, `/backup`)

**Proactive Scanning Detection**:
Beyond passive honeypots, MaluWAF can detect proactive scanning:

**Common Vulnerability Scanning**:
Requests to known vulnerability paths indicate reconnaissance:
- `/phpinfo.php`, `/info.php`
- `/wp-admin/`, `/wp-login.php`
- `/administrator/`
- `/phpmyadmin/`
- `/server-status`
- Git/SVN repository paths (`.git/config`, `.svn/`)
- Backup files (`.bak`, `.swp`, `~`)

**Crawlers Ignoring Robots.txt**:
While not enforced, tracking requests that explicitly violate robots.txt directives helps identify aggressive scrapers.

#### Benefits of Honeypots

1. **Zero False Positives**: Humans literally cannot trigger honeypot detection
2. **Early Warning**: Detects reconnaissance and scanning before any actual exploitation
3. **Intelligence Gathering**: What paths attackers target reveals their objectives
4. **IP Reputation**: Honeypot triggers contribute to client threat scoring
5. **Low Overhead**: Minimal server resources required

#### Implementation

**Configuration**:
```toml
[bot_protection.honeypot]
enabled = true

# Hidden links to protect
paths = [
    "/admin",
    "/wp-admin",
    "/login",
    "/config",
    "/backup"
]

# Form field names to monitor
form_fields = [
    "email_confirm",
    "website",
    "url"
]
```

**Response Options**:
- **Log**: Record probe for intelligence
- **Block**: Immediately deny access
- **Stall**: Hold connection to waste scanner time
- **Redirect**: Send to entirely different content (misleading attackers)

**Whitelisting**:
Known security scanners (legitimate vulnerability assessment tools) can be whitelisted to avoid triggering honeypot blocks during authorized security testing.

---

## 10. Upload Validation and Malware Scanning

File uploads represent a significant attack vector—malicious files can compromise servers, spread malware, or exfiltrate data. MaluWAF provides comprehensive upload protection through multiple validation layers.

### 10.1 File Upload Protection

#### MIME Type Validation

MIME type validation determines file type to enforce security policies. MaluWAF supports two approaches:

**HTTP Content-Type Header**:
The simplest approach—trusting the client's declared content type:
```http
POST /upload HTTP/1.1
Content-Type: image/png
```
Fast but trivially bypassed (attacker can declare anything).

**Magic Bytes Detection**:
For higher security, MaluWAF inspects file contents (magic bytes):
```
File Signatures (first bytes):
JPEG:    FF D8 FF
PNG:     89 50 4E 47 0D 0A 1A 0A
PDF:     25 50 44 46
ZIP:     50 4B 03 04
EXE:     4D 5A
```

MaluWAF analyzes the first 8-16 bytes against known signatures, providing defense against:
- Extension spoofing (`malware.exe.png`)
- MIME type spoofing
- Double extensions (`shell.php.jpg`)

**Validation Modes**:
```toml
[site.upload.validation]
# Whitelist mode: only allow specified types
mode = "whitelist"
allowed_types = [
    "image/jpeg",
    "image/png", 
    "image/gif",
    "application/pdf"
]

# Or blacklist mode: block known dangerous types
# mode = "blacklist"
# blocked_types = ["application/x-executable", "application/x-msdownload"]
```

#### File Size Limits

Size limits prevent denial-of-service through massive uploads:

```toml
[site.upload]
max_file_size = "10MB"        # Individual file limit
max_request_size = "50MB"     # Entire multipart request
max_files = 10                # Files per request
```

#### Multipart Handling

HTTP file uploads use multipart/form-data encoding. MaluWAF parses multipart requests to:
- Extract individual file parts
- Validate each part's size and type
- Reject malformed multipart requests (defenses against parser attacks)

### 10.2 YARA-Based Malware Scanning

For environments requiring malware detection, MaluWAF integrates **YARA**—the pattern matching tool used by security researchers and antivirus products.

#### What is YARA?

YARA ("Yet Another Recursive Acronym") identifies malware by rules that describe patterns:

```yara
rule suspicious_powershell {
    meta:
        description = "Detects obfuscated PowerShell commands"
        severity = "high"
    
    strings:
        $cmd = "powershell" nocase
        $enc = "-enc" nocase
        $b64 = "-encodedcommand" nocase
        
    condition:
        any of them
}

rule encrypted_payload {
    meta:
        description = "Detects common payload encryption patterns"
        
    strings:
        $xor = "XOR"
        $aes = "CreateObject"
        $base64 = "FromBase64String"
        
    condition:
        2 of them
}
```

#### How MaluWAF Uses YARA

**Rule Loading**:
```toml
[site.upload.yara]
enabled = true
rules_dir = "/etc/maluwaf/yara-rules"

# Include built-in rules
include_builtin = true
```

MaluWAF loads all `.yar` and `.yara` files from the rules directory at startup. Rules can be organized into categories.

**Scanning Process**:
```
Upload Request Received
         │
         ▼
   ┌─────────────┐
   │ Size Check  │ ← Reject oversized files before scanning
   └──────┬──────┘
         │
         ▼
   ┌─────────────┐
   │ MIME Check  │ ← Quick rejection of obviously wrong types
   └──────┬──────┘
         │
         ▼
   ┌─────────────┐
   │  YARA Scan  │ ← Full content pattern matching
   └──────┬──────┘
         │
    ┌────┴────┐
    │ Match?  │
    └────┬────┘
   Yes    No
    │      │
    ▼      ▼
Quarantine Allow
```

**Performance Considerations**:
- **Timeout**: Scan failsafe (default 30 seconds) prevents resource exhaustion
- **Size Limits**: Files above threshold bypass scanning (default 50MB)
- **Streaming**: Large files are scanned in chunks to limit memory usage
- **Parallelization**: Multiple files scan concurrently

#### Quarantine Workflow

When YARA rules match, files enter quarantine:

```
┌─────────────────────────────────────────────────────────┐
│                  Quarantine Workflow                     │
└─────────────────────────────────────────────────────────┘

   YARA Match Detected
         │
         ▼
   ┌─────────────┐
   │   Quarantine│ ← Move to isolated storage
   │   Directory │   /var/lib/maluwaf/quarantine/
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │    Log      │ ← Record: filename, matched rules, 
   │   Event     │   client IP, timestamp, file hash
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │  Notify     │ ← Optional: email/Slack/webhook
   │  Admin      │   alert
   └──────┬──────┘
          │
          ▼
    ┌──────────┐
    │ Request  │ ← Client receives generic error
    │ Blocked  │   (no malware details)
    └──────────┘
```

**Quarantine Management**:
```bash
# View quarantined files
maluwafctl quarantine list

# Release false positive
maluwafctl quarantine release <file-id>

# Permanently delete
maluwafctl quarantine delete <file-id>

# Get file for analysis
maluwafctl quarantine fetch <file-id> --output /tmp/
```

#### Integration with External Threat Intelligence

MaluWAF can enrich YARA scanning with external threat data:

```toml
[site.upload.yara.threat_intel]
enabled = true

# Check file hashes against threat feeds
[site.upload.yara.threat_intel.hash_check]
enabled = true
feed_url = "https://threatfeed.example.com/hashes"

# Cache duration
cache_ttl = 3600  # seconds
```

Common integrations:
- **VirusTotal**: Query file hashes (requires API key)
- **AlienVault OTX**: Threat pulse indicators
- **Abuse.ch**: Malware Bazaar, Feodo Tracker
- **Custom feeds**: Organization-specific threat lists

### 10.3 Upload Security Best Practices

**Defense in Depth**:
1. Rename uploaded files (never use original filename)
2. Store outside webroot
3. Strip EXIF metadata from images
4. Convert to safe formats (PDF/A, PNG)
5. Set restrictive file permissions
6. Use CDN for served files

**Monitoring**:
- Track upload volumes for anomaly detection
- Log all upload attempts (success/failure)
- Monitor quarantine queue size

---

## 11. Node Auditing and Integrity

In a distributed P2P network, establishing trust between nodes is critical. MaluNet implements comprehensive auditing and integrity verification through cryptographic attestation, continuous monitoring, and verification pipelines.

### 11.1 Continuous Monitoring

MaluWAF nodes continuously monitor their own health and the health of the network around them:

#### Path Health

Path health monitoring tracks the reachability and quality of routes through the mesh:

```
Path Health Monitoring:

Edge WAF                                 Origin WAF
    │                                        │
    │──── Health Check (every 30s) ─────────►│
    │                                        │
    │◄─── Response (latency, status) ─────────│
    │                                        │
    │  ┌─────────────────────────────────┐   │
    │  │ Update Path Score               │   │
    │  │ - Latency: 45ms (good)          │   │
    │  │ - Packet loss: 0.1%             │   │
    │  │ - Jitter: 5ms                   │   │
    │  └─────────────────────────────────┘   │
    │
    ▼
Multiple Origin Options: Choose Best Path

┌─────────────────────────────────────────────┐
│  Origin-1: latency=45ms  score=0.95 ✓      │
│  Origin-2: latency=120ms score=0.72        │
│  Origin-3: unreachable     score=0.00     │
└─────────────────────────────────────────────┘
```

**Metrics Tracked**:
- Round-trip time (latency)
- Packet loss percentage
- Jitter (latency variance)
- Route stability (uptime percentage)

#### Upstream Health

Each WAF monitors its connected origin servers:

- **HTTP Health Checks**: Periodic GET requests to origin
- **TCP Connectivity**: Port availability
- **TLS Certificate Validity**: Expiration monitoring
- **Response Time**: Slow responses indicate problems

```toml
[upstream.health_check]
enabled = true
interval = "30s"
timeout = "5s"
unhealthy_threshold = 3
healthy_threshold = 2

# Endpoint to check
path = "/health"
expected_status = 200
```

#### Node Performance

Each node reports its operational metrics:

- **Connection Count**: Active connections
- **Throughput**: Requests per second, bytes per second
- **Error Rate**: 5xx responses, timeouts
- **Resource Usage**: CPU, memory, file descriptors

### 11.2 Attestation

Cryptographic attestation allows nodes to prove their identity and state to other nodes.

#### Signed Health Reports

Nodes periodically sign their health status:

```rust
struct HealthReport {
    node_id: NodeId,
    timestamp: u64,
    uptime_seconds: u64,
    connection_count: u32,
    cpu_usage: f32,
    memory_usage: f32,
    paths_healthy: Vec<PathStatus>,
    upstream_status: Vec<UpstreamStatus>,
}

impl Node {
    fn sign_health_report(&self, report: &HealthReport) -> Signature {
        let data = serde_json::to_vec(report).unwrap();
        self.mesh_id_key.sign(&data)
    }
}
```

**Why Sign Reports**:
- Prevents malicious nodes from claiming false health
- Allows trust decisions based on verified data
- Provides audit trail for accountability

#### Remote Verification

Any node can verify another's attestation:

```rust
fn verify_health_report(
    report: &HealthReport,
    signature: &Signature,
    node_cert: &NodeCertificate
) -> Result<bool> {
    // Verify signature using node's public key
    node_cert.public_key.verify(&report, signature)
}
```

**Verification Process**:
1. Receive health report with signature
2. Lookup node's certificate (via DHT or cache)
3. Verify certificate chain to genesis key
4. Verify signature matches report data
5. Check timestamp freshness (< 5 minutes old)

#### Audit Trails

All significant actions are logged with cryptographic signatures:

```
Audit Log Entry:

{
    "timestamp": 1700000000,
    "node_id": "waf-12345",
    "action": "block_ip",
    "details": {
        "ip": "192.168.1.100",
        "reason": "sql_injection",
        "duration": 3600
    },
    "signature": "base64-encoded-signature",
    "prev_hash": "base64-encoded-previous-entry"
}
```

**Chain Structure**:
- Each entry includes hash of previous entry
- Creates tamper-evident log
- Can prove historical actions to third parties

### 11.3 Verification Pipeline

The verification pipeline ensures request integrity at each hop:

```
┌─────────────────────────────────────────────────────────────┐
│                  Verification Pipeline                      │
└─────────────────────────────────────────────────────────────┘

Request Received (from edge node)
      │
      ▼
┌─────────────────┐
│ Signature Check │ ← Verify request authenticity
│                 │   1. Verify node certificate
│                 │   2. Verify request signature
│                 │   3. Check timestamp freshness
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Integrity Check │ ← Verify response hasn't been tampered
│                 │   1. Verify response signature
│                 │   2. Check content hash
│                 │   3. Verify Pass-Over Keypass (if enabled)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Attestation    │ ← Verify node health/status
│                 │   1. Fetch recent health report
│                 │   2. Verify signature
│                 │   3. Check node not compromised
└────────┬────────┘
         │
         ▼
    Allow / Block
```

#### Signature Check

Ensures the request actually came from the claimed node:

1. **Certificate Lookup**: Find node's certificate in DHT
2. **Chain Verification**: Verify certificate signed by trusted CA
3. **Signature Verification**: Verify request signature
4. **Timestamp Check**: Reject requests > 5 minutes old

#### Integrity Check

Ensures response hasn't been modified in transit:

1. **Response Signature**: Origin node signs response
2. **Content Hash**: Verify hash matches content
3. **Pass-Over Keypass**: If enabled, verify E2E encryption

#### Attestation Check

Ensures the node is healthy and trustworthy:

1. **Recent Report**: Fetch health report from last 5 minutes
2. **Signature Valid**: Verify signed by node's key
3. **Health Status**: Verify node reports healthy
4. **No Revocation**: Check node not in revocation list

### 11.4 Trust Scores

Nodes maintain trust scores for other nodes based on behavior:

```
Trust Score Components:

┌─────────────────────────────────────────────────────────────┐
│                    Trust Score                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐                                           │
│  │ Historical  │ 40%  Past behavior accuracy              │
│  │ Behavior    │     - Honest attestations                │
│  │             │     - Accurate health reports            │
│  └─────────────┘                                           │
│                                                             │
│  ┌─────────────┐                                           │
│  │ Uptime      │ 20%  Reliability                         │
│  │             │     - Consistent availability           │
│  │             │     - Quick reconnection                │
│  └─────────────┘                                           │
│                                                             │
│  ┌─────────────┐                                           │
│  │ Attestation │ 25%  Credibility                         │
│  │ Consistency │     - Reports match observations        │
│  │             │     - No contradictory info             │
│  └─────────────┘                                           │
│                                                             │
│  ┌─────────────┐                                           │
│  │ PGP/Key    │ 15%  Identity                            │
│  │ Reputation  │     - Known organization                │
│  │             │     - Verified identity                 │
│  └─────────────┘                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Trust Score = 0.4×behavior + 0.20×uptime + 0.25×consistency + 0.15×identity
```

**Actions Based on Trust**:
- **High Trust (> 0.8)**: Route sensitive traffic, share intelligence
- **Medium Trust (0.5-0.8)**: Standard routing, basic trust
- **Low Trust (< 0.5)**: Limited routing, monitoring increased
- **Revoked (0.0)**: No traffic routed, added to blocklist

---

## 12. System Architecture

### 12.1 Overseer > Master > Worker Model

MaluWAF uses a hierarchical process model designed for high availability, horizontal scalability, and zero-downtime operation.

```
┌─────────────────────────────────────────────────────────────┐
│                     Process Hierarchy                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                        Overseer                              │
│  • Global health monitoring                                  │
│  • Traffic distribution orchestration                        │
│  • Leader election (Raft consensus)                         │
│  • Configuration synchronization                             │
│  • Zero-downtime upgrade handling                           │
└─────────────────────────────────────────────────────────────┘
              │                           │
              ▼                           ▼
    ┌─────────────────┐         ┌─────────────────┐
    │   Master Node   │         │   Master Node   │
    │  ┌───────────┐  │         │  ┌───────────┐  │
    │  │  Worker   │  │         │  │  Worker   │  │
    │  │  Pool     │  │         │  │  Pool     │  │
    │  └───────────┘  │         │  └───────────┘  │
    └─────────────────┘         └─────────────────┘
```

#### The Overseer

The overseer is the root process that ensures system reliability:

**Health Monitoring**:
- Continuously monitors all master processes
- Detects hangs, crashes, or unresponsive states
- Triggers automatic restart of failed masters

**Configuration Synchronization**:
- Receives configuration updates from API or file
- Propagates changes to all masters with consistency guarantees
- Ensures all nodes run identical configurations

**Leader Election (Raft Consensus)**:
When multiple overseers run (for high availability), they use Raft consensus:

```
Raft Leader Election:

┌──────────┐     ┌──────────┐     ┌──────────┐
│ Overseer  │     │ Overseer │     │ Overseer │
│   (A)     │     │   (B)    │     │   (C)    │
└─────┬─────┘     └────┬─────┘     └────┬─────┘
      │               │                 │
      │   Candidate   │                 │
      ├──────────────►│                 │
      │◄──────────────┤                 │
      │               │                 │
      │               │   Voted for A   │
      │               ├──────────────►  │
      │               │◄───────────────┤
      │               │                 │
      │◄──────────────┤                 │
      │  (Leader)      │                 │
```

**How Raft Works in MaluWAF**:
1. **Leader Election**: On startup or leader failure, overseers request votes
2. **Log Replication**: Leader broadcasts configuration changes to followers
3. **Commitment**: Changes commit when majority acknowledge receipt
4. **Failure Detection**: Followers detect leader absence via heartbeat timeout
5. **Terms**: Each election increments term number; stale nodes are rejected

This ensures configuration consistency even if some nodes fail.

**Zero-Downtime Upgrades**:
The overseer manages rolling updates:
1. New binary deployed alongside existing
2. Overseer spawns new master with new binary
3. New master reports healthy
4. Old master gracefully drained
5. Old master exits
6. Repeat for all masters

#### The Master Process

The master acts as coordinator between overseer and workers:

**Site Configuration**:
- Each site has independent configuration
- Master manages routing rules, upstream pools, SSL certificates
- Changes to site config don't require restart

**Worker Management**:
- Spawns worker processes at startup
- Monitors worker health
- Distributes work across worker pools

**Health Reporting**:
- Reports metrics to overseer (connection counts, throughput, errors)
- Triggers failover if becoming unhealthy

#### Workers

Workers perform actual request processing:

**Unified Request Workers**:
- Handle all HTTP/HTTPS/HTTP3 traffic
- Run in Tokio's multi-threaded runtime
- Each worker can process thousands of concurrent connections

**Minifier Workers**:
- Background workers that optimize static content
- Minify HTML, CSS, JavaScript
- Generate compressed variants (gzip, brotli)
- Pre-compress assets for faster serving

### 12.2 Inter-Process Communication

Efficient IPC is critical for high-throughput request processing.

#### Unix Sockets

On POSIX systems (Linux, macOS), Unix domain sockets provide:
- Lower latency than TCP loopback
- No network stack overhead
- File system permissions for access control
- Abstract namespace option (no file system entry)

```
Socket Pair:
┌──────────────────┐        ┌──────────────────┐
│    Master        │        │    Worker        │
│                  │        │                  │
│  ┌────────────┐  │        │  ┌────────────┐  │
│  │ Send Loop  │──┼────────┼──│ Recv Loop  │  │
│  └────────────┘  │        │  └────────────┘  │
│                  │        │                  │
└──────────────────┘        └──────────────────┘
      Unix Socket
  (file descriptor passed)
```

**Message Format**:
```rust
struct IpcMessage {
    msg_type: MessageType,    // Request, Response, Health, Config
    site_id: u32,             // Which site
    payload: Vec<u8>,         // Serialized data
    flags: u32,               // Non-blocking, priority, etc.
}
```

#### Socket FD Passing (Zero-Downtime Upgrades)

For zero-downtime upgrades, MaluWAF passes listening socket file descriptors to new processes:

```
Upgrade Sequence:

1. Old Process (PID 1000) owns sockets
   ┌─────────────────────┐
   │ listen_fd = 3       │
   └─────────────────────┘

2. Fork new process (PID 1001)
   ┌─────────────────────┐
   │ listen_fd = 3       │  (same fd number!)
   └─────────────────────┘

3. Old process closes fd
   ┌─────────────────────┐
   │                    │
   └─────────────────────┘

4. New process accepts connections
   ┌─────────────────────┐
   │ listen_fd = 3       │
   └─────────────────────┘
```

The new process inherits the socket file descriptors—the operating system ensures both processes reference the same socket.

**SCM_RIGHTS**: This uses POSIX message passing with SCM_RIGHTS control message to pass file descriptors between processes.

#### Windows Named Pipes

On Windows, named pipes provide equivalent functionality:
- Named pipe server per master
- Workers connect as clients
- Similar message format to Unix sockets

#### Shared Memory

For high-frequency data sharing (rate limiting counters, blocklists):

```toml
[defaults.rate_limit_memory]
# Use shared memory for counters
use_shmem = true
max_ips = 1_000_000
```

Shared memory regions allow:
- O(1) counter updates without IPC
- Cross-process visibility
- Persistence across restarts

### 12.3 Platform Considerations

MaluWAF achieves best performance on Linux:

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| **Async I/O** | epoll (highly optimized) | kqueue | IOCP |
| **QUIC** | Full support | Full support | Full support |
| **Unix Sockets** | Full support | Full support | N/A (Named Pipes) |
| **Sockets FD Passing** | Full support | Full support | Limited |

#### Linux Optimizations

**epoll**: The Linux event notification interface:
- O(1) readiness notification
- Edge-triggered mode support
- Scales to millions of connections

**QUIC**: All platforms support QUIC via the Quinn library:
- Native HTTP/3 support
- Stream multiplexing
- 0-RTT connection resumption

**Transparent Huge Pages**: For shared memory regions:
- Reduces TLB misses
- Improves large-region access

#### macOS Considerations

**kqueue**: Similar capabilities to epoll:
- Good performance for moderate loads
- Some edge cases differ from Linux

**QUIC**: Runs consistently across platforms:
- Same performance characteristics on all platforms
- No platform-specific optimization differences

#### Windows Considerations

**IOCP (I/O Completion Ports)**:
- Windows async I/O model
- Different programming model than epoll/kqueue
- Adequate for most workloads

**Named Pipes**:
- Windows IPC mechanism
- Slightly higher latency than Unix sockets

---

## 13. Use Cases

### 13.1 Single Server Deployment

Simple deployment for small to medium websites:

```
Internet → MaluWAF → PHP-FPM
              │
              └──→ Static Files
```

### 13.2 High Availability Cluster

Production-grade deployment with failover:

```
Load Balancer
      │
   ┌──┼──┐
   ▼  ▼  ▼
MaluWAF MaluWAF MaluWAF
   │     │     │
   ▼     ▼     ▼
 App1   App2   App3
```

### 13.3 WAF Mesh DDoS Mitigation

Distributed WAF mesh for large-scale attacks:

```
               Attack Traffic
                    │
                    ▼
         ┌─────────────────┐
         │  Edge WAF Nodes │ (Traffic Aggregation)
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │ Scrubbing Center│ (WAF Mesh Cluster)
         └────────┬────────┘
                  │
                  ▼
         Clean Traffic to Origins
```

### 13.4 Multi-Region Deployment

WAF nodes across regions with synchronized protection:

```
US-East          EU-West         Asia-Pacific
  │                │                 │
  ▼                ▼                 ▼
WAF Node ←→ WAF Node ←→ WAF Node
  │                │                 │
  └────────────────┼─────────────────┘
                  │
                  ▼
           Origin Servers
```

---

## 14. Performance Considerations

### 14.1 Configuration Guidelines

Proper configuration of flood protection parameters is essential for balancing security with accessibility. The three key metrics—SYN global limits, connection limits, and half-open connection tracking—each serve different防护 purposes and must be tuned based on expected traffic patterns.

The SYN global limit controls how many incomplete TCP handshakes the system will track simultaneously. During a SYN flood attack, an attacker sends large volumes of SYN packets without completing the handshake, attempting to fill the system's table of half-open connections. The global limit ensures that even if many sources attack simultaneously, the system can continue serving legitimate users. For high-traffic environments handling 50,000 or more connections per second, a global SYN limit of 50,000 provides headroom while still defending against moderate attacks. Standard deployments serving typical websites can operate effectively with 10,000, while low-traffic sites may only need 5,000.

The connection global limit prevents total connection exhaustion regardless of source. This protects against distributed attacks from many different IP addresses, where each individual IP might be within acceptable limits but collectively they exceed system capacity. High-traffic deployments should allow 100,000 simultaneous connections, while standard sites typically need 20,000 and low-traffic sites around 5,000.

The half-open connection tracking limit determines how many incomplete handshakes can be tracked per destination. When a SYN arrives, the system allocates memory to track the in-progress handshake until either the connection completes or times out. This limit should be set high enough to accommodate legitimate bursts of traffic but low enough to limit the impact of SYN floods. The timeout for half-open connections defaults to 30 seconds, after which incomplete connections are cleaned up.

### 14.2 Memory Configuration

Rate limiting requires memory to track the state of each IP address that has recently contacted the server. In environments where millions of unique IPs may connect over time, memory consumption can become significant. The rate limiting system provides configuration options to tune memory usage for specific deployments.

The max_ips parameter controls how many unique IP addresses can be tracked simultaneously in the rate limiting state. When this limit is reached, older entries are evicted to make room for new ones. For most deployments, 1,000,000 entries provides sufficient tracking capacity while keeping memory usage reasonable—approximately 50-100MB depending on configuration. Smaller deployments may reduce this to save memory, while very large deployments handling significant traffic from diverse sources may need to increase it.

The cleanup_interval_secs parameter controls how often the system scans for and removes stale entries. More frequent cleanup keeps memory usage lower by removing entries for IPs that are no longer active, but consumes CPU cycles. Less frequent cleanup reduces CPU usage but allows stale entries to persist longer, potentially causing memory pressure. The optimal setting depends on traffic patterns—sites with many short-lived connections may benefit from more frequent cleanup, while sites with persistent connections can use longer intervals.

---

## 15. Security Considerations

### 15.1 Encryption

All traffic within the MaluNet mesh is encrypted by default, ensuring that data traversing the network cannot be intercepted or tampered with by third parties. The encryption architecture provides defense in depth through multiple mechanisms that address different threat models.

QUIC provides built-in TLS 1.3 encryption for all connections, meaning that every byte transmitted between nodes is authenticated and encrypted using modern cryptographic algorithms. TLS 1.3 represents a significant improvement over its predecessors, reducing the number of round trips required to establish a connection while eliminating support for deprecated cryptographic primitives. The combination of ChaCha20-Poly1305 for authenticated encryption and X25519 for key exchange provides strong security with good performance across diverse hardware.

Certificate verification between nodes ensures that connections are established only with legitimate network participants. Each node presents a certificate signed by the network's Certificate Authority, and connecting nodes verify this certificate before exchanging any sensitive data. This prevents man-in-the-middle attacks where an attacker might attempt to intercept traffic by presenting fraudulent credentials. The certificate chain ultimately traces back to the genesis key, establishing a root of trust for the entire network.

Optional pre-shared keys provide additional security for deployments requiring defense against sophisticated adversaries. When PSKs are configured, they are used in addition to certificate-based authentication, providing defense in depth. An attacker would need to compromise both the private key and the pre-shared key to successfully impersonate a node. PSKs are particularly valuable for high-security deployments or for securing communication within a single organization's infrastructure.

### 15.2 Authentication

Node authentication ensures that only legitimate participants can join the mesh network and that all communications can be attributed to verified nodes. The authentication system provides multiple mechanisms that can be combined based on deployment security requirements.

Token-based admission control serves as the first line of defense for new nodes joining the network. When a node attempts to connect, it must present a valid admission token that has been pre-configured by a network operator. This prevents random internet traffic from establishing connections to mesh nodes and provides a basic filtering mechanism. Tokens can be rotated periodically and revoked individually if compromised.

Key-based verification provides stronger authentication for global nodes, which serve as the trust anchors for the entire network. Global nodes maintain persistent cryptographic identities that are established during the initial network bootstrap process. Connections between global nodes verify these identities cryptographically, ensuring that only legitimate global nodes can participate in directory services and certificate issuance.

Network ID isolation enables multiple organizations to operate separate mesh networks that share infrastructure without interfering with each other. Each network has a unique identifier, and nodes will only connect to other nodes advertising the same network ID. This allows organizations to share physical nodes or hosting infrastructure while maintaining separate logical networks—a useful model for hosting providers or multi-tenant environments.

### 15.3 Trusted Path Routing

For particularly sensitive traffic, MaluNet supports trusted path routing where traffic is routed exclusively through nodes that have been verified through keysigning ceremonies. Unlike standard routing which may use any available node in the network, trusted path routing ensures that all intermediate nodes in the delivery chain meet elevated verification standards.

Nodes that have completed keysigning ceremonies receive a special "trusted" flag in their credentials. This flag indicates that the node's operator has undergone additional verification and has committed to following network policies. When routing requires trusted paths, the pathfinding algorithm selects only nodes carrying this flag, ensuring that sensitive traffic never traverses nodes that have only basic verification.

This capability is particularly valuable for organizations with regulatory compliance requirements, such as handling healthcare data subject to HIPAA or financial data subject to PCI-DSS. By restricting traffic flow to verified infrastructure, organizations can maintain the benefits of a distributed mesh network while meeting compliance obligations that may require knowing exactly where data traverses.

---

## 16. Future Directions

MaluNet continues to evolve with several areas of active development that will expand its capabilities and improve its effectiveness as a distributed security platform.

Enhanced P2P discovery represents a fundamental improvement to how nodes find and connect to each other. The current mesh networking provides basic connectivity, but implementing a full Kademlia-based Distributed Hash Table will enable more efficient peer discovery, particularly as the network grows to hundreds or thousands of nodes. Kademlia's XOR-based distance metric provides mathematically optimal routing, ensuring that lookups scale predictably with network size. This implementation will also enable improved fault tolerance, as the DHT can route around failed or unreachable nodes without central coordination.

Advanced threat intelligence through machine learning offers the potential to detect previously unknown attack patterns by analyzing traffic behavior rather than relying solely on signature matching. Traditional WAFs detect known attacks through pattern matching, but sophisticated attackers constantly develop new variants. Machine learning models can identify anomalous behavior that suggests attack development or reconnaissance, enabling proactive defense. This includes detecting distributed attack campaigns that coordinate across many sources, identifying compromised machines participating in botnets, and recognizing patterns that indicate new exploit techniques.

Performance optimization remains an ongoing effort as deployment scales increase. The transition to Rust has provided excellent baseline performance, but continued tuning for high-throughput environments will unlock additional capacity. This includes optimization of hot paths in the request processing pipeline, improved memory allocation patterns to reduce garbage collection pressure, and better utilization of modern CPU features including SIMD instructions for pattern matching.

---

## 17. Conclusion

MaluNet represents an ambitious approach to distributed web security. By combining a production-grade WAF built on Rust's safety guarantees with an experimental P2P CDN architecture, the project explores new territory in collaborative defense.

The hierarchical trust model—anchored by global nodes and extending through organizations to individual nodes—provides a framework for building trusted P2P networks. The Pass-Over Keypass system addresses the fundamental challenge of integrity in untrusted networks.

While still experimental, MaluNet offers a compelling vision: a world where organizations can pool resources for DDoS protection, where trust is cryptographic rather than institutional, and where the benefits of CDN-style protection are available to anyone willing to contribute a node.

---

## Appendix A: Key Features Summary

| Category | Features |
|----------|----------|
| **Attack Detection** | SQL Injection (libinjection fingerprinting), XSS (context-aware HTML parsing), SSRF, RFI, Path Traversal (Aho-Corasick), Command Injection, JWT Validation, LDAP Injection, SSTI, XXE, XPath Injection, Request Smuggling |
| **Flood Protection** | SYN Proxy, Token Bucket Rate Limiting, Connection Rate Limiting, UDP Flood Protection (O(1) Slotted Counters), Blackhole Mode |
| **Bot Mitigation** | AI Crawler Blocking (isbot integration), CSS Challenges, JavaScript Challenges (Navigator APIs, Canvas Fingerprinting), Proof-of-Work Challenges (Hashcash), Honeypot Endpoints |
| **Upload Security** | MIME Type Validation (whitelist/blacklist), Magic Byte Detection, File Size Limits, YARA Malware Scanning, Quarantine Workflow, Threat Intelligence Integration |
| **Architecture** | Overseer > Master > Worker Model, Raft Consensus (Leader Election), Zero-Downtime Upgrades (Socket FD Passing), Unix Sockets IPC, Shared Memory |
| **Transport** | HTTP/1.1, HTTP/2, HTTP/3 (QUIC) |
| **Protocols** | FastCGI, PHP-FPM, Granian (WSGI/ASGI/RSGI), WebSocket |
| **Security** | TLS 1.3, Post-Quantum Ready (Kyber/ML-KEM), YARA Scanning, Content Signing, Pass-Over Keypass |
| **Mesh Features** | P2P Communication, Threat Intelligence Sharing, Route Aggregation, Gossip Protocol (DHT Overlay), Hierarchical Trust Model |

---

## Appendix B: Technical Specifications

MaluNet is built using modern, production-ready technologies chosen for their security properties, performance characteristics, and ecosystem maturity. The technical stack reflects the project's focus on building a secure, high-performance foundation.

The implementation language is Rust 2021 Edition, which provides memory safety guarantees while maintaining performance comparable to C and C++. Rust's ownership model eliminates entire categories of memory-related vulnerabilities at compile time, making it particularly suitable for security-critical network infrastructure. The 2021 Edition represents the latest stable Rust with improved ergonomics and standardized features.

Asynchronous I/O is handled by Tokio, a runtime that provides cooperative multitasking for Rust applications. Tokio enables handling thousands of concurrent network connections within a single thread, dramatically reducing memory overhead compared to thread-per-connection models while maintaining the safety properties of Rust's type system. The runtime integrates seamlessly with async/await syntax, making concurrent code readable and maintainable.

The HTTP stack builds on Hyper, a production-grade HTTP implementation that supports HTTP/1.1, HTTP/2, and HTTP/3. Hyper is used by major projects including AWS and TiKV, demonstrating its reliability at scale. The HTTP/3 support is implemented through the Quinn library, providing QUIC protocol capabilities that enable modern transport features including 0-RTT connection resumption and connection migration.

Cryptographic operations rely on rustls for TLS implementation, providing modern, secure defaults without the complexity of OpenSSL. The x25519-dalek and ed25519-dalek libraries provide fast, secure implementations of elliptic curve cryptography used throughout the mesh networking for key exchange and digital signatures. Support for post-quantum key exchange through ML-KEM (Kyber) provides forward-looking security against quantum computing threats.

Data persistence uses SQLite in embedded mode, providing a lightweight, zero-configuration database suitable for configuration storage and local caching. SQLite's ACID guarantees ensure data integrity even in unexpected shutdown scenarios, while its single-file format simplifies backup and deployment.

The build system uses Cargo, Rust's package manager and build tool, with prost and tonic-build for generating Protocol Buffer code. This enables efficient binary serialization for mesh communication while maintaining type safety through code generation.

---

*This white paper describes the MaluNet project as of March 2026. The project is actively developed and specifications may change.*
