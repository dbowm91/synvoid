# WAF Security Pipeline

SynVoid features a multi-layered Web Application Firewall (WAF) pipeline that inspects every request and connection to protect against a wide range of threats. The pipeline is coordinated by the `WafCore` engine.

## Protection Layers

The WAF pipeline operates in several distinct phases, from the connection level to the application layer.

### 1. Connection Layer (Flood Protection)

The `FloodProtector` (`src/waf/flood/mod.rs:225-367`) provides comprehensive flood protection with multiple backends:

#### SYN Flood Protection
- **Half-open connection tracking:** Tracks incomplete TCP connections via `SynFloodProtector`
- **Per-IP rate limiting:** Default 50 SYNs/sec per IP, 10,000 SYNs/sec global
- **eBPF backend (Linux only):** Optional kernel-level tracking when `flood-ebpf` feature is enabled
- **Userspace backend:** Default fallback using atomic counters

#### Per-IP Connection Limiting
The `ConnectionLimiter` (`src/waf/traffic_shaper/limiter.rs`) enforces connection limits:
- **Global connection limit:** Default 20,000 concurrent connections
- **Per-IP limits:** Default 100 connections per IP
- **Burst tokens:** IP burst allowance (default 10) enables short-term bursts
- **Site-level tracking:** Per-site connection counting via `SiteConnectionLimiter`
- **Queue system:** When limits are hit, connections can queue (default 1000 queue size, 5000ms timeout)

#### TokenBucket Rate Limiting
The `TokenBucket` (`src/waf/traffic_shaper/bucket.rs`) provides precise rate-based limiting:
- **Capacity-based refilling:** Tokens refill at configurable rate (bytes/sec)
- **GlobalTrafficShaper:** Enforces ingress/egress bandwidth limits with burst allowance
- **SiteTrafficShaper:** Per-site bandwidth limits that can override global settings
- **AsyncTokenBucket:** Async-compatible version for request processing

#### Volumetric Mitigation
- **UDP Flood Protection:** `UdpFloodProtector` with per-IP (1000/sec) and global (100,000/sec) limits
- **Blackhole mode:** When attack detected, enters blackhole for configurable duration (default 60s)
- **ASN & GeoIP Blocking:** ASN tracking via `src/waf/asn_tracker.rs` (GeoIP blocking not fully implemented)

### 2. Protocol Layer (Request Sanitization)
- **HTTP Validation:** Ensures requests adhere to protocol standards (method validation, header size limits, URI length).
- **Header Sanitization:** Removes or modifies sensitive headers (e.g., `Server`, `X-Powered-By`) to prevent information leakage.
- **Request Smuggling Detection:** Inspects for inconsistent `Content-Length` and `Transfer-Encoding` headers.

### 3. Request Layer (Attack Detection)
The `AttackDetector` is responsible for deep packet inspection. It normalizes inputs (decoding URL-encoding, HTML entities, etc.) before running a battery of detectors:

- **SQL Injection (SQLi):** Uses pattern matching and `libinjection` for high-accuracy detection.
- **Cross-Site Scripting (XSS):** Identifies malicious scripts in paths, queries, headers, and bodies.
- **Path Traversal:** Blocks attempts to access files outside the intended directory.
- **SSRF & RFI:** Prevents Server-Side Request Forgery and Remote File Inclusion by validating URLs.
- **Pattern Detection:** Uses Aho-Corasick multi-pattern matching via `PatternDetector` trait (`src/waf/attack_detection/detector_common.rs:264`) for efficient bulk pattern matching. Implementations include `SstiDetector`, `LdapInjectionDetector`, `XPathInjectionDetector`, `OpenRedirectDetector`, `XxeDetector`, `CmdInjectionDetector`, `PathTraversalDetector`, `RfiDetector`, `SsrfDetector`, and `BasePatternDetector`.

### 4. Bot Detection Layer

Bot detection uses multiple techniques to distinguish real browsers from automated tools:

#### CSS Challenge (Honeypot)
The `CssManager` (`src/challenge/css.rs`) generates CSS-based challenges:
- **Valid CSS rules:** Use `@media (min-aspect-ratio: X/Y) and (max-aspect-ratio: X/Y)` with realistic aspect ratio ranges. Real browsers will match at least one rule and request the associated asset.
- **Invalid CSS rules:** Use impossible aspect ratios (negative or zero denominators). Only bots that don't parse CSS correctly will request these assets.
- **Flow:** Challenge page → Browser matches valid rule → Requests `/rnd-<name>.png` → Session verified → Cookie set
- **Bots that follow invalid links** are blocked immediately

#### HTTP Honeypot Traps
The `HoneypotTracker` (`src/challenge/honeypot.rs`) generates trap URLs:
- **Trap paths:** Random URLs under `/_waf_hp_<random>` that are hidden from real users
- **Hidden links:** HTML links with `display:none;visibility:hidden;opacity:0;position:absolute;left:-9999px;width:0;height:0` — invisible to humans but crawlable by bots
- **Per-IP tracking:** Each IP gets unique trap paths that expire after TTL
- **Hit detection:** Bots visiting trap URLs are immediately flagged

#### JS Challenge (WASM-based Proof of Work)
Browser verification via WASM-compiled JavaScript (`src/challenge/pow.rs`). Client must execute JavaScript to solve a SHA-256 proof-of-work puzzle, proving browser identity.

#### Proof of Work (PoW)
Computational puzzle requiring client to solve a computational challenge (`src/wasm_pow/`), effective against high-volume automated tools.

#### Behavioral Analysis
(Mesh mode only) Analyzes request timing, sequence entropy, and request patterns to identify non-human traffic.

### 5. Streaming WAF (Chunked Processing)

The `StreamingWafCore` (`src/waf/attack_detection/streaming.rs`) provides true streaming attack detection for large or chunked request bodies, enabling O(1) memory usage regardless of body size.

**Chunked Processing:**
- Processes data in configurable chunks (default 4096 bytes)
- Maintains a **trailing window** (512 bytes) to detect attacks spanning chunk boundaries
- Uses fragmented scanning via `check_body_fragments()` to avoid memory allocation and copying
- Bounded memory: configurable `max_buffered_bytes` (default 2MB) prevents memory exhaustion attacks

**Multipart Handling:**
- Parses `multipart/form-data` bodies via state machine: `LookingForBoundary` → `ReadingHeaders` → `ReadingField/SkippingFile`
- Distinguishes file uploads from form fields by inspecting `Content-Disposition` headers for `filename=`
- File content scanning is skipped (`SkippingFile` state) to avoid false positives on binary uploads
- Form fields are scanned for attack patterns using the same detection engine

**Trailing Window Mechanism:**
- Preserves last 512 bytes of each chunk to catch boundary-crossing attack patterns
- Enables detection of payloads like `1' OR '1'='1'` split across multiple chunks
- For multipart data, each field maintains its own `field_trailing_window` for intra-field boundary detection

**State Machine Transitions:**
```
None → LookingForBoundary → ReadingHeaders → ReadingField → (scan) → LookingForBoundary
                              ↓
                        SkippingFile → (scan) → LookingForBoundary
```

---

---

## Decisions & Actions

The WAF can take several actions based on its findings:

- **Pass:** The request is allowed through to the upstream.
- **Block:** Returns a configurable error page (e.g., 403 Forbidden).
- **Challenge:** Intercepts the request and serves a challenge (JS/CAPTCHA/PoW).
- **Tarpit:** Artificially delays the response to slow down the attacker.
- **Stall:** Silent stalling that wastes attacker time without sending a response.
- **Drop:** Immediately closes the connection.

---

## Performance & Scalability

### Zero-Copy Inspection

The WAF uses `BufferPool` and `PooledBuf` from `crates/synvoid-utils/src/buffer/pool.rs` to minimize data copying during inspection.

**BufferPool Architecture:**
- **Tiered Design:** Four buffer tiers (Small: 4KB, Medium: 64KB, Large: 256KB, Jumbo: 256KB+) with per-tier capacity limits
- **Sharded Pools:** 8 shards with per-shard arenas to reduce contention under concurrent load
- **Thread-Local Cache:** Each thread caches up to 16 buffers per tier for fast allocation without locking
- **Global Pool:** Fallback shared pool for cross-thread buffer allocation

**PooledBuf Lifecycle:**
- `BufferPool::acquire(size)` allocates from thread-local cache first, then shard arena
- On `Drop`, buffers return to thread-local cache (up to TLS_CACHE_SIZE) or shard arena (up to tier cap)
- Metrics track acquire/reuse rates per tier for monitoring

**Zero-Copy Benefits:**
- WAF inspection operates directly on pooled buffers without copying
- Streaming WAF uses `check_body_fragments()` to scan data in-place
- Multipart parsing maintains state without buffer duplication

### Parallel Processing (Async WAF Pipeline)

The WAF pipeline executes asynchronously at `src/waf/mod.rs:484-512` to maximize throughput:

**Pipeline Stages:**
1. **Flood Protection:** Non-blocking check via `FloodProtector::check()` returning `FloodDecision`
2. **Parallel Attack Detection:** `AttackDetector::check_request()` runs async with `.await`

**Async Execution Model:**
- Flood protection executes first, allowing connection-level blocking before body reading
- Attack detection awaits on `ad.check_request(ip, &http_method, path, query, headers, body)`
- Each stage can block/allow independently; early exit on block decision
- Violation tracking and threat level recording integrate with mesh for distributed intelligence

**Integration:**
- `check_request_full()` is the main entry point coordinating all stages
- Threat level and violation tracker update based on attack detection results
- Mesh mode enables shared blocked IPs and threat signatures across nodes

### eBPF Integration (Linux Only)

eBPF-based flood protection is available via the `flood-ebpf` feature on Linux only (`src/waf/flood/mod.rs:5-6`).

**Availability:**
- Conditionally compiled with `#[cfg(all(target_os = "linux", feature = "flood-ebpf"))]`
- Enabled via `flood-ebpf` Cargo feature flag
- Provides kernel-level traffic filtering via `src/waf/flood/ebpf_flood.rs`

**Benefits:**
- Kernel-space packet filtering reduces context switches
- Earlier drop decision before packet reaches userspace
- Higher throughput for volumetric attack mitigation

### Additional Performance Features

- **Regex & libinjection:** High-performance pattern matching engines for rule evaluation
- **Streaming WAF:** True streaming attack detection via `StreamingWafCore` for chunked processing and multipart parsing (`src/waf/attack_detection/streaming.rs`)
- **Distributed Intelligence:** In a Mesh deployment, WAF nodes share blocked IP addresses and threat signatures in real-time, providing collective defense.
