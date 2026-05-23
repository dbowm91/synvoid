# WAF Security Pipeline

SynVoid features a multi-layered Web Application Firewall (WAF) pipeline that inspects every request and connection to protect against a wide range of threats. The pipeline is coordinated by the `WafCore` engine.

## Protection Layers

The WAF pipeline operates in several distinct phases, from the connection level to the application layer.

### 1. Connection Layer (Flood Protection)
- **Volumetric Mitigation:** Protects against SYN floods, UDP floods, and connection exhaustion via `FloodProtector` (`src/waf/flood/mod.rs:225-367`)
- **SYN Flood Protection:** Half-open connection tracking to limit simultaneous incomplete connections
- **Per-IP Connection Limiting:** `ConnectionLimiter` (`src/waf/traffic_shaper/limiter.rs`) tracks connection counts per IP
- **TokenBucket Rate Limiting:** Precise refill-based rate limiting with global and per-IP isolation (`src/process/ipc_rate_limit.rs:132-141`)
- **eBPF Integration:** (Linux only, `flood-ebpf` feature) Kernel-level traffic filtering via `src/waf/flood/ebpf_flood.rs`
- **ASN-Based Blocking:** ASN tracking via `src/waf/asn_tracker.rs` detects distributed scraping campaigns by monitoring request volume per ASN. Uses GeoIP for IP→ASN lookups (GeoIP country blocking not implemented).

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
- **Command Injection:** Detects shell commands and metacharacters.
- **JWT Validation:** JWT tokens are validated for signature and claims via `src/waf/attack_detection/jwt.rs` (not an attack detector).
- **XXE Detection:** XML External Entity injection detection via `src/waf/attack_detection/xxe.rs`.
- **Anomaly Scoring:** `ThreatLevelManager` (`src/waf/threat_level/mod.rs`) uses statistical anomaly detection. Collects metrics (requests/minute, attacks/minute, rate-limit hits/minute), calculates baseline during learning period, then uses z-score comparison to determine threat level. Optional SQLite-backed history (`persistence/sqlite.rs`) for long-term analysis.

### 4. Bot Detection Layer
- **CSS Honeypot:** Hidden CSS links (`src/challenge/css.rs`) that flag bots visiting trap URLs
- **JS Challenge:** Browser verification via JavaScript execution (`src/challenge/js.rs`)
- **CAPTCHA:** Integration for intrusive verification when needed
- **Proof of Work (PoW):** Computational puzzle to slow automated tools (`src/wasm_pow/`)
- **Honeypots:** Hidden CSS links and trap endpoints that only bots will follow.
- **Challenges:**
  - **JS Challenge:** Requires the client to execute a simple JavaScript snippet to prove it's a browser.
  - **CAPTCHA:** Integration for more intrusive verification when needed.
  - **Proof of Work (PoW):** Requires the client to solve a computational puzzle, effective against high-volume automated tools.
- **Behavioral Analysis:** (Mesh mode only) Analyzes request timing, sequence entropy, and entropy to identify non-human traffic patterns.

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

- **Zero-Copy Inspection:** Minimizes data copying during inspection via `BufferPool` and `PooledBuf` types (`src/waf/attack_detection/streaming.rs`)
- **Parallel Processing:** Different layers of the WAF execute concurrently where possible via async pipeline (`src/waf/mod.rs:484-512`)
- **Regex & libinjection:** High-performance pattern matching engines are used for rule evaluation. The `PatternDetector` trait (`detector_common.rs:264`) provides Aho-Corasick pattern matching used by 11 detectors (XssDetector, SqliDetector, SstiDetector, XxeDetector, XPathInjectionDetector, SsrfDetector, RfiDetector, LdapInjectionDetector, PathTraversalDetector, OpenRedirectDetector, CmdInjectionDetector). The `pattern_detector!` and `url_decode_detector!` macros simplify detector creation.
- **Streaming WAF:** True streaming attack detection via `StreamingWafCore` for chunked processing and multipart parsing (`src/waf/attack_detection/streaming.rs`)
- **Distributed Intelligence:** In a Mesh deployment, WAF nodes share blocked IP addresses and threat signatures via `ThreatIntelligenceManager` (`src/mesh/threat_intel.rs`). Local blocks are announced via `announce_local_block()` and published to DHT. Incoming threats from peers are validated via signature verification and reputation scoring before application.
