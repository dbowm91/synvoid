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
- **Command Injection:** Detects shell commands and metacharacters.
- **JWT Validation:** JWT tokens are validated for signature and claims via `src/waf/attack_detection/jwt.rs` (not an attack detector).
- **XXE Detection:** XML External Entity injection detection via `src/waf/attack_detection/xxe.rs`.
- **Anomaly Scoring:** Optionally combines multiple low-severity signals to block sophisticated attacks.

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
- **Regex & libinjection:** High-performance pattern matching engines are used for rule evaluation
- **Streaming WAF:** True streaming attack detection via `StreamingWafCore` for chunked processing and multipart parsing (`src/waf/attack_detection/streaming.rs`)
- **Distributed Intelligence:** In a Mesh deployment, WAF nodes share blocked IP addresses and threat signatures in real-time, providing collective defense.
