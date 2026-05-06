# Reverse Proxy and WAF Improvement Plan

**Status**: Ready for implementation iteration
**Last updated**: 2026-05-05
**Scope**: True streaming via type-erased connection pool, HTTP/TLS/HTTP3 unification, routing benchmarks, and remaining deferred items.

This file contains all open, partially complete, and deferred work. Every item below should be treated as open unless a commit proves otherwise.

---

## 1. True Streaming via Type-Erased Connection Pool

**Why?**: We need to hit 1 million RPS. The current `hyper` client is typed to `Full<Bytes>`, which means it buffers the entire body before sending. Wrapping the body in a trait object (`Box<dyn ErasedBody>`) allows us to stream it, but normally requires an allocation per request. By "erasing" the body type at the connection pool level, we only box the connection occasionally, which is much faster.

### Phase 2: HTTP/1 Connection Adapter
- [ ] Implement `Http1PooledConnection` in `src/http_client/erased_pool.rs`.
- [ ] **Technical Detail**: This struct should hold a `hyper::client::conn::http1::SendRequest<BoxErasedBody>`.
- [ ] **Task**: Create a constructor that takes a `TcpStream`, wraps it in `TokioIo`, and performs the `http1::handshake`.
- [ ] **Goal**: A wrapper that can send a type-erased request and return a type-erased response.

### Phase 4: The Erased Connection Pool
- [ ] Implement `ErasedConnectionPool` logic.
- [ ] **Technical Detail**: Use a `Mutex<HashMap<PoolKey, VecDeque<SendRequest<BoxErasedBody>>>>`.
- [ ] **Checkout Logic**: Check the map for an idle `SendRequest`. If none, create a new connection.
- [ ] **Checkin Logic**: Crucial! When a response body is fully read (or the request fails), the connection must be returned to the pool.
- [ ] **Goal**: Avoid creating a new TCP connection for every request while still supporting dynamic body types.

### Phase 5: ErasedHttpClient Integration
- [ ] Create the `ErasedHttpClient` struct as the primary interface.
- [ ] **Task**: Integrate it into `src/http/server.rs` proxy path. When `BodyBufferingPolicy::Streaming` is set, use this client instead of the legacy one.
- [ ] **Goal**: First end-to-end true streaming request from client -> synvoid -> upstream.

---

## 2. Unify Protocol Behavior via `ProtocolAdapter`

**Why?**: Currently, the code to "Block with a 403" is copy-pasted across the HTTP, HTTPS, and HTTP/3 servers. This is dangerous because a bug fix in one might be missed in another. We want a "Write Once, Block Everywhere" architecture.

### Phase 4.5: `send_waf_response` Implementation
- [ ] Add `async fn send_waf_response(&self, intent: WafResponseIntent) -> Result<(), anyhow::Error>` to the `ProtocolAdapter` trait in `src/server/waf_handler.rs`.
- [ ] **HTTP/1 Task**: Implement it to build a `hyper::Response`, set the status code/body, and send it.
- [ ] **HTTP/3 Task**: Implement it to use the `h3` stream to send a response frame and then data.
- [ ] **Goal**: The WAF core can simply say `adapter.send_waf_response(intent).await` and it will "just work" regardless of the protocol.

---

## 3. Replace Deprecated Global Service Access (Performance)

**Why?**: Accessing global services (Threat Intel, Yara) via `ArcSwap` in the hot path causes CPU cache contention. It also risks "Config Drift" where a request uses different config versions for its headers vs its body.

- [ ] **Step 1**: Update `WafContext` to hold an `Arc<RequestServices>`.
- [ ] **Step 2**: In `UnifiedServerWorker::handle_connection`, pull the services *once* and put them into the context.
- [ ] **Step 3**: Update `WafCore::check_request_full` and internal detector methods to use the services from the context rather than `self.request_services.load()`.
- [ ] **Goal**: Zero atomic loads for services during the request lifecycle. Perfect consistency and higher throughput.

---

## 4. Phase 6: eBPF SYN-Level Dropping

**Why?**: This is the ultimate defense. If an IP is on our "Global Blocklist" (from Threat Intel or ASN rules), we shouldn't even let the TCP handshake finish. Dropping at the SYN level via XDP is 100x more efficient than blocking in the WAF.

- [x] **Step 1**: Add `IP_BLOCKLIST_V4` and `IP_BLOCKLIST_V6` maps to `ebpf-flood/src/maps.rs`.
- [x] **Step 2**: In `ebpf-flood/src/xdp.rs`, check these maps at the very beginning. If found, return `XDP_DROP` immediately.
- [x] **Step 3**: In `src/block_store.rs`, add a "hook" that whenever `block_ip` is called with "global" scope, it also tries to insert that IP into the eBPF maps if they are loaded.
- [ ] **Goal**: Known attackers are silenced at the network driver level before they consume a single byte of Synvoid's userspace memory.

---

## Verification Commands
- `cargo test --lib erased_pool` (Verify the pool logic)
- `cargo check --all-targets` (Ensure no regressions in protocol adapters)
- `cargo test --test integration_streaming` (New integration test for streaming)
