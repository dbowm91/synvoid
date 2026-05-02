# IPC Framing Copies Analysis

## Priority 7: Reduce IPC Framing Copies and Make Message Size Policy Explicit

**Status**: DOCUMENTED (not implemented)

---

## 1. Where Copies Happen in `read_message()`

**File**: `src/process/ipc_framing.rs`

### `read_message_sync()` (lines 96-97)
```rust
let data = buffer[4..total_needed].to_vec();  // COPY #1
buffer.drain(..total_needed);                 // DRAIN
```
- Extracts message payload into a new `Vec<u8>` via `to_vec()`
- Then drains the data from the read buffer
- Deserializes from the new Vec

### `read_message()` (async, lines 215-216)
```rust
let data = buffer[4..total_needed].to_vec();  // COPY #1
buffer.drain(..total_needed);                 // DRAIN
```
- Identical copy pattern to sync version

**Impact**: At 1MB max message size, each message read triggers a 1MB allocation and copy.

---

## 2. Where Copies Happen in `serialize_signed()`

**File**: `src/process/ipc_signed.rs` (lines 420-444)

```rust
pub fn serialize_signed<T: serde::Serialize>(msg: &T, signer: &IpcSigner) -> io::Result<Vec<u8>> {
    let payload = crate::serialization::serialize(msg)?;  // ALLOCATION #1

    let timestamp = crate::utils::current_timestamp();
    let nonce = generate_nonce();

    // BUILD HMAC INPUT - ALLOCATION #2
    let mut hmac_data = Vec::with_capacity(TIMESTAMP_SIZE + NONCE_SIZE + payload.len());
    hmac_data.extend_from_slice(&timestamp.to_be_bytes());  // COPY timestamp
    hmac_data.extend_from_slice(&nonce);                      // COPY nonce
    hmac_data.extend_from_slice(&payload);                   // COPY payload again

    let hmac = signer.sign(&hmac_data);

    // BUILD FINAL FRAME - ALLOCATION #3
    let total_len = (TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE + payload.len()) as u32;
    let mut result = Vec::with_capacity(4 + total_len as usize);
    result.extend_from_slice(&total_len.to_be_bytes());  // COPY length header
    result.extend_from_slice(&timestamp.to_be_bytes());  // COPY timestamp again
    result.extend_from_slice(&nonce);                      // COPY nonce again
    result.extend_from_slice(&hmac);                       // COPY HMAC
    result.extend_from_slice(&payload);                    // COPY payload 3rd time

    Ok(result)
}
```

**Summary of copies in serialize_signed**:
| Stage | Data | Copies |
|-------|------|--------|
| Serialization | payload | 1 (initial serialize) |
| HMAC input build | timestamp + nonce + payload | 3 (timestamp, nonce, payload) |
| Final frame build | length + timestamp + nonce + HMAC + payload | 5 (length, timestamp, nonce, HMAC, payload) |

**Total copies of payload**: 3x (serialize output, HMAC input, final frame)

---

## 3. Where New Vec Allocation Happens Per Message (Signed)

**File**: `src/process/ipc_signed.rs`

### `SignedReader::read_message()` (lines 297-377)
```rust
fn read_message(&mut self) -> io::Result<()> {
    // ...
    let total_len = u32::from_be_bytes(len_buf) as usize;

    const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
    if !(TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE..=MAX_MESSAGE_SIZE).contains(&total_len) {
        // ...
    }

    let mut raw = vec![0u8; total_len];  // ALLOCATION #1 - reads entire message
    let n = self.inner.read(&mut raw)?;
    // ...

    let payload = &raw[TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE..];

    // BUILD HMAC INPUT FOR VERIFICATION - ALLOCATION #2
    let mut hmac_data = Vec::with_capacity(TIMESTAMP_SIZE + NONCE_SIZE + payload.len());
    hmac_data.extend_from_slice(&timestamp.to_be_bytes());
    hmac_data.extend_from_slice(&nonce);
    hmac_data.extend_from_slice(payload);  // copies payload slice

    // ...
    self.payload_buffer = payload.to_vec();  // ALLOCATION #3 - copies payload again
    self.payload_pos = 0;
    Ok(())
}
```

### `SignedIpcMessage::deserialize_signed_from_stream()` (lines 519-586)
```rust
let mut raw = vec![0u8; total_len];  // ALLOCATION #1
// ...
let payload = &raw[TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE..];

let mut hmac_data = Vec::with_capacity(TIMESTAMP_SIZE + NONCE_SIZE + payload.len());  // ALLOCATION #2
hmac_data.extend_from_slice(&timestamp.to_be_bytes());
hmac_data.extend_from_slice(&nonce);
hmac_data.extend_from_slice(payload);
// ...
crate::serialization::deserialize(payload)  // no additional copy if deserialize borrows
```

**Per-message allocations in signed receive**:
1. `vec![0u8; total_len]` - Full message buffer (up to 1MB)
2. `hmac_data Vec` - HMAC verification input (up to ~1MB + overhead)
3. `payload_buffer = payload.to_vec()` - Payload copy after verification

---

## 4. Current Message Size Limits

### Centralized Definition (single source of truth)

| Location | Constant | Value | Used By |
|----------|----------|-------|---------|
| `src/process/ipc_framing.rs:6` | `MAX_MESSAGE_SIZE` | 1 MB | `read_message_sync`, `read_message`, `write_message_sync`, `write_message` |

### Duplicated Definitions (NOT centralized)

| Location | Constant | Value | Notes |
|----------|----------|-------|-------|
| `src/process/ipc_signed.rs:314` | `const MAX_MESSAGE_SIZE` (inline) | 1 MB | Used in `SignedReader::read_message()` |
| `src/process/ipc_signed.rs:451` | `const MAX_MESSAGE_SIZE` (inline) | 1 MB | Used in `SignedIpcMessage::deserialize_signed()` |
| `src/process/ipc_signed.rs:531` | `const MAX_MESSAGE_SIZE` (inline) | 1 MB | Used in `SignedIpcMessage::deserialize_signed_from_stream()` |
| `src/tunnel/quic/framing.rs:8` | `DEFAULT_MAX_MESSAGE_SIZE` | 1 MB | Tunnel QUIC framing |
| `src/tunnel/quic/validation.rs:9` | `MAX_MESSAGE_SIZE` | 16 MB | QUIC validation layer |
| `src/tunnel/quic/validation.rs:10` | `DEFAULT_MESSAGE_SIZE` | 1 MB | QUIC validation layer |
| `src/tunnel/quic/ipc.rs:21` | `MAX_FRAME_SIZE` | 16 MB | Tunnel multiplex IPC |
| `src/mesh/transport.rs:83` | `MAX_MESSAGE_SIZE` | 10 MB | Mesh transport |

**Problem**: Three identical `1024 * 1024` constants in `ipc_signed.rs` instead of using the one from `ipc_framing.rs`.

---

## 5. IPC Traffic Classification

### Control-Plane (Cold Paths) - Copies Acceptable

These messages are low-frequency, administrative operations:

| Category | Examples | Frequency |
|----------|----------|-----------|
| **Worker Lifecycle** | `WorkerStarted`, `WorkerReady`, `WorkerShutdownComplete` | Per worker startup/shutdown |
| **Worker Heartbeat** | `WorkerHeartbeat` | Every ~5-30 seconds per worker |
| **Master Commands** | `MasterShutdown`, `MasterConfigReload`, `MasterHealthCheck` | Rare/one-time |
| **Upgrade Protocol** | `OverseerUpgradePrepare`, `UpgradeReady`, `UpgradeFailed` | During upgrades |
| **Drain Protocol** | `WorkerDrain`, `WorkerDrained`, `MasterDrainMode` | During drain operations |
| **Overseer** | `OverseerDrainWorkers`, `OverseerStatusResponse` | Rare |
| **Blocklist/Rules** | `BlocklistUpdate`, `RulePatternsUpdate` | Occasional updates |

**Rationale**: At most a few dozen messages per second across all workers, copies are negligible.

### Request Log Path (Warmer) - Could Benefit from Optimization

| Message | Payload Size | Frequency |
|---------|-------------|-----------|
| `WorkerRequestLog` | Request/response data (up to 1MB each) | Per request completion |
| `StaticWorkerRequestLog` | Same | Per static worker request |

**Current design**: Worker completes request, sends log to master, master aggregates. This is async relative to request handling.

### Hot Path (Request Critical) - Zero Copies Ideal

**Finding**: Based on code review, there is NO direct request-path IPC in the worker-to-master communication. The architecture uses:

1. **Worker handles request** - No IPC during request processing
2. **Request log sent after completion** - Async, acceptable latency
3. **Socket handoff** - Uses `SocketHandoffRequest` which passes file descriptors, not data

**Assessment**: The IPC path is NOT on the critical request path. Workers handle requests independently and only communicate with master for:
- Lifecycle (startup/shutdown/heartbeat)
- Logs (after request completes)
- Commands (reload/drain)

This is a good architectural decision - it avoids IPC overhead during request handling.

---

## 6. What Would Need to Change to Reduce Copies

### For `read_message()` (ipc_framing.rs)

**Current**:
```rust
let data = buffer[4..total_needed].to_vec();  // copy
buffer.drain(..total_needed);
let msg: T = crate::serialization::deserialize(&data)?;
```

**Zero-copy approach**:
```rust
// Create a cursor/view over the buffer without copying
let slice = &buffer[4..total_needed];
let msg: T = crate::serialization::deserialize(slice)?;
// Only advance read position, don't drain
read_offset += total_needed;
```

**Requirements**:
- Serialization crate must support deserializing from `&[u8]` slices without requiring `Vec`
- Need to track `read_offset` in buffer instead of draining
- Reuse buffer capacity across reads

### For `serialize_signed()`

**Current**:
- Serializes to `payload Vec`
- Builds HMAC input in new `Vec`
- Builds final frame in new `Vec`

**Lower-copy approach**:
```rust
// 1. Serialize directly into a BytesMut with capacity hint
let mut payload = BytesMut::with_capacity(estimated_size);
serde_json::Serializer::into Serializer::new(&mut payload);
// 2. HMAC can work on slices - compute HMAC over payload bytes directly
let hmac = signer.sign(payload.as_bytes());
// 3. Write header + payload in single write_all - no intermediate frame Vec
```

**Requirements**:
- Use `BytesMut` for serialization output
- `IpcSigner::sign()` already works on `&[u8]`, no change needed
- Use `write_all` with multiple slices instead of building final frame

### For `SignedReader`

**Current**:
- Allocates `raw Vec` for entire message
- Then copies `payload.to_vec()` into `payload_buffer`

**Lower-copy approach**:
```rust
// 1. Read into buffer
// 2. Verify HMAC over slices (no copy)
// 3. Store reference to payload slice in buffer, not a new Vec
// 4. Deserialize from the buffer slice directly
```

### For Message Size Limits

**Current state**: Scattered constants

**Centralized approach**:
```rust
// src/process/ipc_constants.rs
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;  // 1MB for general IPC
pub const MAX_LARGE_MESSAGE_SIZE: usize = 16 * 1024 * 1024;  // For bulk transfers

// Other modules import from here
pub use crate::process::ipc_constants::MAX_MESSAGE_SIZE;
```

**Consider different limits**:
- `MAX_MESSAGE_SIZE` (1MB) - Standard control messages
- `MAX_BULK_MESSAGE_SIZE` (16MB) - Blocklist snapshots, large rule sets
- `MAX_TUNNEL_MESSAGE_SIZE` (16MB) - Tunnel QUIC (already set)

---

## 7. Issues and Items Not Fully Resolved

### 1. Serialization Crate Compatibility

The current code uses `crate::serialization::serialize/deserialize`. Need to verify:
- Whether this is JSON, postcard, or bincode
- Whether `deserialize` can work on `&[u8]` slices directly

### 2. Buffer Reuse Strategy

For `read_message()`:
- Currently uses `Vec<u8>` passed as mutable reference
- Track offset instead of drain? But caller owns the buffer
- Need to understand buffer lifecycle from callers

### 3. QUIC Tunnel Framing vs Process IPC

Two separate framing systems:
- `src/process/ipc_framing.rs` - Unix socket IPC between processes
- `src/tunnel/quic/framing.rs` - QUIC streams for tunnel traffic

These serve different purposes and could have different optimization requirements.

### 4. Signed Reader State Machine

`SignedReader<R>` maintains `payload_buffer: Vec<u8>` and `payload_pos: usize`. This is necessary because:
- It reads the signed envelope first
- Then provides a `Read` interface for the payload

To eliminate the final `payload.to_vec()` copy, would need to change the interface to return slices instead of implementing `Read`.

---

## 8. Recommendations Summary

### Quick Wins (Low Effort, Some Benefit)
1. **Deduplicate `MAX_MESSAGE_SIZE` constants** in `ipc_signed.rs` - use the one from `ipc_framing.rs`
2. **Add metric** for rejected oversized messages
3. **Document** that IPC is not on the request hot path

### Medium Effort (Moderate Benefit)
4. **Use `BytesMut` for `serialize_signed()`** - avoid intermediate HMAC input Vec
5. **Reduce `serialize_signed()` copies** - write header + payload directly via scatter-gather

### Harder (High Effort, Lower Benefit - Not Needed)
6. **Zero-copy `read_message()`** - requires serialization API support for slice deserialization
7. **Buffer offset tracking** instead of drain - requires changing buffer lifecycle

**Priority**: Items 1-3 should be done regardless. Items 4-5 only if profiling shows IPC is a bottleneck (unlikely given traffic classification). Items 6-7 are likely not worth the complexity given cold-path classification.