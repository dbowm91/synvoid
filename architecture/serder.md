# Serialization Strategy Architecture

## 1. Purpose and Responsibility

The Serialization module (`src/serder.rs`) provides **serialization strategy documentation and migration guidance** for transitioning from serde/bincode to rkyv zero-copy deserialization, with feature-gated re-exports.

**Core Responsibilities:**
- Document serialization strategy across codebases
- Re-export rkyv derives when feature enabled
- Guide migration from serde to rkyv for critical paths

---

## 2. Serialization Paths

| Path | Format | Reason |
|------|--------|--------|
| DHT/Mesh/Persistence | Postcard | Compact, single-allocation encoding |
| IPC Messages | Postcard | Performance, type safety |
| High-perf paths | Rkyv | Zero-copy deserialization |
| Admin API | JSON | Human-readable, OpenAPI compatible |

---

## 3. Feature Gate

When `rkyv` feature is enabled:

```rust
pub use rkyv::{Archive, Deserialize, Serialize};
```

---

## 4. Integration Points

- **IPC**: Postcard for all IPC messages
- **Mesh**: Postcard for DHT and mesh protocol
- **Config**: Postcard for distributed state
- **Admin API**: JSON for REST endpoints

---

## 5. Key Implementation Details

- **Postcard**: Preferred for new code — compact, no-std compatible, single-allocation encoding
- **Rkyv**: For hot paths requiring zero-copy deserialization
- **Deterministic caveat**: Postcard is NOT cross-version/platform deterministic by default. Only `no_std` mode with explicit endianness provides deterministic output. Default `std` mode uses platform-native layout
- **Cross-language**: Postcard has implementations in multiple languages
