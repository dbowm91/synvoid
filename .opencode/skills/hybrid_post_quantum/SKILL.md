---
name: hybrid_post_quantum
description: Hybrid Ed25519 + ML-DSA-44 post-quantum mesh signature implementation and usage.
---

# Hybrid Post-Quantum Mesh Signatures

This skill provides guidance for implementing and using hybrid Ed25519 + ML-DSA-44 signatures for mesh messages in SynVoid.

## Overview

Hybrid signatures combine classical Ed25519 with post-quantum ML-DSA-44 to provide security against both classical and quantum adversaries. This is critical for mesh orchestration messages that establish trust chains and share threat intelligence.

## Key Files

- `crates/synvoid-mesh/src/mesh/hybrid_signature.rs` - Core `HybridSignature` type and serialization
- `crates/synvoid-mesh/src/mesh/ml_dsa.rs` - `MeshMlDsaSigner` wrapper around pqc crate
- `crates/synvoid-mesh/src/mesh/protocol.rs` - Extended `MeshMessageSigner` with hybrid methods
- `crates/synvoid-mesh/src/mesh/config.rs` - ML-DSA key configuration in `GlobalNodeConfig`

## Usage

### Creating a Hybrid Signature

```rust
use crate::mesh::protocol::MeshMessageSigner;
use crate::mesh::ml_dsa::MeshMlDsaSigner;
use std::sync::Arc;

let key_bytes = MeshMessageSigner::generate();
let mut signer = MeshMessageSigner::new(key_bytes);

// With ML-DSA
let ml_dsa = Arc::new(MeshMlDsaSigner::generate());
signer = signer.with_ml_dsa_signer(ml_dsa);

// Sign with hybrid (both Ed25519 and ML-DSA)
let content = b"mesh message content";
let hybrid_sig = signer.sign_hybrid(content);

// Sign with only Ed25519 (backward compatible)
let ed25519_sig = signer.sign(content);
```

### Verifying a Hybrid Signature

```rust
// Verify hybrid signature
if signer.verify_hybrid(content, &hybrid_sig) {
    // Signature is valid (both Ed25519 AND ML-DSA if present)
}

// Verify Ed25519 only (backward compatible)
let pk_bytes = signer.get_public_key_bytes();
if signer.verify(content, &ed25519_sig, &pk_bytes) {
    // Ed25519 signature is valid
}
```

### Configuration

In `GlobalNodeConfig`:

```rust
pub struct GlobalNodeConfig {
    pub ml_dsa_private_key_base64: Option<String>,
    pub ml_dsa_public_key_base64: Option<String>,
    // ... other fields
}
```

## Key Sizes

| Algorithm | Public Key | Signature |
|-----------|------------|-----------|
| Ed25519 | 32 bytes | 64 bytes |
| ML-DSA-44 | 1312 bytes | 2420 bytes |

Hybrid signature = 64 + 2420 + variable overhead ≈ 2500 bytes

## Feature Flag

Enable with `post-quantum` feature:

```toml
[features]
post-quantum = ["dep:rustls-post-quantum"]
```

## Backward Compatibility

The system maintains full backward compatibility:
- Messages signed without ML-DSA are still valid
- `verify_hybrid()` returns true if Ed25519 is valid (even without ML-DSA)
- Configuration fields are optional

## Testing

```bash
# Run ML-DSA tests
cargo test --lib -- ml_dsa

# Run hybrid signature tests
cargo test --lib -- hybrid

# Test with feature
cargo test --features pqc-mesh --lib -- ml_dsa
```

## Implementation Notes

1. **Use pqc crate**: The `pqc` crate (in workspace) provides ML-DSA-44 via libcrux
2. **Base64 encoding**: Always use `URL_SAFE_NO_PAD` for mesh/DHT data
3. **Fail-open for Ed25519**: Verify Ed25519 first; ML-DSA is optional
4. **Serialization**: Use `HybridSignature::to_bytes()` / `from_bytes()` for stable wire format

## Async Verification Pool

For CPU-intensive ML-DSA verification (1-5ms per operation), use `CryptoVerificationPool`:

```rust
use crate::mesh::CryptoVerificationPool;

// Create pool (defaults to available parallelism, min 4 threads)
let pool = CryptoVerificationPool::default_pool();

// Async verification via spawn_blocking
let result = pool.verify_ml_dsa(&vk_bytes, message, &signature).await;

// With pre-wrapped signer
let result = pool.verify_ml_dsa_with_signer(signer_arc, message, &signature).await;
```

Key characteristics:
- Uses `tokio::task::spawn_blocking` to avoid blocking async executor
- Pool size: `available_parallelism().max(4)` for proper CPU utilization
- Provides both low-level (raw bytes) and high-level (Arc<MeshMlDsaSigner>) APIs
- ML-KEM encapsulation/decapsulation also available async

Integration with `MeshMessageSigner::verify_hybrid()`:
```rust
// Current sync path (blocks async thread for ~1-5ms):
if signer.verify_hybrid(content, &hybrid_sig) { ... }

// Future async path (non-blocking):
if pool.verify_ml_dsa_with_signer(signer.arc_clone(), content, &hybrid_sig.ml_dsa_signature).await {
    // ML-DSA valid
}
```