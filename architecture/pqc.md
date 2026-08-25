# Post-Quantum Cryptography (`pqc`)

## 1. Purpose and Responsibility

The `pqc/` workspace crate provides **post-quantum primitives** — ML-KEM key encapsulation and ML-DSA signatures — used by mesh transport, integrity signing, and browser-side challenge/key-exchange flows. It wraps two vetted backends rather than implementing algorithms directly.

## 2. Primitives

| Primitive | Standard | Backend | Sizes (PK / SK / CT-or-Sig) |
|-----------|----------|---------|------------------------------|
| `MlKem768` | FIPS 203 | `aws-lc-rs` | 1184 B / 2400 B / 1088 B (SS = 32 B) |
| `MlKem1024` | FIPS 203 | `aws-lc-rs` | 1568 B / 3168 B / 1568 B |
| `MlDsa44` | FIPS 204 | `libcrux-ml-dsa` | 1312 B (VK) / 2560 B (SK) / 2420 B sig |

Key types: `SigningKey`/`VerifyingKey`, `PublicKey`/`SecretKey`/`SharedSecret`/`Ciphertext`. Signing keys zeroize on drop. Encoding helpers use Base64 `URL_SAFE_NO_PAD` (repo standard for all mesh/DHT data). A test-vector module checks conformance.

## 3. Consumers

- **Mesh hybrid signatures**: `synvoid-mesh::HybridSignature` = Ed25519 (64 B) ‖ ML-DSA-44 (2420 B), both-must-verify semantics via `HybridSigner`/`MeshMlDsaSigner` (see [`mesh_deep_dive.md`](./mesh_deep_dive.md) and the `hybrid_post_quantum` skill).
- **Integrity key exchange**: `synvoid-integrity` combines X25519 + ML-KEM-768 for origin-signed session keys (`origin_key_exchange` feature).
- **TLS**: server-side PQ is handled by rustls `prefer-post-quantum` + `aws-lc-rs` (root feature `post-quantum` is a marker); this crate is *not* in the TLS path.
- **Browser-side PoW crate**: `synvoid-wasm-pow` performs ML-KEM-768 encapsulation for edge key exchange (see [`wasm_pow.md`](./wasm_pow.md)).

## 4. Boundaries

- Pure crypto primitives only: no I/O, no async, no protocol logic.
- Feature `async` is enabled by the root app; default usage is synchronous.
