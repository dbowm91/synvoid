# WASM Proof-of-Work (`synvoid-wasm-pow`)

## 1. Purpose and Responsibility

`crates/synvoid-wasm-pow` contains the **browser-side WASM module** served with challenge pages: it solves SHA-256 proof-of-work challenges, performs hybrid post-quantum key exchange with the edge node, and signs subsequent requests with derived session keys.

## 2. Capabilities

| Function | Behavior |
|----------|----------|
| `solve_pow(challenge, difficulty)` | Brute-force SHA-256 leading-zero search (nonce cap ~100M) |
| `verify_pow(challenge, nonce, difficulty)` | Reference verification (server logic mirrors `synvoid-challenge`) |
| `init_key_exchange` | X25519 + ML-KEM-768 hybrid exchange in two steps (key-request → key-confirm) |
| `ml_kem_backend()` | Returns backend identifier (`ml-kem/0.3 (FIPS 203 final, RustCrypto)`) for audits |
| `sign_request` / `verify_response` | Session-key request/response signing |
| `audit_edge_nodes` | HEAD-probe reachability audit of mesh edge nodes |

Supporting types: `PqcKeyPair`, `PqcEncapsulationResult`, `KeyExchangeResult`, `MeshAuditResult`/`AuditResults`.

## 3. Integration

- Served as part of `ChallengeType::PowChallenge` / `MeshPowChallenge` flows issued by `synvoid-challenge` (see [`challenge_deep_dive.md`](./challenge_deep_dive.md)).
- ML-KEM-768 uses maintained final FIPS 203 backends on both ends (Phase 44):
  client via RustCrypto `ml-kem` 0.3 (`crates/synvoid-wasm-pow/src/pqc.rs`),
  server via `aws-lc-rs` (`pqc` crate) — see [`pqc.md`](./pqc.md).
  Bidirectional cross-implementation interop (RustCrypto ↔ aws-lc-rs) is verified;
  draft-Kyber encodings are NOT wire-compatible with final ML-KEM despite matching
  sizes, which is why the pre-Phase-44 draft client silently fell back to X25519-only.
- Server-side PoW verification is constant-time (`has_leading_zeros_ct`) per the security invariant; this crate must remain algorithm-compatible with it.

## 4. Protocol compatibility (Phase 44)

All ML-KEM material is **ephemeral per-session challenge state**, never persisted:

| Datum | Size | Wire | Lifetime |
|-------|------|------|----------|
| Encapsulation (public) key | 1184 B | base64 `URL_SAFE_NO_PAD` in `KeyExchangeRequest.client_ml_kem_pubkey` → `/mesh/key-request` | one session |
| Ciphertext | 1088 B | base64 in `KeyExchangeResponse.server_ml_kem_ciphertext` | one session |
| Shared secret | 32 B | never transmitted; both sides combine with X25519 via `combine_wasm_secrets` | one session |
| Decapsulation (secret) key | 64 B seed (`d \|\| z`) | **client-local only**, never sent or stored | one session |

A fresh keypair is generated per `init_key_exchange` call and dropped after use.
No key material touches disk, localStorage, or the DHT. Upgrade skew needs no
migration: an in-flight session from an older release fails closed to
X25519-only through the existing fallback. The pre-Phase-44 2400-byte expanded
draft-Kyber secret format is gone; the 64-byte seed form is local-only so no
server change was required.

## 5. Backend provenance (Phase 44 KyberSlash closure)

- Before: `pqc_kyber_edit` 0.7.2 (renamed draft-Kyber fork). RUSTSEC-2023-0079
  (KyberSlash) is keyed to `pqc_kyber` with no patched upstream release, so a
  renamed package escaping `cargo audit` matching was never sufficient control —
  and the draft encoding was wire-incompatible with the server's final ML-KEM.
- After: RustCrypto `ml-kem` 0.3 (pure Rust, `no_std` + `alloc`, `zeroize` on
  drop). Conformance is proven by a NIST FIPS 203 ML-KEM-768 key-generation KAT
  (`generate_keypair_from_seed` vs key-gen.json tcId 26), round-trip tests,
  implicit-rejection tests, and size-boundary tests in `src/pqc.rs`.
- Verification: `cargo test -p synvoid-wasm-pow --profile ci`,
  `cargo check -p synvoid-wasm-pow --target wasm32-unknown-unknown`, and the
  `wasm-pack build --target web --release` path (278 KB vs 257 KB pre-migration).
- Guard: `pqc_backend_is_maintained_ml_kem` in
  `tools/synvoid-repo-guards/tests/dependency_security.rs` fails if
  `pqc_kyber`/`pqc_kyber_edit` reappears in the lockfile or any manifest without
  updated security metadata.

## 6. Secret handling

The WASM boundary must return owned bytes to JavaScript, so JS-visible secrets
cannot rely on Rust drop-zeroization (WASM linear memory is JS-readable).
Exposure is minimized to one session with no persistence. Inside Rust,
decapsulation keys zeroize on drop (`ml-kem` `zeroize` feature), seed buffers
use `Zeroizing<[u8; 64]>`, errors report sizes only, and `PqcKeyPair` /
`PqcEncapsulationResult` deliberately omit `Debug` to prevent secret leakage
through logging.

## 7. Boundaries

- No HTTP client of its own; the host page/JS glue submits solutions.
- Difficulty and nonce limits must stay within `synvoid-challenge`'s configured bounds (1–32 bits).
