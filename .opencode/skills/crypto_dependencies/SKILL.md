---
name: crypto_dependencies
description: Cryptographic dependency analysis, post-quantum signature considerations, and supply chain security for crypto libraries.
---

# Crypto & Post-Quantum Dependencies

This skill documents the cryptographic dependencies in SynVoid, security considerations, and architecture decisions.

## Overview

SynVoid uses a multi-layered approach to cryptography:
- **TLS**: aws-lc-rs (C library, AWS-maintained)
- **Signatures**: ed25519-dalek, libcrux-ml-dsa
- **Key Exchange**: x25519-dalek (classical), `ml-kem` / aws-lc-rs (post-quantum, final FIPS 203)
- **Hashing**: sha2, sha3, hmac (pure Rust)

## Dependency Inventory

### Primary Crypto Crates

| Crate | Version | Language | Purpose |
|-------|---------|----------|---------|
| `aws-lc-rs` | 1.18.1 | C (compiled) | TLS 1.3, ML-KEM, ML-DSA |
| `quinn` | 0.11.9 | Rust | QUIC transport, HTTP/3 |
| `h3` | 0.0.8 | Rust | HTTP/3 protocol |
| `ring` | 0.17.14 | Rust + asm | DNS/QUIC crypto (transitive) |
| `libcrux-ml-dsa` | 0.0.10 | Pure Rust | ML-DSA signatures |
| `ml-kem` | 0.3.2 | Pure Rust | Final ML-KEM-768 (wasm-pow client; Phase 44) |
| `ed25519-dalek` | 2.2.0 | Pure Rust | Ed25519 signatures |
| `x25519-dalek` | 2.0.0 | Pure Rust | X25519 key exchange |
| `sha2` | 0.10 | Pure Rust | SHA-256/512 |
| `sha3` | 0.10 | Pure Rust | SHA3 |
| `hmac` | 0.12 | Pure Rust | HMAC |
| `aes-gcm` | 0.10 | Pure Rust | AES-GCM |
| `zeroize` | 1.9.0 | Pure Rust | Secret destruction |
| `subtle` | 2.6.1 | Pure Rust | Constant-time ops |
| `hkdf` | 0.12 | Pure Rust | Key derivation |
| `pbkdf2` | 0.12 | Pure Rust | Password KDF |

### Post-Quantum Crates

| Crate | Algorithm | Location | Status |
|-------|-----------|----------|--------|
| `ml-kem` | ML-KEM-768 (FIPS 203 final) | crates/synvoid-wasm-pow | ✅ Pure Rust, KAT-verified (Phase 44) |
| `libcrux-ml-dsa` | ML-DSA-44 (FIPS 204; `pqc::MlDsa44`) | pqc/ + mesh signing | ✅ Pure Rust (mesh hybrid signatures use **ML-DSA-44** — see `hybrid_post_quantum` skill; do not write ML-DSA-65/87 here) |
| `aws-lc-rs` | ML-KEM + ML-DSA | Cargo.toml / pqc | ✅ Via feature (server ML-KEM) |

Phase 44 removed `pqc_kyber` / `pqc_kyber_edit` (draft Kyber) from the
lockfile. Guard `pqc_backend_is_maintained_ml_kem` fails if either package
reappears without updated security metadata.

## Architecture

### Hybrid Key Exchange

SynVoid uses a hybrid approach for post-quantum key exchange in the WASM PoW module:

```
X25519 (classical) + final ML-KEM-768 (ml-kem client / aws-lc-rs server)
```

This provides defense-in-depth: even if one algorithm is compromised, the other provides security.
Both ends speak final FIPS 203 (verified interoperable); draft-Kyber encodings
are NOT wire-compatible despite matching sizes.

### TLS Stack

```
hyper-rustls → rustls (with aws-lc-rs feature) → aws-lc-rs
```

aws-lc-rs provides:
- TLS 1.3 implementation
- ML-KEM key encapsulation (via rustls-post-quantum)
- ML-DSA signatures

### Signature Architecture

| Operation | Crate | Algorithm |
|-----------|-------|-----------|
| Mesh signatures | ed25519-dalek | Ed25519 |
| YARA rules | ed25519-dalek | Ed25519 |
| DNS TSIG | ed25519-dalek | Ed25519 |
| Alternative | libcrux-ml-dsa | ML-DSA (available) |
| TLS | aws-lc-rs | Ed25519 + ML-DSA |

## Security Considerations

### Known Vulnerabilities

| CVE | Crate | Severity | Status | Mitigation |
|-----|------|----------|--------|------------|
| ~~RUSTSEC-2023-0079~~ | ~~`pqc_kyber`~~ | ~~High~~ | **Remediated (Phase 44)** | Migrated to maintained `ml-kem`; packages absent from graph |
| RUSTSEC-2023-0071 | rsa | Medium | No fix | Not actively used |

### KyberSlash (RUSTSEC-2023-0079) — closed Phase 44

- **Issue**: Division timing depends on secrets (draft `pqc_kyber`; no patched upstream).
- **Closure**: migrated wasm-pow to maintained final ML-KEM (`ml-kem` 0.3);
  `pqc_kyber`/`pqc_kyber_edit` absent from `Cargo.lock` (guard-enforced).
- **Evidence**: NIST FIPS 203 ML-KEM-768 KAT, round-trip + implicit-rejection
  tests in `crates/synvoid-wasm-pow/src/pqc.rs`, wasm32 check, wasm-pack build.
- **Do not** reintroduce draft-Kyber packages or add a deny ignore for an
  advisory the scanner cannot associate with a renamed package and call that coverage.

### rsa (Marvin Attack)

- **Issue**: Timing side-channel in RSA decryption
- **Severity**: Medium (CVSS 5.9)
- **Exposure**: LOW - transitive via yara-x, not invoked
- **Recommendation**: Acceptable risk

### Unmaintained Crates (Monitor)

| Crate | Source | Issue |
|-------|--------|-------|
| `ring` | hickory-proto, quinn-proto | Unmaintained but stable |
| `bincode` 2.0.1 | yara-x | Unmaintained (RUSTSEC-2025-0141) |
| `gimli` 0.33.1 | wasmtime transitive | Yanked but non-blocking |

## Language Summary

| Language | Crates | Status |
|----------|--------|--------|
| Pure Rust | Most crypto crates | ✅ Primary |
| C (aws-lc-rs) | TLS, post-quantum | ✅ Accepted - AWS maintained |
| C (ring) | DNS/QUIC | ⚠️ Unmaintained - transitive |

## Build Dependencies (Non-Executable)

These crates use C compilers at build time but don't add runtime C dependencies:

| Crate | Build Tool | Purpose |
|-------|------------|---------|
| `cc` | C compiler | Build aws-lc-rs |
| `cmake` | CMake | Build aws-lc-rs |

## Usage Guidelines

### Adding New Crypto

1. Prefer pure Rust implementations
2. For TLS, use rustls with aws-lc-rs
3. For post-quantum, consider hybrid mode
4. Use zeroize for secret data

### Feature Flags

```toml
# For TLS with post-quantum
rustls = { version = "0.23", features = ["prefer-post-quantum", "aws-lc-rs"] }

# For wasm-pow (final ML-KEM-768 + x25519 hybrid, Phase 44)
ml-kem = { version = "0.3", features = ["zeroize"] }
x25519-dalek = { version = "2", features = ["static_secrets"] }
```

## Dependencies File Reference

| File | Purpose |
|------|---------|
| `Cargo.toml` | Main workspace |
| `pqc/Cargo.toml` | ML-DSA workspace |
| `crates/synvoid-wasm-pow/Cargo.toml` | WASM PoW module |

## Monitoring

```bash
# Check for new vulnerabilities
cargo audit

# Check dependency tree
cargo tree -i <crate>

# Check duplicates
cargo tree --duplicates
```

---

Last updated: 2026-09-19
