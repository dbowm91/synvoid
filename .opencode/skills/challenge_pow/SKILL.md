---
name: challenge_pow
description: Challenge system — PoW, CAPTCHA-CSS, honeypot fields, mesh PoW, WASM solver. Use when touching bot challenges, difficulty tuning, or solver verification.
---

# Challenge & Proof-of-Work

## Overview

`crates/synvoid-challenge/` owns challenge types and pure verification logic
(no HTTP rendering); `crates/synvoid-wasm-pow/` owns the browser WASM solver
with hybrid X25519 + ML-KEM-768 key exchange (Phase 44: final ML-KEM via
`ml-kem` client / aws-lc-rs server — draft Kyber removed from the lockfile).

## Key Files

- `crates/synvoid-challenge/src/manager.rs` - `ChallengeManager`, `ChallengeConfig`
- `crates/synvoid-challenge/src/manager_pow.rs` - PoW issuance/verification
- `crates/synvoid-challenge/src/pow.rs` - Core PoW primitives
- `crates/synvoid-challenge/src/mesh_pow.rs` - `MeshPowManager`,
  `MeshPowChallenge`, `MeshPowSolution`, `MeshPowResult`, `MeshAuditResult`
- `crates/synvoid-challenge/src/css.rs` - CSS/crypto-challenge rendering data
- `crates/synvoid-challenge/src/honeypot.rs` - Honeypot-field challenges
- `crates/synvoid-challenge/src/types.rs` - `ChallengeType`,
  `ChallengeResult`, `ChallengePriority`
- `crates/synvoid-wasm-pow/src/lib.rs` - Browser WASM solver
- `crates/synvoid-wasm-pow/src/pqc.rs` - Solver-side post-quantum exchange

## Invariants

- **Constant-time verification**: PoW/solution comparison uses
  `subtle::ConstantTimeEq` — never early-return byte comparison
  (see `security_patterns`).
- **Bounded difficulty**: difficulty retunes are clamped; a config or mesh
  peer must not be able to set unbounded work factors (DoS via difficulty).
- **Solver/client split**: browser solver code (`synvoid-wasm-pow`) never
  decides enforcement — verification happens server-side in
  `synvoid-challenge`; solver output is untrusted input.
- **Mesh PoW is advisory**: `MeshPowResult` feeds reputation/policy layers,
  never direct request-path blocking (see `architecture/mesh_trust_domains.md`).

## Verification

```bash
cargo nextest run -p synvoid-challenge -p synvoid-wasm-pow --cargo-profile ci --profile ci
```
