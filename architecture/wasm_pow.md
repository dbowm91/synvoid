# WASM Proof-of-Work (`synvoid-wasm-pow`)

## 1. Purpose and Responsibility

`crates/synvoid-wasm-pow` contains the **browser-side WASM module** served with challenge pages: it solves SHA-256 proof-of-work challenges, performs hybrid post-quantum key exchange with the edge node, and signs subsequent requests with derived session keys.

## 2. Capabilities

| Function | Behavior |
|----------|----------|
| `solve_pow(challenge, difficulty)` | Brute-force SHA-256 leading-zero search (nonce cap ~100M) |
| `verify_pow(challenge, nonce, difficulty)` | Reference verification (server logic mirrors `synvoid-challenge`) |
| `init_key_exchange` | X25519 + ML-KEM-768 hybrid exchange in two steps (key-request → key-confirm) |
| `sign_request` / `verify_response` | Session-key request/response signing |
| `audit_edge_nodes` | HEAD-probe reachability audit of mesh edge nodes |

Supporting types: `PqcKeyPair`, `PqcEncapsulationResult`, `KeyExchangeResult`, `MeshAuditResult`/`AuditResults`.

## 3. Integration

- Served as part of `ChallengeType::PowChallenge` / `MeshPowChallenge` flows issued by `synvoid-challenge` (see [`challenge_deep_dive.md`](./challenge_deep_dive.md)).
- ML-KEM-768 comes from the `pqc` crate backend (`pqc_kyber_edit`) — see [`pqc.md`](./pqc.md).
- Server-side PoW verification is constant-time (`has_leading_zeros_ct`) per the security invariant; this crate must remain algorithm-compatible with it.

## 4. Boundaries

- No HTTP client of its own; the host page/JS glue submits solutions.
- Difficulty and nonce limits must stay within `synvoid-challenge`'s configured bounds (1–32 bits).
