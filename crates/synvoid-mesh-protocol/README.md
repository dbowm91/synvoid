# synvoid-mesh-protocol

Low-capability mesh wire vocabulary and synchronous Ed25519/replay primitives.
The crate owns no mesh runtime, storage, transport, policy, or consensus.

## Sign, verify, and frame

```rust
use synvoid_mesh_protocol::{decode_with_length_prefix, encode_with_length_prefix, ProtocolSigner};

let signer = ProtocolSigner::new([7u8; 32]);
let message = b"hello mesh";
let signature = signer.sign(message);
assert!(signer.verify(message, &signature, &signer.get_public_key_bytes()));
let frame = encode_with_length_prefix(message)?;
let (payload, consumed) = decode_with_length_prefix(&frame)?;
assert_eq!(payload, message);
assert_eq!(consumed, frame.len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The sample key is for demonstration only. Callers own key generation, custody,
rotation, and zeroization policy. Hybrid-envelope parsing in this crate only
checks Ed25519; `synvoid-mesh` owns ML-DSA verification and trust composition.

## Compatibility contract

Rust API semver, serialized wire bytes, signature-envelope encoding, and the
mesh message version are separate compatibility surfaces. The current
`MESH_MESSAGE_VERSION` is `1`; the application handshake requires exact version
equality and rejects both older and newer unknown versions. The version covers
the current mesh message vocabulary/interpretation, not Rust package versions or
individual DHT record subprotocols. Add or change fields, enum ordering,
discriminants, framing, signature envelopes, or semantics only with an explicit
protocol migration, updated golden vectors, and mixed-version behavior tests.
Do not infer compatibility from `serde` succeeding.

Length-prefixed frames use a four-byte big-endian payload length, reject empty,
truncated, and over-10-MiB payloads before exposing a frame, and return the
consumed byte count so a caller may process following frames. Unknown enum
behavior is type-specific: `AckStatus::from_u8` maps unknown codes to
`InternalError`, `AnnounceAction::from_u8` returns an error, and serde enum
decoding rejects unknown variants. Callers must preserve those fail-closed
decisions rather than inventing fallback actions.

## Replay contract

Replay timestamps are Unix seconds. The accepted skew is at most 60 seconds
behind or ahead of caller-supplied `now`. The nonce cache is in-memory, capped at
10,000 entries; on saturation it evicts a portion of cached entries. State is
not persisted across restart, so the cache alone does not provide durable replay
protection. Callers validate and bound untrusted nonce strings before passing
them to `ReplayProtection`, choose a trustworthy wall clock, and decide whether
to persist higher-authority replay state. `check_and_add_at` is available for
deterministic tests.

The crate's Rust 1.85.0 packaged-consumer result is class-2 evidence only.
`external_support = false`; no publication or external compatibility guarantee
is implied.
