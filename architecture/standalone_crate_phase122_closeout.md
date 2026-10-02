# Phase 122 Closeout — DNSSEC Keystore and Mesh Protocol Packages

Plan: `plans/phase_122_security_protocol_leaf_package_hardening.md`.
Date: 2026-10-02.
Disposition: **CLOSED CLASS 2** for both packages. `external_support=false`;
no publish or class-3 support promise. Live PKCS#11 provider qualification is
deferred, and class-3/public promotion is blocked while the RSA advisory remains
unresolved.

## DNSSEC keystore

- Added package README and class-2 metadata with Rust 1.85.0 consumer evidence.
- Replaced derived `Debug` for `HsmConfig` with redacted formatting; tests assert
  the PIN is absent from both `Debug` and `redacted()` output.
- Made owned generated/signing private-byte copies use `Zeroizing`; software key
  handles continue to expose only signing and public metadata. The guarantee
  does not cover internal RSA/Ed25519 dependency or PKCS#11 provider allocations,
  allocator copies, process memory, or OS state.
- Made same-directory temp files exclusive with `create_new`; an RAII cleanup
  removes partial/stale temp files on write/sync/rename failure. Tests prove
  failed replacement preserves an existing destination, propagates permission
  setting failure, rejects malformed metadata, retains the current active key
  after failed rotation, and allows an existing sealed signer to sign while the
  keystore rotates.
- Unix `0700` key directories and `0600` private files remain enforced; Windows
  DACL behavior is explicitly operator-owned and unverified by this crate.
- `pkcs11` remains opt-in with no silent software fallback. Default and feature
  test suites passed. No live PKCS#11 module/token was available; README records
  a release qualification procedure and makes no provider qualification claim.
- RSA signing support remains for DNSSEC compatibility. RustSec's
  `RUSTSEC-2023-0071` still has no patched release; README records exposure and
  mitigations. This is not represented as fixed. Class-3/public support remains
  blocked while this dependency/use remains.

## Mesh protocol

- Added standalone package README for framing, signing/verification, exact
  handshake version, enum decoding behavior, and replay/time assumptions.
- Added `is_compatible_message_version`; discovery and both transport
  handshake paths use exact equality with version 1. Golden and differential
  tests reject older/newer versions. No serialized bytes or enums changed.
- Fixed replay future-window comparison to avoid `u64` overflow and pinned
  near-maximum timestamp cases. Replay remains a process-local 10,000-entry
  cache; application callers bound nonce strings and own persistence needs.

## Verification

Passed:

- `cargo fmt --all -- --check`.
- `cargo test -p synvoid-dnssec-keystore --profile ci` — 30 unit, 12 boundary,
  3 doctests.
- `cargo test -p synvoid-dnssec-keystore --features pkcs11 --profile ci` —
  feature build passed (30 unit, 11 boundary, 3 doctests).
- `cargo test -p synvoid-mesh-protocol --profile ci` — 9 golden-vector tests.
- `cargo test -p synvoid-mesh-protocol --doc --profile ci` — passed.
- `cargo test -p synvoid-mesh --test protocol_contract --profile ci` — 6 tests.
- Both `RUSTDOCFLAGS="-D warnings" cargo doc ... --no-deps` commands passed.
- Both `cargo package ... --allow-dirty` and both `cargo publish --dry-run
  --allow-dirty` package/verification steps passed; Cargo aborted both uploads
  due to dry-run.
- Both packaged consumer tests passed outside the workspace on Rust 1.85.0,
  offline: keystore signing/verification/rotation and protocol
  signing/verification/framing/replay.
- `cargo test -p synvoid-repo-guards --test standalone_candidate_contract
  --profile ci` passed for all registered candidates.
- `cargo deny check` passed; `cargo audit` completed with six existing allowed
  unmaintained-crate warnings.

No HSM hardware or provider qualification is claimed. Phase 123 is eligible to reconcile this
state with the campaign's other blocked/deferred tracks and must preserve the
RSA and HSM residuals.
