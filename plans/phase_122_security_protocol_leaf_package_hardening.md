# Phase 122 Plan: DNSSEC-Keystore and Mesh-Protocol Leaf Package Hardening

Status: **PLANNED / READY AFTER PHASE 115** (2026-10-02).

Registered in: `plans/roadmap.md` and
`plans/standalone_crate_generalization_roadmap.md`.

## Goal

Harden two existing low-capability leaf crates for standalone-capable class-2
consumption without changing their ownership roles:

- `synvoid-dnssec-keystore` — private-key/signing/HSM custody boundary;
- `synvoid-mesh-protocol` — wire/identity/signature/replay vocabulary.

These are independent workstreams and may be implemented/verified separately.
Neither is automatically promoted to class 3.

# Workstream A — DNSSEC keystore

## A1. Public threat model

Document:

- assets: private signing material, HSM session/provider handles, metadata;
- attacker inputs: key files, paths/config, signing requests, PKCS#11 provider
  behavior;
- trust assumptions: filesystem/OS permissions, HSM, process memory;
- non-goals;
- secret exposure/logging rules;
- crash/restart behavior.

Reaffirm that normal DNS/query/transport code receives sealed signing handles and
cannot request raw private-key bytes.

## A2. Secret lifetime / zeroization audit

Audit every software-key representation and temporary buffer from generation,
decode/load, signing and rotation.

Use `zeroize` only where it meaningfully covers owned secret buffers; document
where cryptographic dependency internals control lifetime and cannot be proven
zeroized by this crate.

No false "all key material is zeroized" claim.

## A3. Persistence and crash consistency

Add deterministic tests for:

- interrupted/failed atomic replacement;
- malformed/truncated key metadata;
- permission-setting failure;
- stale temp artifacts;
- rotation rollback/fail-closed behavior;
- concurrent read/sign/rotate boundaries where supported.

Document Unix permissions and Windows behavior separately.

## A4. PKCS#11/HSM qualification

The `pkcs11`/`hsm` feature needs a feature-specific build/test lane. Prefer a
software PKCS#11 provider in CI if deterministic and supportable; otherwise
document the release qualification procedure and keep HSM support from being
implied by default-package proof.

Provider-load failures and unsupported mechanisms must fail closed with typed,
secret-safe errors.

## A5. RSA advisory disposition

Re-evaluate the current `rsa` dependency/advisory state during implementation.
Do not describe an unresolved upstream advisory as fixed. If no safe replacement
exists and RSA is required for DNSSEC compatibility, document exposure and
mitigations precisely and keep public-support promotion blocked as necessary.

## A6. Package proof

Add consumer docs/examples, explicit MSRV evidence and outside-workspace tests for
software-key sign/verify/rotate. HSM proof is feature-specific.

# Workstream B — mesh protocol

## B1. Wire-version contract

Turn the existing `MESH_MESSAGE_VERSION` and golden vectors into a written
compatibility contract:

- what the version covers;
- when it must change;
- major/minor or explicit compatibility policy;
- treatment of unknown/new enum variants;
- framing bounds;
- mixed-version handshake/rejection behavior where applicable.

Do not change wire format merely to make the policy easier.

## B2. Rust API versus wire API

Document separately:

- Rust semver surface;
- serialized/wire compatibility;
- cryptographic signature envelope compatibility;
- replay-cache behavior;
- constants that are protocol versus implementation detail.

Decide whether public enums need `#[non_exhaustive]`, wrapper decode types or an
explicit versioned envelope. Any wire-affecting change requires golden vectors and
mixed-version tests, not an incidental derive edit.

## B3. Replay/time assumptions

Make replay semantics consumer-facing:

- timestamp source/units;
- allowed skew/window;
- nonce/cache capacity;
- restart persistence non-guarantee;
- behavior on saturation/large time jumps;
- caller responsibilities.

Retain injectable deterministic time in tests.

## B4. Package proof

Add README/rustdoc quickstart showing framing/sign/verify/replay usage without
`synvoid-mesh`.

Run the Phase 115 outside-workspace consumer against the packaged tarball.

Declare/test MSRV appropriate to the actual dependencies; do not inherit the root
toolchain implicitly.

# Shared verification

```bash
cargo test -p synvoid-dnssec-keystore --profile ci
cargo test -p synvoid-mesh-protocol --profile ci
cargo test -p synvoid-mesh-protocol --doc --profile ci
RUSTDOCFLAGS="-D warnings" cargo doc -p synvoid-dnssec-keystore --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc -p synvoid-mesh-protocol --no-deps
cargo package -p synvoid-dnssec-keystore --allow-dirty
cargo package -p synvoid-mesh-protocol --allow-dirty
cargo publish -p synvoid-dnssec-keystore --dry-run
cargo publish -p synvoid-mesh-protocol --dry-run
cargo xtask <standalone-consumer-command> synvoid-dnssec-keystore
cargo xtask <standalone-consumer-command> synvoid-mesh-protocol
cargo xtask verify-release
cargo deny check
cargo audit
```

No actual publish.

## Acceptance criteria

DNSSEC keystore:

- explicit threat model and secret-lifetime claims;
- crash-consistency/permission tests;
- PKCS#11 qualification disposition;
- advisory state accurately documented;
- outside-workspace software-key consumer passes.

Mesh protocol:

- wire/Rust compatibility policies separated;
- golden/mixed-version coverage matches the declared evolution rule;
- replay/time assumptions are explicit;
- outside-workspace consumer passes.

Both remain class 2 unless Phase 123 registers later promotion.

## Rejection criteria

Reject implementation that:

- exposes raw DNSSEC private-key bytes for convenience;
- claims PKCS#11 support from compile-only evidence;
- papers over a security advisory;
- changes mesh enum representation without wire decision;
- equates Rust crate semver with wire compatibility;
- publishes either crate.
