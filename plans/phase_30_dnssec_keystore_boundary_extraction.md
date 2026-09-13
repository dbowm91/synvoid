# Phase 30 Plan: DNSSEC Key-Custody Boundary Extraction

Status: complete (2026-09-12). Landing commit: `6351b39d442ee4295b4a24ae23d0c4b43304c92c`. Closure evidence: `architecture/track4_dependency_security_closeout.md`.

The body below is the executed handoff specification, preserved as historical implementation guidance.

Roadmap position: Track 4, Phase 30.

Primary goal: isolate DNSSEC private-key generation/signing/HSM/trust-anchor persistence from DNS transport/resolver/server code when doing so produces a clean one-way security boundary.

## Current state

`synvoid-dns` legitimately owns DNS/DNSSEC behavior but has a broad sensitive dependency set: Hickory resolver/protocol, QUIC/Hyper networking, RSA/Ed25519/SHA-1/SHA-2, PKCS#11 (`cryptoki`), zeroization, SQLite, RNG, libc/nix, caches and async runtime.

The high-value split is not authoritative-vs-recursive DNS solely for size. It is key custody. Private signing keys and HSM handles should ideally live behind a narrow signer/keystore contract so ordinary query parsing, caching, recursive resolution, and transport handling cannot accidentally acquire key-management authority.

SHA-1 must not be removed blindly: DNSSEC DS digest algorithm 1 and NSEC3 use protocol-defined SHA-1 semantics. The goal is dependency/authority isolation, not algorithm substitution outside standards.

## Target architecture

Create a dedicated crate only if the dependency graph remains one-way, tentatively `crates/synvoid-dnssec-keystore/`.

It may own:

- DNSSEC private key material wrappers with zeroization;
- KSK/ZSK generation/import/export policy;
- signing operations and algorithm dispatch;
- public-key/DNSKEY derivation;
- PKCS#11/HSM backend;
- secure key-file persistence/permissions;
- trust-anchor persistence/lifecycle only if it shares key-custody invariants and does not pull resolver/server authority downward;
- typed signer/keystore errors and key identifiers.

`synvoid-dns` should own:

- DNS wire parsing/encoding;
- authoritative/recursive server behavior;
- zone lifecycle/update/transfer;
- DNSSEC canonical RRset construction and validation policy where no private key is required;
- NSEC/NSEC3 proof construction;
- transport (UDP/TCP/DoT/DoH/DoQ);
- cache/coalescing/health behavior.

## Part A — Inventory private-key reachability

Audit at minimum:

- `dnssec_signing.rs`;
- `dnssec_key_mgmt.rs`;
- HSM/PKCS#11 modules;
- `trust_anchor.rs`;
- TLS certificate/key resolver interactions;
- dynamic update/zone signing call sites;
- mesh DNSSEC distribution if enabled.

For each function/type record whether it requires:

- private key bytes;
- HSM session/handle;
- public key only;
- canonical RRset bytes;
- protocol digest only;
- SQLite/file persistence.

This inventory determines the actual crate boundary. Do not move canonicalization/query logic into the key crate merely because signing calls it today.

## Part B — Define a narrow signer contract

Introduce a trait/API along the lines of:

- enumerate key metadata/public DNSKEY;
- sign canonical bytes with a named key/algorithm;
- rotate/generate/import keys through explicit management methods;
- report key lifecycle state without exposing private bytes.

Requirements:

- request/query path cannot retrieve raw private key material;
- HSM handles remain opaque;
- algorithm selection is validated against DNSSEC policy before signing;
- signatures are over caller-supplied canonical bytes with explicit algorithm/key ID;
- key management operations are not mixed into ordinary query response methods.

If direct trait objects on the hot path are undesirable, use an enum/backend handle with the same authority restrictions.

## Part C — PKCS#11/HSM isolation

Move `cryptoki` to the keystore crate/feature if possible.

Keep HSM concerns out of the normal DNS server dependency graph when HSM support is not enabled:

- feature `pkcs11`/`hsm` off unless configured/required;
- no dynamic library/provider loading on normal software-key builds;
- PINs/secrets never logged;
- HSM errors typed and fail closed for zones configured to require HSM keys;
- no silent fallback from HSM-required signing to software keys.

## Part D — Secure software-key storage

Preserve or strengthen:

- mode `0600` on Unix private key files;
- atomic write/rename where used;
- directory permission checks;
- zeroization of temporary private-key buffers;
- no private keys in JSON/OpenAPI/admin DTOs, logs, metrics labels, panic messages or debug output;
- explicit backup/import semantics.

Add tests around permissions and error paths on supported platforms.

## Part E — Trust anchors

Treat trust anchors separately from private signing keys in the design even if they share the crate.

The root trust anchor file currently contains public DNSKEY material. Ensure extraction does not incorrectly classify it as a secret. Trust-anchor lifecycle needs authenticity/freshness and RFC behavior, whereas private signing keys need confidentiality.

If combining these responsibilities makes the crate conceptually broad, leave trust-anchor validation/persistence in `synvoid-dns` and extract only signer/key custody.

## Part F — Mesh and distributed key semantics

If mesh distributes DNSSEC public material or coordinates signing state:

- preserve Phase 23 canonical/advisory authority rules;
- never distribute raw private signing keys through DHT/best-effort gossip;
- any global key-management mutation must retain typed canonical/quorum outcomes;
- signed public artifacts must bind key ID/version/algorithm/zone.

Do not introduce cross-node private-key replication as part of this extraction.

## Part G — Crypto dependency placement

After extraction, inspect:

```bash
cargo tree -p synvoid-dns
cargo tree -p synvoid-dnssec-keystore
cargo tree -i cryptoki --workspace
cargo tree -i rsa --workspace
```

The target is not to remove protocol-required crypto from DNS entirely. It is to confine private-key generation/signing/HSM dependencies to the custody boundary and make optional HSM support genuinely optional.

## Required tests

Add/migrate:

- RSA/Ed25519 known-answer sign/verify tests;
- DNSKEY derivation/key-tag compatibility tests;
- KSK/ZSK lifecycle/rotation characterization;
- HSM mocked/backend failure tests;
- no-fallback test for HSM-required zones;
- private-key file permission/atomic persistence tests;
- zeroization-sensitive type tests where observable safely;
- DNSSEC authoritative response golden/interoperability tests before/after extraction;
- NSEC/NSEC3 and DS digest tests proving protocol SHA-1 uses remain correct;
- feature-disabled compile tests with no `cryptoki` in the graph;
- guard preventing private key types from appearing in admin/serde response DTOs.

## Documentation updates

Update:

- DNS/DNSSEC architecture docs;
- key/HSM operator documentation;
- security invariants in `AGENTS.md`;
- crate granularity audit;
- dependency ownership ledger;
- feature/profile docs if a new HSM feature is introduced.

## Acceptance criteria

Phase 30 is complete when:

- private signing-key/HSM authority is behind a narrow explicit boundary;
- DNS query/transport/resolver code cannot access raw private keys through normal APIs;
- PKCS#11 dependency is isolated/optional where technically feasible;
- software-key permissions/zeroization/fail-closed behavior are preserved;
- no private-key replication is introduced through mesh;
- DNSSEC wire behavior and interoperability remain compatible;
- protocol-required SHA-1 uses remain explicit and narrowly scoped rather than globally removed;
- dependency-tree evidence demonstrates meaningful authority reduction.

If the inventory proves extraction would create cycles or force more dependencies downward than it removes, stop and document that result rather than creating a low-value crate. A rejected extraction with evidence is an acceptable Phase 30 outcome; silent broadening is not.

## Rejection criteria

Reject an implementation that:

- moves the entire DNSSEC subsystem solely to reduce `synvoid-dns` LOC;
- exposes private key bytes through a generic keystore getter;
- silently falls back from required HSM keys to software keys;
- replaces DNSSEC/NSEC3 SHA-1 uses outside protocol requirements without standards analysis;
- changes zone signing/rotation semantics incidentally;
- replicates private keys through DHT/Raft as part of crate movement.

## Verification

```bash
cargo test -p synvoid-dns --all-targets
cargo test -p synvoid-dnssec-keystore --all-targets   # if extraction proceeds
cargo check -p synvoid-dns --no-default-features
cargo xtask verify
./scripts/dns/conformance.sh
cargo tree -i cryptoki --workspace
cargo tree -i rsa --workspace
cargo deny check
cargo audit
```