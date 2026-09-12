# DNSSEC Key-Custody Boundary (Phase 30)

Status: complete. Canonical crate: `crates/synvoid-dnssec-keystore/`;
`crates/synvoid-dns` keeps transport/resolver/server behavior plus
public-only validation and proofs. Guards:
`dnssec_keystore_boundary` (repo guards).

## 1. Goal

Isolate DNSSEC private-key generation, sealed storage, rotation, signing
dispatch, and HSM/PKCS#11 backing behind a narrow one-way boundary so
ordinary query parsing, caching, recursive resolution, and transport
handling cannot acquire key-management authority. This is a key-custody
split, not an authoritative-vs-recursive split and not a LOC reduction.

## 2. Ownership

| `synvoid-dnssec-keystore` (custody) | `synvoid-dns` (protocol/transport) |
|------------------------------------|------------------------------------|
| `SealedSigningKey` (opaque private bytes, `sign()`, DNSKEY/CDS derivation, public metadata) | Wire parsing/encoding, authoritative/recursive behavior |
| KSK/ZSK generation, sealed file persistence, rotation lifecycle (`DnssecKeystore`) | Zone lifecycle/update/transfer, canonical RRset construction |
| `DnssecSigner` trait (enumerate public DNSKEY, sign canonical bytes, explicit management ops) | NSEC/NSEC3 proof construction, DS/SHA-1 protocol uses |
| PKCS#11/HSM backend (`HsmSigner`, `HsmManager`, `SoftHsm`; `cryptoki` optional) | RFC 5011 trust anchors (public-only, SQLite; stays here per §6) |
| DS digest derivation for locally held keys only | Signature verification, key-tag, DS validation, TSIG |
| `KeyMetadata` (public-only shareable snapshot) | `MeshTrustAnchor` over `KeyMetadata` (public only) |

Dependency direction: `synvoid-dns` → `synvoid-dnssec-keystore`
(one-way). The keystore depends only on `synvoid-core` (time), serde,
`ed25519-dalek`, `rsa`, `sha1`/`sha2`, `getrandom`/`rand_core_06`,
`zeroize`, `parking_lot`, `tokio`, `tracing`, and optional `cryptoki`.
It never touches Hickory, Hyper, Quinn, SQLite, mesh, admin, or config
(the HSM config conversion lives in the `synvoid-dns` facade).

## 3. Inventory outcome (Part A)

| Area | Requires | Disposition |
|------|----------|-------------|
| `dnssec_signing::sign_data` | private bytes | moved (now `SealedSigningKey::sign`) |
| `dnssec_key_mgmt` generation/persistence/rotation/CDS | private bytes, files | moved (`DnssecKeystore`) |
| `hsm` PKCS#11 sessions, SoftHSM | HSM handles, PINs | moved (feature-gated) |
| `dnssec_validation` (key-tag, canonicalization, DS verify) | public key only | stays in `synvoid-dns` |
| NSEC/NSEC3/RRSIG wire construction | public metadata + caller signature | stays in `synvoid-dns` |
| `trust_anchor` RFC 5011 lifecycle | public keys, SQLite | stays in `synvoid-dns` (§6) |
| `mesh_dnssec` validation | public keys | stays; anchors narrowed to `KeyMetadata` |
| TSIG HMAC secrets | symmetric secrets on the query path by design | stays (out of DNSSEC-custody scope) |
| `mesh_sync` registration signer | session-derived mesh identity keys | stays (mesh identity, not zone custody) |
| TLS cert/key resolvers | TLS PKI, not DNSSEC | untouched (`synvoid-tls`) |

Canonicalization/query logic was not moved into the key crate merely
because signing calls it.

## 4. Narrow contract (Part B)

- `SealedSigningKey` is `#[non_exhaustive]` with crate-private
  `private_key: Zeroizing<Vec<u8>>`. There is no getter returning private
  bytes. Public surface: `sign(canonical_bytes)`,
  `metadata()`/`public_key()`/`dnskey_rdata()`/`cds_rdata()`/`cdnskey_rdata()`,
  `has_private()`, `from_public_parts()`, `generate_ephemeral()`.
- `DnssecKeystore` exposes `sign_canonical(bytes, KeyType)`,
  `public_dnskeys()`, `signing_handles()`/`dnskey_handles()` (opaque
  `Arc<SealedSigningKey>`), and explicit management methods
  (`generate_key`, `generate_standby_key`, `start/complete_key_rollover`,
  `check_and_rotate`). Query signing and key management share no path
  that exposes private bytes.
- Algorithm policy is validated before signing (closed set: Ed25519(15),
  RSASHA256(8)). `Debug` redacts secrets; status/export DTOs
  (`KeyInfo`, `DnsSecKeyStatus`, `export_public_keys_to_file`) are
  public-only by construction.
- Zones hold `Option<Arc<SealedSigningKey>>` handles; cloning a zone
  clones the `Arc`, never raw bytes.

## 5. HSM isolation (Part C)

- `cryptoki` is optional behind crate features `pkcs11` (dep gate) and
  `hsm` (alias). `synvoid-dns` exposes `hsm = ["synvoid-dnssec-keystore/pkcs11"]`,
  off by default; root exposes `dns-hsm = ["dns", "synvoid-dns/hsm"]`.
  Normal software-key builds have no `cryptoki` in the graph
  (`cargo tree -i cryptoki` empty) and load no provider library.
- `HsmSigner` exposes `sign`/`get_public_key`/`key_id` only; sessions and
  object handles never cross the module boundary.
- Fail-closed: PKCS#11 establishment failures return typed `HsmError`
  (including `NotCompiled` when the feature is off and `require_hsm` is
  set). There is no silent fallback from HSM-required signing to software
  keys; without an available backend, signing stays unavailable and zones
  must refuse signed answers.
- PINs live in `Zeroizing<String>`, are never logged (redacted config
  rendering), and HSM errors never include secret material.

## 6. Software storage (Part D)

- Private files: mode `0600` on Unix regardless of umask, written
  atomically (temp file in the same directory + fsync + rename, unique
  temp names, no leftovers). Key directories are restricted to `0700`.
- On load, group/world-readable private files are refused (fail-closed)
  rather than silently used.
- In-memory private bytes are `Zeroizing` and zeroized on drop; no
  private bytes in JSON/OpenAPI/admin DTOs, logs, metrics labels, panics,
  or `Debug` output. Disk layout
  (`{key_path}/{ksk,zsk}/<name>.{key,pub,priv}` + JSON sidecars) is
  unchanged for compatibility.
- Backup semantics: back up the sealed `{key_path}` tree preserving
  `0600`; restore by restoring the tree then `load_keys_from_disk`.
  `export_public_keys_to_file` exports identifiers/algorithms/tags/
  lifetimes only — never private bytes.

## 7. Trust anchors (Part E)

Trust anchors are public DNSKEY material needing authenticity/freshness
(RFC 5011), whereas signing keys need confidentiality. Combining them
would broaden the crate, so `trust_anchor.rs` (state machine, SQLite
persistence, anchor-file parsing) stays in `synvoid-dns` and was not
reclassified as secret storage.

## 8. Mesh semantics (Part F)

- `MeshTrustAnchor.dnskeys` is `Vec<KeyMetadata>` (public-only). No raw
  private zone keys are distributed through DHT/gossip/Raft; global
  key-management mutation semantics are unchanged (no cross-node private
  replication introduced).
- Phase 23 canonical/advisory authority rules are preserved; signed
  public artifacts bind key ID/algorithm/zone via existing DNSKEY/DS
  shapes.

## 9. Crypto placement (Part G)

- `cargo tree -p synvoid-dns` (default features): no `cryptoki`.
- `cargo tree -p synvoid-dnssec-keystore` (default): `ed25519-dalek`,
  `rsa`, no `cryptoki`, no Hickory/Hyper/Quinn/SQLite.
- With `pkcs11`: `cryptoki` appears only under the keystore.
- `synvoid-dns` retains `rsa`/`ed25519-dalek`/`sha1`/`sha2` for
  verification-only and protocol uses (public-key verify, DS digests,
  NSEC3 hashing). SHA-1 remains narrowly scoped to DS digest type 1 and
  NSEC3 algorithm 1 interop (RFC 4034 §5.1.4, RFC 5155); it was not
  removed or replaced outside protocol requirements.

## 10. Verification

```bash
cargo test -p synvoid-dnssec-keystore --all-targets
cargo test -p synvoid-dnssec-keystore --features pkcs11
cargo test -p synvoid-dns --all-targets
cargo check -p synvoid-dns --no-default-features
cargo check -p synvoid-dns --features hsm --all-targets
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
./scripts/dns/conformance.sh   # 7/7 internal suites (external section is operator-deferred)
cargo tree -i cryptoki --workspace        # empty on default features
cargo tree -p synvoid-dnssec-keystore --features synvoid-dnssec-keystore/pkcs11  # cryptoki present
```

Required coverage lives in
`crates/synvoid-dnssec-keystore/tests/keystore_boundary.rs` (KAT
sign/verify, DNSKEY/key-tag compat, lifecycle/rotation, HSM
mocked/failure/no-fallback, permissions/atomicity, redaction,
golden shapes, DS lengths incl. SHA-1, feature-disabled, admin-DTO
guard) plus the migrated `synvoid-dns` DNSSEC suites
(`dnssec_live_signing`, `dnssec_known_vectors`, `verification_gate`,
`dns_interop_dnssec`).

## 11. Operator notes

- Software keys (default): no extra feature needed.
- HSM backing: build with root `--features dns-hsm` (or
  `-p synvoid-dns --features hsm`), configure
  `[dns.dnssec.hsm]` with `provider = "pkcs11"`, a module path, slot,
  and key selector. Zones selecting the PKCS#11 provider require HSM
  backing: establishment failures fail closed (no software fallback).
- Key files live under the configured DNSSEC `key_path`
  (`{ksk,zsk}/` subdirs); keep `0600`/`0700` permissions on backup and
  restore.
