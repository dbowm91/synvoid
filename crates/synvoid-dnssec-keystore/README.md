# synvoid-dnssec-keystore

DNSSEC private-key custody primitives for DNS implementations. This package
generates, seals, persists, rotates, and signs with DNSSEC keys. Normal query,
transport, zone, and mesh code receives opaque `SealedSigningKey` handles or
public `KeyMetadata`; this crate has no API that returns private-key bytes.

## Software key lifecycle

```rust,no_run
use synvoid_dnssec_keystore::{Algorithm, DnssecKeystore, KeyType};

fn sign_rrset(dir: std::path::PathBuf, canonical_rrset: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut keys = DnssecKeystore::new(dir);
    keys.initialize()?;
    keys.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)?;
    keys.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)?;
    Ok(keys.sign_canonical(canonical_rrset, KeyType::ZSK)?)
}
```

`SealedSigningKey::sign()` accepts canonical bytes and returns a signature;
public DNSKEY/DS data is derived from public metadata. Rotation is explicit
through `start_key_rollover` / `complete_key_rollover`. Callers keep signer
handles behind their own synchronization boundary when concurrent query
signing and rotation are needed.

## Threat model and key lifetime

Assets are software private-key files, in-process signing material, HSM PINs
and opaque provider handles. The OS account and key directory are trusted; this
crate does not defend against a compromised process, kernel, administrator,
debugger, swap capture, or malicious HSM/provider firmware. Key paths and stored
metadata are untrusted inputs and malformed metadata, insecure Unix key files,
failed writes, or required-HSM initialization failures abort rather than fall
back silently. Secret values must not be logged; `HsmConfig` debug output is
redacted. Only public key metadata may be exported or replicated.

Owned encoded software private-key buffers use `zeroize` containers and clear on
drop. This does not establish a whole-process zeroization guarantee: temporary
copies and internal allocations in `rsa`, `ed25519-dalek`, allocators, compiler
temporaries, and OS/runtime code are outside this crate's verifiable control.
RSA key objects are reconstructed by the cryptographic dependency when signing.
Crash recovery uses same-directory temporary files, file `fsync`, and atomic
rename; stale temp files are not treated as active keys. No backup/restore
protocol or encryption at rest is provided.

On Unix, key directories are mode `0700`, private files are created `0600`, and
overly permissive key files are rejected on load. On Windows, this crate does
not modify or verify DACLs; operators must protect the key directory using the
host ACL. HSM PINs are held in zeroizing wrappers while owned here, but copies
made by the PKCS#11 provider are provider-controlled.

## HSM qualification

The default build has no PKCS#11 dependency or dynamic provider loading. The
`pkcs11` feature (also enabled by the `hsm` alias) is opt-in and never falls
back to software keys. `cargo check -p synvoid-dnssec-keystore --features
pkcs11` is only a compile check, not provider qualification. Release
qualification requires an isolated PKCS#11 token/provider: initialize a test
token, create a signing key, find it by configured label or ID, sign known
canonical bytes, verify with the token's public key, then test missing key,
wrong PIN, unsupported mechanism, and provider removal fail-closed paths. No
PKCS#11 provider was available in this environment, so hardware/provider
qualification remains separate from the software package proof.

## RSA advisory

`rsa` has no patched release for RustSec `RUSTSEC-2023-0071` (Marvin timing
attack). This crate supports DNSSEC RSA private signing for compatibility; the
advisory is not fixed or ignored as patched. Use Ed25519 where the DNSSEC
deployment permits it. RSA software signing should be confined to environments
where an attacker cannot observe signer timing; deployments with remotely
observable RSA signing should use a separately qualified HSM or disable that
algorithm. This unresolved dependency blocks any class-3/public-support
promotion. See [the RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
and [upstream tracking](https://github.com/RustCrypto/RSA/security/advisories/GHSA-c38w-74pg-36hr).

This package's Rust 1.85.0 packaged-consumer result is class-2 evidence only.
`external_support = false`; this README does not establish an external support
or publication commitment.
