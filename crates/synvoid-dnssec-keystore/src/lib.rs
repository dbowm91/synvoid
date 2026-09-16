//! DNSSEC private-key custody boundary (Phase 30).
//!
//! Canonical owner of DNSSEC private-key generation, sealed persistence,
//! rotation lifecycle, signing dispatch, and HSM/PKCS#11 backing.
//!
//! # One-way boundary
//!
//! `synvoid-dns` depends on this crate; this crate never depends on
//! `synvoid-dns`, `synvoid-mesh`, `synvoid-admin`, Hickory, Hyper, Quinn,
//! or SQLite. Trust-anchor validation/persistence (public-only, RFC 5011)
//! stays in `synvoid-dns`; canonical RRset construction, NSEC/NSEC3 proofs,
//! and DS/SHA-1 protocol uses stay in `synvoid-dns` validation code.
//!
//! # Authority rules (enforced by repo guards + API shape)
//!
//! - No API returns raw private key bytes. [`SealedSigningKey`] exposes
//!   `sign()`, public metadata, and DNSKEY derivation only.
//! - HSM handles are opaque behind [`HsmSigner`]; `cryptoki` is optional
//!   behind `pkcs11`/`hsm` and off by default.
//! - HSM-required zones fail closed: no silent software fallback.
//! - SHA-1 in this crate is narrowly scoped to DS digest type 1 interop.
//! - Private key files are `0600` on Unix, written atomically, with
//!   overly-permissive files refused on load.
//! - Nothing in this crate replicates private keys over mesh/DHT/Raft:
//!   only [`KeyMetadata`] (public) is mesh-shareable.
//!
//! # Dependency budget (Phase 34)
//!
//! This crate depends only on cryptography, serialization, and OS
//! primitives (`serde`, `ed25519-dalek`, `rsa`, `sha1`/`sha2`, `zeroize`,
//! `parking_lot`, `tokio`, `tracing`). It has no edge on `synvoid-core`,
//! `synvoid-config`, or the root SynVoid crate: the only historical
//! `synvoid-core` use (a `u64` wall-clock helper) is owned locally in
//! `time.rs`. An external DNS implementation can therefore depend on this
//! crate without dragging in unrelated SynVoid application contracts.
//!
//! # Examples
//!
//! Ephemeral in-memory signer (tests, short-lived signers):
//!
//! ```rust
//! use synvoid_dnssec_keystore::{Algorithm, KeyType, SealedSigningKey};
//!
//! let key = SealedSigningKey::generate_ephemeral(Algorithm::Ed25519, KeyType::ZSK)?;
//! let sig = key.sign(b"canonical rrset bytes")?;
//! assert_eq!(sig.len(), 64);
//! // The public-only view carries no private material.
//! assert_eq!(key.metadata().public_key.len(), 32);
//! # Ok::<(), synvoid_dnssec_keystore::KeystoreError>(())
//! ```
//!
//! Persistent keystore lifecycle (generate, sign, reload from disk):
//!
//! ```rust
//! use synvoid_dnssec_keystore::{Algorithm, DnssecKeystore, KeystoreError, KeyType};
//!
//! let tmp = tempfile::tempdir()
//!     .map_err(|e| KeystoreError::Storage(format!("doctest tempdir: {e}")))?;
//! let mut ks = DnssecKeystore::new(tmp.path().to_path_buf());
//! ks.initialize()?;
//! ks.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)?;
//! ks.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)?;
//! let sig = ks.sign_canonical(b"canonical rrset bytes", KeyType::ZSK)?;
//! assert!(!sig.is_empty());
//! assert_eq!(ks.public_dnskeys().len(), 2);
//! // Sealed handles are reconstituted from disk with permission re-checks.
//! let mut reloaded = DnssecKeystore::new(tmp.path().to_path_buf());
//! reloaded.load_keys_from_disk()?;
//! assert!(reloaded.active_zsk().is_ok());
//! # Ok::<(), synvoid_dnssec_keystore::KeystoreError>(())
//! ```
//!
//! Optional HSM use (opaque handles, fail-closed when unavailable):
//!
//! ```rust
//! use synvoid_dnssec_keystore::{HsmConfig, HsmManager, HsmSigner, SoftHsm};
//!
//! // Disabled config: unavailable, with no silent software fallback.
//! let manager = HsmManager::new();
//! manager.initialize(&HsmConfig::default())?;
//! assert!(!manager.is_available());
//! // Explicit software handle for tests and development.
//! let soft = SoftHsm::from_bytes("example".to_string(), &[9u8; 32]);
//! assert_eq!(soft.sign(b"canonical")?.len(), 64);
//! # Ok::<(), synvoid_dnssec_keystore::KeystoreError>(())
//! ```

pub mod algorithm;
pub mod digests;
pub mod error;
pub mod hsm;
pub mod key;
pub mod keystore;
pub mod signer;

pub(crate) mod rng;
pub(crate) mod time;

pub use algorithm::{Algorithm, DsDigestType};
pub use error::KeystoreError;
#[cfg(feature = "pkcs11")]
pub use hsm::Pkcs11Hsm;
pub use hsm::{HsmAlgorithm, HsmConfig, HsmError, HsmManager, HsmProvider, HsmSigner, SoftHsm};
pub use key::{calculate_key_tag, KeyMetadata, KeyType, SealedSigningKey};
pub use keystore::{
    DnsSecKeyManager, DnsSecKeyStatus, DnssecKeystore, KeyInfo, KeyRotationConfig,
    KeyRotationResult, RolloverState, ZoneSigningKey,
};
pub use signer::DnssecSigner;
