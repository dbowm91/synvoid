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

pub mod algorithm;
pub mod digests;
pub mod error;
pub mod hsm;
pub mod key;
pub mod keystore;
pub mod signer;

pub(crate) mod rng;

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
