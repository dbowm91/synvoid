//! Narrow signer contract (Phase 30 Part B).
//!
//! The query path needs exactly three capabilities: enumerate public key
//! metadata, fetch public DNSKEY RDATA, and sign caller-supplied canonical
//! bytes with a named key. It must not retrieve raw private bytes, manage
//! HSM sessions, or perform key lifecycle operations inline.

use std::sync::Arc;

use crate::error::KeystoreError;
use crate::key::{KeyMetadata, KeyType, SealedSigningKey};

/// What the request path may do with key custody.
pub trait DnssecSigner: Send + Sync {
    /// Public metadata for every published DNSKEY (active + rollover).
    fn public_dnskeys(&self) -> Vec<KeyMetadata>;
    /// Sign canonical RRset bytes with the active key of `key_type`.
    fn sign_canonical(
        &self,
        canonical_bytes: &[u8],
        key_type: KeyType,
    ) -> Result<Vec<u8>, KeystoreError>;
    /// Opaque signing handles (ZSK + standby). No private bytes exposed.
    fn signing_handles(&self) -> Vec<Arc<SealedSigningKey>>;
}

impl DnssecSigner for crate::keystore::DnssecKeystore {
    fn public_dnskeys(&self) -> Vec<KeyMetadata> {
        crate::keystore::DnssecKeystore::public_dnskeys(self)
    }
    fn sign_canonical(
        &self,
        canonical_bytes: &[u8],
        key_type: KeyType,
    ) -> Result<Vec<u8>, KeystoreError> {
        crate::keystore::DnssecKeystore::sign_canonical(self, canonical_bytes, key_type)
    }
    fn signing_handles(&self) -> Vec<Arc<SealedSigningKey>> {
        crate::keystore::DnssecKeystore::signing_handles(self)
    }
}
