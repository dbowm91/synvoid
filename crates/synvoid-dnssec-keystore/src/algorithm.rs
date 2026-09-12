//! DNSSEC signing algorithm vocabulary (Phase 30).
//!
//! Public-only value types. No private key material lives here. The set is
//! intentionally limited to the algorithms SynVoid signs with (Ed25519 URI
//! 15, RSASHA256 URI 8). Protocol digest uses (DS/NSEC3 SHA-1) are owned by
//! `synvoid-dns` validation/proof code, not by this custody crate.

use serde::{Deserialize, Serialize};

use crate::error::KeystoreError;

/// DNSSEC signing algorithm supported for authoritative signing.
///
/// IANA values: Ed25519 = 15 (RFC 8080), RSASHA256 = 8 (RFC 5702).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    Ed25519,
    RSA,
}

impl Algorithm {
    pub fn to_u8(&self) -> u8 {
        match self {
            Algorithm::Ed25519 => 15,
            Algorithm::RSA => 8,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            15 => Some(Algorithm::Ed25519),
            8 => Some(Algorithm::RSA),
            _ => None,
        }
    }

    pub fn dns_algorithm_name(&self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "ED25519",
            Algorithm::RSA => "RSASHA256",
        }
    }

    /// Fail-closed policy check before any signing operation.
    pub fn validate_for_signing(&self) -> Result<(), KeystoreError> {
        // Both variants are explicitly supported; the match documents the
        // closed set so adding a variant forces a policy decision.
        match self {
            Algorithm::Ed25519 | Algorithm::RSA => Ok(()),
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.dns_algorithm_name())
    }
}

/// DS digest type (public protocol vocabulary, duplicated here so keystore
/// CDS/DS derivation does not depend on `synvoid-dns`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DsDigestType {
    Sha1 = 1,
    Sha256 = 2,
    Sha384 = 4,
}

impl DsDigestType {
    pub fn to_u8(&self) -> u8 {
        match self {
            DsDigestType::Sha1 => 1,
            DsDigestType::Sha256 => 2,
            DsDigestType::Sha384 => 4,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DsDigestType::Sha1),
            2 => Some(DsDigestType::Sha256),
            4 => Some(DsDigestType::Sha384),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_iana_values() {
        assert_eq!(Algorithm::Ed25519.to_u8(), 15);
        assert_eq!(Algorithm::RSA.to_u8(), 8);
        assert_eq!(Algorithm::from_u8(15), Some(Algorithm::Ed25519));
        assert_eq!(Algorithm::from_u8(8), Some(Algorithm::RSA));
        assert_eq!(Algorithm::from_u8(5), None);
    }

    #[test]
    fn ds_digest_values() {
        assert_eq!(DsDigestType::Sha1.to_u8(), 1);
        assert_eq!(DsDigestType::Sha256.to_u8(), 2);
        assert_eq!(DsDigestType::Sha384.to_u8(), 4);
        assert_eq!(DsDigestType::from_u8(1), Some(DsDigestType::Sha1));
    }
}
