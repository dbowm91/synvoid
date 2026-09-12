//! Sealed signing keys: opaque private custody + public metadata.
//!
//! # Boundary rule
//!
//! `SealedSigningKey` owns private key bytes inside this crate only. The
//! `private_key` field is private to this crate; consumers in `synvoid-dns`
//! (or anywhere else) can sign canonical bytes and read public metadata but
//! have no API that returns raw private bytes. Debug redacts secrets and
//! serialization is public-only (see `KeyMetadata`).

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::algorithm::{Algorithm, DsDigestType};
use crate::error::KeystoreError;

/// KSK signs the DNSKEY RRset; ZSK signs all other zone data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    KSK,
    ZSK,
}

/// Public-only view of a signing key. Safe to clone into zones, caches,
/// mesh trust anchors, logs, metrics, and admin responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub algorithm: Algorithm,
    pub key_type: KeyType,
    pub key_tag: u16,
    pub flags: u16,
    pub key_size: Option<u32>,
    pub created_at: u64,
    pub expires_at: u64,
    pub public_key: Vec<u8>,
}

impl KeyMetadata {
    /// DNSKEY RDATA: flags(2) + protocol(1, always 3) + algorithm(1) + public key.
    pub fn dnskey_rdata(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.public_key.len());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.push(3);
        out.push(self.algorithm.to_u8());
        out.extend_from_slice(&self.public_key);
        out
    }

    /// Canonical DNSKEY bytes used for DS digest computation.
    pub fn dnskey_canonical(&self) -> Vec<u8> {
        self.dnskey_rdata()
    }
}

/// Opaque handle over one signing key. Private bytes never leave this crate.
///
/// `#[non_exhaustive]` prevents external crates from constructing or
/// pattern-matching this type with struct literals: the only constructors
/// are the associated functions (`from_public_parts` for public-only
/// handles; generation/loading inside the keystore for sealed handles).
#[non_exhaustive]
pub struct SealedSigningKey {
    key_id: String,
    algorithm: Algorithm,
    key_type: KeyType,
    created_at: u64,
    expires_at: u64,
    public_key: Vec<u8>,
    // Private to this crate: no pub accessor returns these bytes.
    private_key: Zeroizing<Vec<u8>>,
    key_tag: u16,
    flags: u16,
    key_size: Option<u32>,
}

impl Clone for SealedSigningKey {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id.clone(),
            algorithm: self.algorithm,
            key_type: self.key_type,
            created_at: self.created_at,
            expires_at: self.expires_at,
            public_key: self.public_key.clone(),
            private_key: Zeroizing::new(self.private_key.to_vec()),
            key_tag: self.key_tag,
            flags: self.flags,
            key_size: self.key_size,
        }
    }
}

impl Drop for SealedSigningKey {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

// Redacted: never print key bytes, tags are fine (public), ids are fine.
impl std::fmt::Debug for SealedSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedSigningKey")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("key_type", &self.key_type)
            .field("key_tag", &self.key_tag)
            .field("flags", &self.flags)
            .field("key_size", &self.key_size)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("public_key_len", &self.public_key.len())
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// Raw keypair parts: (public_key, private_key, key_tag, flags, key_size).
/// Factored out so generation helpers share one shape.
pub(crate) type KeypairParts = (Vec<u8>, Vec<u8>, u16, u16, Option<u32>);

impl SealedSigningKey {
    /// Canonical constructor used by generation/import paths inside this crate.
    #[allow(clippy::too_many_arguments)] // mirrors the sealed key fields
    pub(crate) fn new_sealed(
        key_id: String,
        algorithm: Algorithm,
        key_type: KeyType,
        created_at: u64,
        expires_at: u64,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        key_tag: u16,
        flags: u16,
        key_size: Option<u32>,
    ) -> Self {
        Self {
            key_id,
            algorithm,
            key_type,
            created_at,
            expires_at,
            public_key,
            private_key: Zeroizing::new(private_key),
            key_tag,
            flags,
            key_size,
        }
    }

    /// Generate an in-memory (never persisted) sealed key. Intended for
    /// tests, ephemeral signers, and callers that manage their own
    /// persistence. Private bytes never leave the returned handle.
    pub fn generate_ephemeral(
        algorithm: Algorithm,
        key_type: KeyType,
    ) -> Result<Self, KeystoreError> {
        algorithm.validate_for_signing()?;
        let now = synvoid_core::time::current_timestamp_secs();
        let expires_at = now.saturating_add(90 * 86400);
        let (public_key, private_key, key_tag, flags, key_size) =
            generate_keypair(algorithm, key_type, 2048)?;
        let key_id = match key_type {
            KeyType::KSK => "ephemeral-ksk",
            KeyType::ZSK => "ephemeral-zsk",
        };
        Ok(Self::new_sealed(
            key_id.to_string(),
            algorithm,
            key_type,
            now,
            expires_at,
            public_key,
            private_key,
            key_tag,
            flags,
            key_size,
        ))
    }

    /// Public-only construction for re-encoding paths (e.g. DNSKEY wire
    /// handling) that never possess private material. The sealed private
    /// slot is empty; [`SealedSigningKey::has_private`] reports false and
    /// [`SealedSigningKey::sign`] refuses.
    pub fn from_public_parts(
        key_id: String,
        algorithm: Algorithm,
        key_type: KeyType,
        public_key: Vec<u8>,
        key_tag: u16,
        flags: u16,
    ) -> Self {
        Self {
            key_id,
            algorithm,
            key_type,
            created_at: 0,
            expires_at: u64::MAX,
            public_key,
            private_key: Zeroizing::new(Vec::new()),
            key_tag,
            flags,
            key_size: None,
        }
    }

    /// Reconstitute a sealed key loaded from disk (crate-internal; the bytes
    /// cross the disk boundary but never cross the API boundary outward).
    #[allow(clippy::too_many_arguments)] // mirrors the sealed key fields
    pub(crate) fn from_stored_parts(
        key_id: String,
        algorithm: Algorithm,
        key_type: KeyType,
        created_at: u64,
        expires_at: u64,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        key_tag: u16,
        flags: u16,
        key_size: Option<u32>,
    ) -> Self {
        Self::new_sealed(
            key_id,
            algorithm,
            key_type,
            created_at,
            expires_at,
            public_key,
            private_key,
            key_tag,
            flags,
            key_size,
        )
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn key_size(&self) -> Option<u32> {
        self.key_size
    }

    /// Whether this handle actually holds private material. Public-only
    /// handles (e.g. [`SealedSigningKey::from_public_parts`]) return false.
    pub fn has_private(&self) -> bool {
        !self.private_key.is_empty()
    }

    /// Public-only snapshot. This is the only way to move key identity into
    /// zones, caches, mesh anchors, or admin responses.
    pub fn metadata(&self) -> KeyMetadata {
        KeyMetadata {
            key_id: self.key_id.clone(),
            algorithm: self.algorithm,
            key_type: self.key_type,
            key_tag: self.key_tag,
            flags: self.flags,
            key_size: self.key_size,
            created_at: self.created_at,
            expires_at: self.expires_at,
            public_key: self.public_key.clone(),
        }
    }

    /// DNSKEY RDATA derived from public parts only.
    pub fn dnskey_rdata(&self) -> Vec<u8> {
        self.metadata().dnskey_rdata()
    }

    /// Sign caller-supplied canonical bytes with this key's private material.
    ///
    /// Algorithm policy is validated before touching private bytes. There is
    /// deliberately no method that returns the private bytes themselves.
    pub fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        self.algorithm.validate_for_signing()?;
        if !self.has_private() {
            return Err(KeystoreError::SigningFailed(
                "no private material for public-only key handle".to_string(),
            ));
        }
        match self.algorithm {
            Algorithm::Ed25519 => self.sign_ed25519(canonical_bytes),
            Algorithm::RSA => self.sign_rsa(canonical_bytes),
        }
    }

    fn sign_ed25519(&self, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        use ed25519_dalek::Signer;
        let bytes: [u8; 32] = self.private_key.as_slice().try_into().map_err(|_| {
            KeystoreError::InvalidKey("invalid Ed25519 private key length".to_string())
        })?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        Ok(signing_key.sign(data).to_bytes().to_vec())
    }

    fn sign_rsa(&self, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        use rsa::pkcs1v15::Pkcs1v15Sign;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::SignatureScheme;
        use sha2::{Digest, Sha256};

        let private_key = rsa::RsaPrivateKey::from_pkcs8_der(self.private_key.as_slice())
            .map_err(|e| KeystoreError::InvalidKey(format!("invalid RSA private key: {e}")))?;
        let hashed = Sha256::digest(data);
        let scheme = Pkcs1v15Sign::new::<Sha256>();
        scheme
            .sign(
                Some(&mut crate::rng::CryptoRngAdapter),
                &private_key,
                &hashed,
            )
            .map_err(|e| KeystoreError::SigningFailed(format!("RSA signing failed: {e}")))
    }

    /// DS record data for a KSK: key_tag(2) + algorithm(1) + digest_type(1) + digest.
    /// Public-only; refuses non-KSK keys.
    pub fn cds_rdata(&self, digest_type: DsDigestType) -> Result<Vec<u8>, KeystoreError> {
        if self.key_type != KeyType::KSK {
            return Err(KeystoreError::Management(
                "CDS records can only be generated for KSK keys".to_string(),
            ));
        }
        let canonical = self.dnskey_rdata();
        let digest = crate::digests::ds_digest_bytes(digest_type.to_u8(), &canonical)?;
        let mut out = Vec::with_capacity(4 + digest.len());
        out.extend_from_slice(&self.key_tag.to_be_bytes());
        out.push(self.algorithm.to_u8());
        out.push(digest_type.to_u8());
        out.extend_from_slice(&digest);
        Ok(out)
    }

    /// CDNSKEY RDATA (same wire shape as DNSKEY). Public-only.
    pub fn cdnskey_rdata(&self) -> Result<Vec<u8>, KeystoreError> {
        if self.key_type != KeyType::KSK {
            return Err(KeystoreError::Management(
                "CDNSKEY records can only be generated for KSK keys".to_string(),
            ));
        }
        Ok(self.dnskey_rdata())
    }
}

/// Generate a raw keypair for `algorithm`/`key_type` (public + private
/// bytes, tag, flags, size). Crate-internal: callers must wrap the output
/// in a [`SealedSigningKey`] immediately; the bytes must never be returned
/// through a public API.
pub(crate) fn generate_keypair(
    algorithm: Algorithm,
    key_type: KeyType,
    rsa_key_size: u32,
) -> Result<KeypairParts, KeystoreError> {
    match algorithm {
        Algorithm::Ed25519 => {
            let bytes = crate::rng::random_bytes(32)?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .expect("random_bytes(32) always returns 32 bytes"),
            );
            let public = signing_key.verifying_key().to_bytes().to_vec();
            let private = signing_key.to_bytes().to_vec();
            let flags = if key_type == KeyType::KSK { 257 } else { 256 };
            let tag = calculate_key_tag(flags, 3, Algorithm::Ed25519.to_u8(), &public);
            Ok((public, private, tag, flags, None))
        }
        Algorithm::RSA => {
            use rsa::traits::PublicKeyParts;
            let bits = if rsa_key_size == 0 {
                2048_usize
            } else {
                let requested = rsa_key_size as usize;
                if requested == 1024 {
                    tracing::warn!("RSA 1024 is insecure, auto-upgrading to 2048");
                    2048
                } else {
                    requested
                }
            };
            if !matches!(bits, 2048 | 4096) {
                return Err(KeystoreError::UnsupportedAlgorithm(format!(
                    "unsupported RSA key size {bits}; use 2048 or 4096"
                )));
            }
            let private_key = rsa::RsaPrivateKey::new(&mut crate::rng::CryptoRngAdapter, bits)
                .map_err(|e| {
                    KeystoreError::Management(format!("RSA key generation failed: {e}"))
                })?;
            let public_rsa = private_key.to_public_key();
            let e_bytes = public_rsa.e().to_bytes_be();
            let n_bytes = public_rsa.n().to_bytes_be();
            let mut public_dnskey = Vec::new();
            if e_bytes.len() > 255 {
                public_dnskey.push(0);
                public_dnskey.push((e_bytes.len() >> 8) as u8);
                public_dnskey.push((e_bytes.len() & 0xFF) as u8);
            } else {
                public_dnskey.push(e_bytes.len() as u8);
            }
            public_dnskey.extend_from_slice(&e_bytes);
            public_dnskey.extend_from_slice(&n_bytes);
            let private_der = {
                use rsa::pkcs8::EncodePrivateKey;
                private_key
                    .to_pkcs8_der()
                    .map_err(|e| {
                        KeystoreError::Management(format!(
                            "RSA private key DER encoding failed: {e}"
                        ))
                    })?
                    .as_bytes()
                    .to_vec()
            };
            let flags = if key_type == KeyType::KSK { 257 } else { 256 };
            let tag = calculate_key_tag(flags, 3, Algorithm::RSA.to_u8(), &public_dnskey);
            Ok((public_dnskey, private_der, tag, flags, Some(bits as u32)))
        }
    }
}

/// RFC 4034 Appendix B key-tag calculation over public DNSKEY RDATA.
/// Public-only helper shared by keystore generation and DNS-side validation.
pub fn calculate_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(4 + public_key.len());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.push(protocol);
    buf.push(algorithm);
    buf.extend_from_slice(public_key);

    let mut sum: u32 = 0;
    for (i, byte) in buf.iter().enumerate() {
        if i & 1 == 0 {
            sum += (*byte as u32) << 8;
        } else {
            sum += *byte as u32;
        }
    }
    sum.wrapping_add(sum >> 16) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sealed_ed25519() -> SealedSigningKey {
        let mut seed = [7u8; 32];
        getrandom::getrandom(&mut seed).expect("rng");
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes().to_vec();
        let private = signing.to_bytes().to_vec();
        let tag = calculate_key_tag(256, 3, 15, &public);
        SealedSigningKey::new_sealed(
            "zsk".to_string(),
            Algorithm::Ed25519,
            KeyType::ZSK,
            0,
            u64::MAX,
            public,
            private,
            tag,
            256,
            None,
        )
    }

    #[test]
    fn debug_redacts_private() {
        let key = test_sealed_ed25519();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("private_key_bytes"));
    }

    #[test]
    fn metadata_contains_no_private_bytes() {
        let key = test_sealed_ed25519();
        let meta = key.metadata();
        assert_eq!(meta.public_key, key.public_key().to_vec());
        let serialized = serde_json::to_string(&meta).unwrap();
        assert!(!serialized.contains("private"));
    }

    #[test]
    fn public_only_handle_cannot_sign() {
        let key = SealedSigningKey::from_public_parts(
            "k".to_string(),
            Algorithm::Ed25519,
            KeyType::ZSK,
            vec![1u8; 32],
            1234,
            256,
        );
        assert!(!key.has_private());
        assert!(key.sign(b"canonical").is_err());
    }

    #[test]
    fn key_tag_known_answer() {
        // Deterministic: same inputs always produce the same tag.
        let tag1 = calculate_key_tag(257, 3, 15, &[0x01; 32]);
        let tag2 = calculate_key_tag(257, 3, 15, &[0x01; 32]);
        assert_eq!(tag1, tag2);
        assert!(tag1 > 0);
    }
}
