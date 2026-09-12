//! DS digest helpers scoped to key-custody needs (Phase 30 Part G).
//!
//! Only the digests needed to derive DS/CDS from locally held public keys
//! live here. Full validation/canonicalization stays in `synvoid-dns`.
//! SHA-1 (digest type 1) is protocol-required for DS interop (RFC 4034
//! §5.1.4, RFC 8080-era toleration) and is narrowly scoped to this function;
//! it must not be treated as a general-purpose hash choice.

use sha2::{Digest, Sha256, Sha384};

use crate::error::KeystoreError;

/// Compute a DS digest over canonical DNSKEY RDATA bytes.
pub fn ds_digest_bytes(digest_type: u8, canonical_dnskey: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    match digest_type {
        // Protocol-required SHA-1 for DS digest type 1. Narrow scope:
        // DS interop only, never password/token hashing.
        1 => {
            use sha1::Sha1;
            let mut hasher = Sha1::new();
            hasher.update(canonical_dnskey);
            Ok(hasher.finalize().to_vec())
        }
        2 => {
            let mut hasher = Sha256::new();
            hasher.update(canonical_dnskey);
            Ok(hasher.finalize().to_vec())
        }
        4 => {
            let mut hasher = Sha384::new();
            hasher.update(canonical_dnskey);
            Ok(hasher.finalize().to_vec())
        }
        other => Err(KeystoreError::UnsupportedAlgorithm(format!(
            "unsupported DS digest type: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ds_digest_lengths_are_protocol_correct() {
        let canonical = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(ds_digest_bytes(1, &canonical).unwrap().len(), 20);
        assert_eq!(ds_digest_bytes(2, &canonical).unwrap().len(), 32);
        assert_eq!(ds_digest_bytes(4, &canonical).unwrap().len(), 48);
        assert!(ds_digest_bytes(3, &canonical).is_err());
    }
}
