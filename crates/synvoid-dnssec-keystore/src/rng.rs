//! Crate-internal entropy helpers (Phase 30).
//!
//! Key generation randomness must never silently fall back to a weak source:
//! every helper returns a typed error and callers fail closed.

use crate::error::KeystoreError;

/// RNG adapter: `getrandom` behind the `rand_core` 0.6 traits required by
/// `rsa` 0.9. Never panics on entropy failure in production paths; the
/// `RngCore` impls keep the historical expect-fail-closed behavior for the
/// RSA internals that cannot thread Results, while fallible helpers below
/// return [`KeystoreError::Entropy`].
pub(crate) struct CryptoRngAdapter;

impl rand_core_06::RngCore for CryptoRngAdapter {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        getrandom::getrandom(dest).map_err(rand_core_06::Error::new)
    }
}

impl rand_core_06::CryptoRng for CryptoRngAdapter {}

pub(crate) fn random_bytes(len: usize) -> Result<Vec<u8>, KeystoreError> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| KeystoreError::Entropy(format!("getrandom failed: {e}")))?;
    Ok(bytes)
}
