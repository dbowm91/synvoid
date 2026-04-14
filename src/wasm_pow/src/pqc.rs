//! Post-Quantum Cryptography abstraction layer
//!
//! This module provides a unified interface for PQC operations
//! using pqc_kyber as the backend for ML-KEM-768 (Kyber-768).

use pqc_kyber::*;
use serde::{Deserialize, Serialize};

pub const PUBLIC_KEY_SIZE: usize = 1184; // KYBER768
pub const SECRET_KEY_SIZE: usize = 2400; // KYBER768
pub const CIPHERTEXT_SIZE: usize = 1088; // KYBER768

#[derive(Serialize, Deserialize)]
pub struct PqcKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PqcEncapsulationResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

pub fn generate_keypair() -> Result<PqcKeyPair, String> {
    let mut rng = rand::rngs::OsRng;
    let keys =
        pqc_kyber::keypair(&mut rng).map_err(|e| format!("Key generation failed: {:?}", e))?;

    Ok(PqcKeyPair {
        public_key: keys.public.to_vec(),
        secret_key: keys.secret.to_vec(),
    })
}

pub fn encapsulate(public_key: &[u8]) -> Result<PqcEncapsulationResult, String> {
    if public_key.len() != PUBLIC_KEY_SIZE {
        return Err(format!(
            "Invalid public key size: expected {}, got {}",
            PUBLIC_KEY_SIZE,
            public_key.len()
        ));
    }

    let mut rng = rand::rngs::OsRng;
    let (ct, ss) = pqc_kyber::encapsulate(public_key, &mut rng)
        .map_err(|e| format!("Encapsulation failed: {:?}", e))?;

    Ok(PqcEncapsulationResult {
        ciphertext: ct.to_vec(),
        shared_secret: ss.to_vec(),
    })
}

pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() != CIPHERTEXT_SIZE {
        return Err(format!(
            "Invalid ciphertext size: expected {}, got {}",
            CIPHERTEXT_SIZE,
            ciphertext.len()
        ));
    }
    if secret_key.len() != SECRET_KEY_SIZE {
        return Err(format!(
            "Invalid secret key size: expected {}, got {}",
            SECRET_KEY_SIZE,
            secret_key.len()
        ));
    }

    pqc_kyber::decapsulate(ciphertext, secret_key)
        .map_err(|e| format!("Decapsulation failed: {:?}", e))
        .map(|ss| ss.to_vec())
}
