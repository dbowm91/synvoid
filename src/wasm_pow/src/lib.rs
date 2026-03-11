use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

const MAX_NONCE: u64 = 100_000_000;

#[wasm_bindgen]
pub fn solve_pow(challenge: String, difficulty: u8) -> Option<String> {
    let zeros = difficulty as usize;

    for nonce in 0..MAX_NONCE {
        let input = format!("{}{}", challenge, nonce);
        let hash = Sha256::digest(input.as_bytes());

        if has_leading_zeros(&hash, zeros) {
            return Some(nonce.to_string());
        }
    }

    None
}

#[wasm_bindgen]
pub fn verify_pow(challenge: String, nonce: String, difficulty: u8) -> bool {
    let input = format!("{}{}", challenge, nonce);
    let hash = Sha256::digest(input.as_bytes());
    has_leading_zeros(&hash, difficulty as usize)
}

fn has_leading_zeros(hash: &[u8], zeros: usize) -> bool {
    let mut bit_index = 0;

    for &byte in hash {
        for j in (0..8).rev() {
            if bit_index >= zeros {
                return true;
            }
            if (byte >> j) & 1 != 0 {
                return false;
            }
            bit_index += 1;
        }
    }

    bit_index >= zeros
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solve_pow() {
        let challenge = "dGVzdDoxMjM0NTY3ODkwYWJjZA==";
        let solution = solve_pow(challenge.to_string(), 4);
        assert!(solution.is_some());

        let nonce = solution.unwrap();
        assert!(verify_pow(challenge.to_string(), nonce, 4));
    }

    #[test]
    fn test_verify_invalid() {
        assert!(!verify_pow("test".to_string(), "invalid".to_string(), 8));
    }
}
