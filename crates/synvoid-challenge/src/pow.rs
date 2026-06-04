use sha2::{Digest, Sha256};

pub const HONEYPOT_PREFIX: &str = "/_waf_hp_";

#[derive(Debug, Clone, PartialEq)]
pub enum PowResult {
    Valid,
    NotSet,
    Invalid,
}

pub fn has_leading_zeros(hash: &[u8], zeros: usize) -> bool {
    let zeros_u8 = zeros / 8;
    let zeros_remainder = zeros % 8;

    let mut result: u8 = 1;

    for hash_byte in &hash[..zeros_u8] {
        result &= (*hash_byte == 0) as u8;
    }

    if zeros_remainder > 0 && zeros_u8 < hash.len() {
        let mask = (0xFF_u8) << (8 - zeros_remainder);
        result &= ((hash[zeros_u8] & mask) == 0) as u8;
    }

    result == 1
}

pub fn has_leading_zeros_ct(hash: &[u8], zeros: usize) -> subtle::Choice {
    let zeros_u8 = zeros / 8;
    let zeros_remainder = zeros % 8;

    let mut result = subtle::Choice::from(1);

    for hash_byte in hash.iter().take(zeros_u8.min(hash.len())) {
        result &= subtle::Choice::from((*hash_byte == 0) as u8);
    }

    if zeros_remainder > 0 && zeros_u8 < hash.len() {
        let mask = (0xFF_u8) << (8 - zeros_remainder);
        result &= subtle::Choice::from(((hash[zeros_u8] & mask) == 0) as u8);
    }

    result
}

pub fn verify_pow_solution(challenge: &str, nonce: &str, difficulty: u8) -> bool {
    let input = format!("{}{}", challenge, nonce);
    let hash = Sha256::digest(input.as_bytes());
    has_leading_zeros(&hash, difficulty as usize)
}

pub fn solve_pow_sync(challenge: &str, difficulty: u8) -> Option<String> {
    let zeros = difficulty as usize;

    for nonce in 0..100_000_000u64 {
        let input = format!("{}{}", challenge, nonce);
        let hash = Sha256::digest(input.as_bytes());

        if has_leading_zeros(&hash, zeros) {
            return Some(nonce.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_zeros() {
        let hash = hex::decode("0001ff").unwrap();
        assert!(has_leading_zeros(&hash, 15));
        assert!(!has_leading_zeros(&hash, 16));
    }

    #[test]
    fn test_leading_zeros_ct() {
        let hash = hex::decode("0001ff").unwrap();
        assert!(has_leading_zeros_ct(&hash, 15).unwrap_u8() == 1);
        assert!(has_leading_zeros_ct(&hash, 16).unwrap_u8() == 0);
    }

    #[test]
    fn test_verify_pow_solution() {
        let challenge = "test_challenge";
        let nonce = "0";
        let _ = verify_pow_solution(challenge, nonce, 1);
    }
}
