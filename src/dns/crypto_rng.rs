pub fn random_u16() -> u16 {
    let mut bytes = [0u8; 2];
    getrandom::getrandom(&mut bytes).unwrap();
    u16::from_be_bytes(bytes)
}

pub fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).unwrap();
    u32::from_be_bytes(bytes)
}

pub fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).unwrap();
    u64::from_be_bytes(bytes)
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).unwrap();
    bytes
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).unwrap();
    bytes
}

pub fn fill_bytes(dest: &mut [u8]) {
    getrandom::getrandom(dest).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_u16_generates_valid_value() {
        let val = random_u16();
        assert!(val <= u16::MAX);
    }

    #[test]
    fn test_random_u16_unique_values() {
        let mut values = std::collections::HashSet::new();
        for _ in 0..1000 {
            values.insert(random_u16());
        }
        assert!(
            values.len() > 900,
            "Expected mostly unique values, got {}",
            values.len()
        );
    }

    #[test]
    fn test_random_u32_generates_valid_value() {
        let val = random_u32();
        assert!(val <= u32::MAX);
    }

    #[test]
    fn test_random_u64_generates_valid_value() {
        let val = random_u64();
        assert!(val <= u64::MAX);
    }

    #[test]
    fn test_random_bytes_length() {
        for len in [0, 1, 16, 32, 64, 256] {
            let bytes = random_bytes(len);
            assert_eq!(bytes.len(), len);
        }
    }

    #[test]
    fn test_random_bytes_unique() {
        let mut values = std::collections::HashSet::new();
        for _ in 0..100 {
            let bytes = random_bytes(32);
            values.insert(bytes);
        }
        assert!(
            values.len() == 100,
            "Expected all unique, got {}",
            values.len()
        );
    }

    #[test]
    fn test_random_array_16() {
        let arr: [u8; 16] = random_array();
        assert_eq!(arr.len(), 16);
    }

    #[test]
    fn test_random_array_32() {
        let arr: [u8; 32] = random_array();
        assert_eq!(arr.len(), 32);
    }

    #[test]
    fn test_random_array_64() {
        let arr: [u8; 64] = random_array();
        assert_eq!(arr.len(), 64);
    }

    #[test]
    fn test_fill_bytes() {
        let mut dest = [0u8; 100];
        fill_bytes(&mut dest);
        assert!(dest.iter().any(|&b| b != 0), "Expected non-zero bytes");
    }

    #[test]
    fn test_fill_bytes_modifies_all_bytes() {
        let mut dest = [0u8; 1000];
        fill_bytes(&mut dest);
        let non_zero_count = dest.iter().filter(|&&b| b != 0).count();
        assert!(
            non_zero_count > 900,
            "Expected >90% non-zero, got {}",
            non_zero_count
        );
    }
}
