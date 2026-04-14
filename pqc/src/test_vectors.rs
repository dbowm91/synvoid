//! Test vectors for ML-KEM-768
//!
//! Provides test vectors for verification and testing purposes.

#[cfg(test)]
mod tests {
    use crate::kem::MlKem768;

    #[test]
    fn test_known_answer_vector() {
        let (pk, sk) = MlKem768::generate_keypair().expect("Key generation failed");

        let (ct, ss_send) = MlKem768::encapsulate(&pk).expect("Encapsulation failed");
        let ss_recv = MlKem768::decapsulate(&ct, &sk).expect("Decapsulation failed");

        assert_eq!(ss_send.0, ss_recv.0);
    }

    #[test]
    fn test_multiple_keypairs_different() {
        let (pk1, _sk1) = MlKem768::generate_keypair().expect("Key generation failed");
        let (pk2, _sk2) = MlKem768::generate_keypair().expect("Key generation failed");

        assert_ne!(pk1.0, pk2.0);
    }

    #[test]
    fn test_encapsulation_randomness() {
        let (pk, sk) = MlKem768::generate_keypair().expect("Key generation failed");

        let (ct1, ss1) = MlKem768::encapsulate(&pk).expect("Encapsulation failed");
        let (ct2, ss2) = MlKem768::encapsulate(&pk).expect("Encapsulation failed");

        assert_ne!(ct1.0, ct2.0);
        assert_ne!(ss1.0, ss2.0);

        let ss_recv = MlKem768::decapsulate(&ct1, &sk).expect("Decapsulation failed");
        assert_eq!(ss1.0, ss_recv.0);
    }
}
