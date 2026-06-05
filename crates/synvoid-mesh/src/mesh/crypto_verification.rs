use std::sync::Arc;
use tokio::task;

#[derive(Clone)]
pub struct CryptoVerificationPool {
    max_concurrent: usize,
}

impl CryptoVerificationPool {
    pub fn new(max_concurrent: usize) -> Self {
        Self { max_concurrent }
    }

    pub fn default_pool() -> Self {
        let parallel = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);
        Self {
            max_concurrent: parallel.max(4),
        }
    }

    pub async fn verify_ml_dsa(
        &self,
        verifying_key_bytes: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let vk_bytes = verifying_key_bytes.to_vec();
        let msg = message.to_vec();
        let sig = signature.to_vec();

        task::spawn_blocking(move || {
            let verifying_key = match pqc::VerifyingKey::from_bytes(&vk_bytes) {
                Ok(vk) => vk,
                Err(_) => return false,
            };

            let sig = match pqc::Signature::from_bytes(&sig) {
                Ok(s) => s,
                Err(_) => return false,
            };

            pqc::MlDsa44::verify(&verifying_key, &msg, &sig).is_ok()
        })
        .await
        .unwrap_or(false)
    }

    pub async fn verify_ml_dsa_with_signer(
        &self,
        signer: Arc<crate::ml_dsa::MeshMlDsaSigner>,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let signer = Arc::clone(&signer);
        let msg = message.to_vec();
        let sig = signature.to_vec();

        task::spawn_blocking(move || signer.verify(&msg, &sig))
            .await
            .unwrap_or(false)
    }

    pub async fn verify_ml_dsa_standalone(
        verifying_key_bytes: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let vk_bytes = verifying_key_bytes.to_vec();
        let msg = message.to_vec();
        let sig = signature.to_vec();

        task::spawn_blocking(move || {
            let verifying_key = match pqc::VerifyingKey::from_bytes(&vk_bytes) {
                Ok(vk) => vk,
                Err(_) => return false,
            };

            let sig = match pqc::Signature::from_bytes(&sig) {
                Ok(s) => s,
                Err(_) => return false,
            };

            pqc::MlDsa44::verify(&verifying_key, &msg, &sig).is_ok()
        })
        .await
        .unwrap_or(false)
    }

    pub async fn ml_kem_decapsulate(
        &self,
        secret_key_bytes: &[u8],
        ciphertext_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let sk_bytes = secret_key_bytes.to_vec();
        let ct_bytes = ciphertext_bytes.to_vec();

        let result = task::spawn_blocking(move || -> Result<Vec<u8>, String> {
            use crate::kem::KemSession;
            use crate::kem::MlKem768;
            use crate::kem::MlKem768SecretKey;

            let sk = MlKem768SecretKey::new(sk_bytes);
            MlKem768::decapsulate(&ct_bytes, &sk)
                .map(|ss| ss.as_ref().to_vec())
                .map_err(|e| format!("ML-KEM decapsulation failed: {:?}", e))
        })
        .await;

        match result {
            Ok(inner_result) => inner_result,
            Err(e) => Err(format!("Task join error: {}", e)),
        }
    }

    pub async fn ml_kem_encapsulate(
        &self,
        public_key_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let pk_bytes = public_key_bytes.to_vec();

        let result = task::spawn_blocking(move || -> Result<(Vec<u8>, Vec<u8>), String> {
            use crate::kem::KemSession;
            use crate::kem::MlKem768;
            use crate::kem::MlKem768PublicKey;

            let pk = MlKem768PublicKey(pk_bytes);
            let (ct, ss) = MlKem768::encapsulate(&pk)
                .map_err(|e| format!("ML-KEM encapsulation failed: {:?}", e))?;
            Ok((ct, ss.as_ref().to_vec()))
        })
        .await;

        match result {
            Ok(inner_result) => inner_result,
            Err(e) => Err(format!("Task join error: {}", e)),
        }
    }

    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }
}

impl Default for CryptoVerificationPool {
    fn default() -> Self {
        Self::default_pool()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::KemSession;
    use base64::Engine;

    #[tokio::test]
    async fn test_verify_ml_dsa_success() {
        let pool = CryptoVerificationPool::default_pool();
        let signer = crate::ml_dsa::MeshMlDsaSigner::generate();

        let message = b"test message for ML-DSA verification";
        let signature = signer.sign(message).expect("Signing failed");

        let vk_bytes = signer.verifying_key_base64().unwrap();
        let vk_decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&vk_bytes)
            .unwrap();

        let result = pool.verify_ml_dsa(&vk_decoded, message, &signature).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_verify_ml_dsa_failure_wrong_message() {
        let pool = CryptoVerificationPool::default_pool();
        let signer = crate::ml_dsa::MeshMlDsaSigner::generate();

        let message = b"test message";
        let wrong_message = b"wrong message";
        let signature = signer.sign(message).expect("Signing failed");

        let vk_bytes = signer.verifying_key_base64().unwrap();
        let vk_decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&vk_bytes)
            .unwrap();

        let result = pool
            .verify_ml_dsa(&vk_decoded, wrong_message, &signature)
            .await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_verify_ml_dsa_with_signer() {
        let pool = CryptoVerificationPool::default_pool();
        let signer = Arc::new(crate::ml_dsa::MeshMlDsaSigner::generate());

        let message = b"test message with signer arc";
        let signature = signer.sign(message).expect("Signing failed");

        let result = pool
            .verify_ml_dsa_with_signer(signer, message, &signature)
            .await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_ml_kem_encapsulate_decapsulate() {
        let pool = CryptoVerificationPool::default_pool();

        let (pk, sk) = crate::kem::MlKem768::generate_keypair().unwrap();
        let pk_bytes: Vec<u8> = pk.as_ref().to_vec();

        let (ct, ss_send) = pool
            .ml_kem_encapsulate(&pk_bytes)
            .await
            .expect("encapsulate failed");

        let ss_recv = pool
            .ml_kem_decapsulate(sk.as_ref(), &ct)
            .await
            .expect("decapsulate failed");

        assert_eq!(ss_send, ss_recv);
    }

    #[tokio::test]
    async fn test_verify_ml_dsa_standalone() {
        let signer = crate::ml_dsa::MeshMlDsaSigner::generate();
        let message = b"standalone verification test";
        let signature = signer.sign(message).expect("Signing failed");

        let vk_bytes = signer.verifying_key_base64().unwrap();
        let vk_decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&vk_bytes)
            .unwrap();

        let result =
            CryptoVerificationPool::verify_ml_dsa_standalone(&vk_decoded, message, &signature)
                .await;
        assert!(result);
    }
}
