//! DNS-01 ACME challenge support.
//!
//! This module provides DNS-01 challenge integration for ACME certificate
//! issuance. It creates and manages `_acme-challenge.{domain}` TXT records
//! via the DNS server API.

use std::sync::Arc;

/// DNS-01 challenge manager for ACME.
#[derive(Clone)]
pub struct AcmeDnsChallenge {
    /// Pending challenges: domain -> key_authorization (dns value)
    pending: Arc<dashmap::DashMap<String, String>>,
}

impl AcmeDnsChallenge {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Prepare a DNS-01 challenge by computing the expected TXT record value.
    /// The value is the SHA-256 hash of the key authorization, base64url encoded.
    #[allow(deprecated)]
    pub fn prepare_challenge(&self, domain: &str, key_authorization: &str) -> String {
        use base64::Engine;
        use sha2::Digest;

        let mut hasher = sha2::Sha256::new();
        hasher.update(key_authorization.as_bytes());
        let hash = hasher.finalize();

        let txt_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_slice());

        self.pending.insert(domain.to_string(), txt_value.clone());

        tracing::info!(
            "DNS-01 challenge prepared: _acme-challenge.{} = {}",
            domain,
            txt_value
        );

        txt_value
    }

    /// Get the TXT record value for a pending challenge.
    pub fn get_txt_value(&self, domain: &str) -> Option<String> {
        self.pending.get(domain).map(|v| v.clone())
    }

    /// Clean up a challenge after completion.
    pub fn cleanup(&self, domain: &str) {
        self.pending.remove(domain);
        tracing::debug!("DNS-01 challenge cleaned up for {}", domain);
    }

    /// Get all pending challenges (for DNS server to serve).
    pub fn pending_challenges(&self) -> Vec<(String, String)> {
        self.pending
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }
}

impl Default for AcmeDnsChallenge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_challenge_prepare() {
        let challenge = AcmeDnsChallenge::new();
        let txt = challenge.prepare_challenge("example.com", "test-key-auth-value");
        assert!(!txt.is_empty());
        assert_eq!(challenge.get_txt_value("example.com"), Some(txt));
    }

    #[test]
    fn test_dns_challenge_cleanup() {
        let challenge = AcmeDnsChallenge::new();
        challenge.prepare_challenge("example.com", "test-key-auth-value");
        assert!(challenge.get_txt_value("example.com").is_some());
        challenge.cleanup("example.com");
        assert!(challenge.get_txt_value("example.com").is_none());
    }
}
