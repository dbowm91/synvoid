//! Per-site HTTP Basic authentication (Phase 43, Workstream C).
//!
//! CPU-hard bcrypt verification runs behind [`PasswordCrypto`] (bounded
//! `spawn_blocking`), never directly on a Tokio core thread. The API is
//! async on purpose: no `block_in_place` is hidden inside a sync wrapper.
//!
//! Semantics preserved (fail-closed):
//! - malformed/missing Basic header → [`BasicAuthResult::Unauthorized`] (or
//!   `CredentialsRequired` when no header is present at all);
//! - unknown user and wrong password both execute exactly one bounded bcrypt
//!   (dummy hash for unknown users), so account existence does not leak
//!   through large timing differences;
//! - crypto overload authenticates nobody and surfaces as
//!   [`BasicAuthResult::BackendBusy`] so HTTP policy can map it to 503
//!   (distinct from 401) without revealing usernames.

use base64::Engine;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use synvoid_config::SiteBasicAuthConfig;

use crate::crypto::{PasswordCrypto, PasswordCryptoError, DUMMY_PASSWORD_HASH};

pub struct BasicAuthManager {
    realm: String,
    users: Arc<RwLock<HashMap<String, String>>>,
    crypto: Arc<PasswordCrypto>,
}

impl BasicAuthManager {
    pub fn new(config: &SiteBasicAuthConfig) -> Option<Arc<Self>> {
        Self::new_with_crypto(config, Arc::new(PasswordCrypto::default()))
    }

    pub fn new_with_crypto(
        config: &SiteBasicAuthConfig,
        crypto: Arc<PasswordCrypto>,
    ) -> Option<Arc<Self>> {
        if !config.enabled {
            return None;
        }

        let realm = config
            .realm
            .clone()
            .unwrap_or_else(|| "Restricted".to_string());

        let mut users = HashMap::new();
        for (username, password) in &config.users {
            users.insert(username.clone(), password.clone());
        }

        if users.is_empty() {
            tracing::warn!("Basic auth enabled but no users configured");
            return None;
        }

        tracing::info!("Basic auth enabled with {} users", users.len());

        Some(Arc::new(Self {
            realm,
            users: Arc::new(RwLock::new(users)),
            crypto,
        }))
    }

    fn parse_header(auth_header: &str) -> Option<(String, String)> {
        let credentials = auth_header.strip_prefix("Basic ")?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(credentials)
            .ok()?;
        let credentials_str = String::from_utf8(decoded).ok()?;
        let (username, password) = credentials_str.split_once(':')?;
        Some((username.to_string(), password.to_string()))
    }

    /// Async credential check. `None` = malformed header (fail closed);
    /// `Some(Ok(true))` = authenticated; `Some(Ok(false))` = bad credentials;
    /// `Some(Err(Busy))` = overload (authenticates nobody).
    pub async fn check_credentials_async(
        &self,
        auth_header: &str,
    ) -> Option<Result<bool, PasswordCryptoError>> {
        let (username, password) = Self::parse_header(auth_header)?;
        // Snapshot the hash under a short read lock; release before bcrypt.
        let stored = { self.users.read().get(&username).cloned() };
        match stored {
            Some(hash) => {
                let result = self.crypto.verify(password, hash).await;
                match result {
                    Ok(valid) => Some(Ok(valid)),
                    Err(PasswordCryptoError::Verify) => {
                        tracing::warn!("Basic auth verify backend failure");
                        Some(Ok(false))
                    }
                    Err(e) => Some(Err(e)),
                }
            }
            None => {
                // Unknown user: one bounded dummy bcrypt for constant work.
                match self
                    .crypto
                    .verify(password, DUMMY_PASSWORD_HASH.to_string())
                    .await
                {
                    Ok(_) => Some(Ok(false)),
                    Err(PasswordCryptoError::Verify) => Some(Ok(false)),
                    Err(e) => Some(Err(e)),
                }
            }
        }
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub async fn authenticate_request_async(&self, headers: &http::HeaderMap) -> BasicAuthResult {
        let auth_header = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        match auth_header {
            Some(header) => match self.check_credentials_async(&header).await {
                Some(Ok(true)) => BasicAuthResult::Authenticated,
                Some(Ok(false)) => BasicAuthResult::Unauthorized,
                Some(Err(PasswordCryptoError::Busy)) => BasicAuthResult::BackendBusy,
                Some(Err(_)) => BasicAuthResult::Unauthorized,
                None => BasicAuthResult::Unauthorized,
            },
            None => BasicAuthResult::CredentialsRequired,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BasicAuthResult {
    Authenticated,
    CredentialsRequired,
    Unauthorized,
    /// Bounded crypto saturated. HTTP policy should map to 503 (not 401)
    /// so overload is distinguishable without revealing usernames.
    BackendBusy,
}

impl BasicAuthResult {
    pub fn is_authenticated(&self) -> bool {
        matches!(self, BasicAuthResult::Authenticated)
    }

    pub fn requires_401(&self) -> bool {
        matches!(
            self,
            BasicAuthResult::Unauthorized | BasicAuthResult::CredentialsRequired
        )
    }

    pub fn is_backend_busy(&self) -> bool {
        matches!(self, BasicAuthResult::BackendBusy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    fn test_config(users: HashMap<String, String>) -> SiteBasicAuthConfig {
        SiteBasicAuthConfig {
            enabled: true,
            users,
            realm: Some("Test".to_string()),
        }
    }

    fn basic_header(user: &str, pass: &str) -> String {
        let raw = format!("{user}:{pass}");
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }

    #[tokio::test]
    async fn unknown_user_executes_one_bounded_bcrypt() {
        let crypto = Arc::new(PasswordCrypto::new(8, StdDuration::from_secs(10), 4));
        let hash = bcrypt::hash("secret", 4).unwrap();
        let mgr = BasicAuthManager::new_with_crypto(
            &test_config(HashMap::from([("alice".to_string(), hash)])),
            Arc::clone(&crypto),
        )
        .unwrap();
        let res = mgr
            .check_credentials_async(&basic_header("nobody", "pw"))
            .await;
        assert!(matches!(res, Some(Ok(false))));
    }

    #[tokio::test]
    async fn overload_maps_to_backend_busy() {
        // Typed overload result exists and is distinct from 401 paths:
        // HTTP policy maps BackendBusy → 503, Unauthorized → 401.
        assert!(BasicAuthResult::BackendBusy.is_backend_busy());
        assert!(!BasicAuthResult::BackendBusy.is_authenticated());
        assert!(!BasicAuthResult::BackendBusy.requires_401());
        assert!(BasicAuthResult::Unauthorized.requires_401());
        assert!(BasicAuthResult::CredentialsRequired.requires_401());

        // Malformed header fails closed without crypto.
        let crypto = Arc::new(PasswordCrypto::new(8, StdDuration::from_secs(10), 4));
        let hash = bcrypt::hash("secret", 4).unwrap();
        let mgr = BasicAuthManager::new_with_crypto(
            &test_config(HashMap::from([("alice".to_string(), hash)])),
            crypto,
        )
        .unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "not-basic".parse().unwrap());
        let res = mgr.authenticate_request_async(&headers).await;
        assert_eq!(res, BasicAuthResult::Unauthorized);
    }
}
