use base64::Engine;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct BasicAuthConfig {
    pub enabled: bool,
    pub users: std::collections::HashMap<String, String>,
    pub realm: Option<String>,
}

pub struct BasicAuthManager {
    realm: String,
    users: Arc<RwLock<HashMap<String, String>>>,
}

impl BasicAuthManager {
    pub fn new(config: &BasicAuthConfig) -> Option<Arc<Self>> {
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
        }))
    }

    pub fn check_credentials(&self, auth_header: &str) -> Option<bool> {
        let credentials = auth_header.strip_prefix("Basic ")?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(credentials)
            .ok()?;

        let credentials_str = String::from_utf8(decoded).ok()?;
        let (username, password) = credentials_str.split_once(':')?;

        let users = self.users.read();
        let stored_hash = users.get(username)?;

        match bcrypt::verify(password, stored_hash) {
            Ok(valid) => Some(valid),
            Err(e) => {
                tracing::warn!("Failed to verify password for {}: {}", username, e);
                Some(false)
            }
        }
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn authenticate_request(&self, headers: &http::HeaderMap) -> BasicAuthResult {
        let auth_header = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        match auth_header {
            Some(header) => {
                if self.check_credentials(&header) == Some(true) {
                    BasicAuthResult::Authenticated
                } else {
                    BasicAuthResult::Unauthorized
                }
            }
            None => BasicAuthResult::CredentialsRequired,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BasicAuthResult {
    Authenticated,
    CredentialsRequired,
    Unauthorized,
}

impl BasicAuthResult {
    pub fn is_authenticated(&self) -> bool {
        matches!(self, BasicAuthResult::Authenticated)
    }

    pub fn requires_401(&self) -> bool {
        !self.is_authenticated()
    }
}
