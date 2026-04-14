use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dashmap::DashMap;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};

use super::cert_resolver::CertResolver;
use super::config::InternalAcmeConfig;

struct ManagedCert {
    domain: String,
    expires_at: SystemTime,
}

struct ChallengeGuard {
    http_challenges: Arc<DashMap<String, String>>,
    tokens: Vec<String>,
}

impl ChallengeGuard {
    fn new(http_challenges: Arc<DashMap<String, String>>) -> Self {
        Self {
            http_challenges,
            tokens: Vec::new(),
        }
    }

    fn add_token(&mut self, token: String) {
        self.tokens.push(token);
    }

    fn clear_challenges(&self) {
        for token in &self.tokens {
            self.http_challenges.remove(token);
        }
    }
}

impl Drop for ChallengeGuard {
    fn drop(&mut self) {
        self.clear_challenges();
    }
}

pub struct AcmeManager {
    config: InternalAcmeConfig,
    cert_resolver: Arc<CertResolver>,
    account: parking_lot::RwLock<Option<Account>>,
    credentials_path: PathBuf,
    http_challenges: Arc<DashMap<String, String>>,
    managed_certs: parking_lot::RwLock<HashMap<String, ManagedCert>>,
}

impl AcmeManager {
    pub fn new(config: InternalAcmeConfig, cert_resolver: Arc<CertResolver>) -> Self {
        let cache_dir = config
            .cache_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/maluwaf/acme"));

        let credentials_path = cache_dir.join("account_credentials.json");

        Self {
            config,
            cert_resolver,
            account: parking_lot::RwLock::new(None),
            credentials_path,
            http_challenges: Arc::new(DashMap::new()),
            managed_certs: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Initialize the ACME account, loading from cache or creating new.
    pub async fn init(&self) -> Result<(), AcmeError> {
        if !self.config.enabled {
            return Ok(());
        }

        let directory_url = if self.config.staging {
            LetsEncrypt::Staging.url().to_string()
        } else {
            LetsEncrypt::Production.url().to_string()
        };

        let email = self
            .config
            .email
            .as_ref()
            .ok_or(AcmeError::Config("ACME email not configured".into()))?;

        // Try loading existing credentials
        if self.credentials_path.exists() {
            match std::fs::read_to_string(&self.credentials_path) {
                Ok(creds_json) => match serde_json::from_str::<AccountCredentials>(&creds_json) {
                    Ok(credentials) => {
                        let builder = Account::builder().map_err(|e| {
                            AcmeError::Protocol(format!("Failed to create account builder: {}", e))
                        })?;
                        match builder.from_credentials(credentials).await {
                            Ok(account) => {
                                tracing::info!(
                                    "Loaded existing ACME account from {:?}",
                                    self.credentials_path
                                );
                                *self.account.write() = Some(account);
                                return Ok(());
                            }
                            Err(e) => {
                                tracing::warn!(
                                        "Failed to restore ACME account credentials: {}, creating new account",
                                        e
                                    );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse ACME credentials: {}", e);
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read ACME credentials file: {}", e);
                }
            }
        }

        // Create new account
        let contact_str = format!("mailto:{}", email);
        let contact = &[contact_str.as_str()];
        let new_account = NewAccount {
            contact,
            terms_of_service_agreed: self.config.terms_of_service_agreed,
            only_return_existing: false,
        };

        let builder = Account::builder()
            .map_err(|e| AcmeError::Protocol(format!("Failed to create account builder: {}", e)))?;

        let (account, credentials) = builder
            .create(&new_account, directory_url, None)
            .await
            .map_err(|e| AcmeError::Protocol(format!("Failed to create ACME account: {}", e)))?;

        // Persist credentials with restrictive permissions (0600)
        // Write to temp file first to avoid race condition where file exists with default permissions
        if let Some(parent) = self.credentials_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AcmeError::Io(format!("Failed to create cache dir: {}", e)))?;
        }

        let creds_json = serde_json::to_string(&credentials)
            .map_err(|e| AcmeError::Config(format!("Failed to serialize credentials: {}", e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let temp_path = self.credentials_path.with_extension("tmp");
            let mut file = std::fs::File::create(&temp_path).map_err(|e| {
                AcmeError::Io(format!("Failed to create temp credentials file: {}", e))
            })?;
            let perms = std::fs::Permissions::from_mode(0o600);
            file.set_permissions(perms).map_err(|e| {
                AcmeError::Io(format!("Failed to set permissions on temp file: {}", e))
            })?;
            use std::io::Write;
            file.write_all(creds_json.as_bytes())
                .map_err(|e| AcmeError::Io(format!("Failed to write credentials: {}", e)))?;
            drop(file);
            std::fs::rename(&temp_path, &self.credentials_path).map_err(|e| {
                AcmeError::Io(format!("Failed to rename temp credentials file: {}", e))
            })?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&self.credentials_path, creds_json)
                .map_err(|e| AcmeError::Io(format!("Failed to write credentials: {}", e)))?;
        }

        tracing::info!("Created new ACME account for {}", email);
        *self.account.write() = Some(account);

        Ok(())
    }

    /// Request a certificate for the given domain via ACME.
    pub async fn request_certificate(&self, domain: &str) -> Result<Vec<u8>, AcmeError> {
        if !self.config.enabled {
            return Err(AcmeError::Disabled);
        }

        let account = self
            .account
            .read()
            .clone()
            .ok_or(AcmeError::Config("ACME account not initialized".into()))?;

        let identifiers = vec![Identifier::Dns(domain.to_string())];
        let new_order = NewOrder::new(&identifiers);

        let mut order = account
            .new_order(&new_order)
            .await
            .map_err(|e| AcmeError::Protocol(format!("Failed to create ACME order: {}", e)))?;

        // Process authorizations and set up challenges
        let mut auths = order.authorizations();
        let mut challenge_guard = ChallengeGuard::new(self.http_challenges.clone());
        while let Some(auth_result) = auths.next().await {
            let mut auth = auth_result
                .map_err(|e| AcmeError::Protocol(format!("Failed to get authorization: {}", e)))?;

            if matches!(auth.status, AuthorizationStatus::Valid) {
                continue;
            }

            // Determine which challenge type to use
            let challenge_type = self.get_acme_challenge_type();

            // Try to get a challenge handle for the desired type
            let mut challenge_handle = auth.challenge(challenge_type.clone()).ok_or_else(|| {
                AcmeError::Protocol(format!(
                    "No {:?} challenge available for domain: {}",
                    challenge_type, domain
                ))
            })?;

            let key_auth = challenge_handle.key_authorization();

            match challenge_type {
                ChallengeType::Http01 => {
                    // Store key authorization for HTTP-01 challenge
                    // ChallengeHandle derefs to Challenge which has a `token` field
                    let token = challenge_handle.token.clone();
                    let token_for_log = token.clone();
                    self.http_challenges
                        .insert(token.clone(), key_auth.as_str().to_string());
                    challenge_guard.add_token(token);

                    tracing::info!(
                        "HTTP-01 challenge ready for {} at /.well-known/acme-challenge/{}",
                        domain,
                        token_for_log
                    );
                }
                ChallengeType::Dns01 => {
                    // DNS-01 challenge handled externally
                    let dns_value = key_auth.dns_value();
                    tracing::info!(
                        "DNS-01 challenge for {} — TXT record _acme-challenge.{} = {}",
                        domain,
                        domain,
                        dns_value
                    );
                }
                _ => {
                    return Err(AcmeError::Protocol(format!(
                        "Unsupported challenge type for domain: {}",
                        domain
                    )));
                }
            }

            // Set challenge as ready
            challenge_handle.set_ready().await.map_err(|e| {
                AcmeError::Protocol(format!("Failed to set challenge ready: {}", e))
            })?;
        }
        // challenge_guard is dropped here on early return, cleaning up challenges
        // On success, explicit cleanup below also runs (may be redundant but harmless)

        // Poll for order readiness
        let retry = RetryPolicy::new().timeout(Duration::from_secs(120));
        let status = order
            .poll_ready(&retry)
            .await
            .map_err(|e| AcmeError::Protocol(format!("Order polling failed: {}", e)))?;

        if status != OrderStatus::Ready {
            return Err(AcmeError::Protocol(format!(
                "Order not ready after polling, status: {:?}",
                status
            )));
        }

        // Finalize — generates CSR via rcgen
        let private_key_pem = order
            .finalize()
            .await
            .map_err(|e| AcmeError::Protocol(format!("Failed to finalize order: {}", e)))?;

        // Poll for certificate
        let cert_pem = order
            .poll_certificate(&retry)
            .await
            .map_err(|e| AcmeError::Protocol(format!("Failed to get certificate: {}", e)))?;

        // Write cert and key to configured paths
        let cache_dir = self
            .config
            .cache_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/maluwaf/acme"));

        let cert_path = cache_dir.join(format!("{}.pem", domain));
        let key_path = cache_dir.join(format!("{}.key", domain));

        std::fs::create_dir_all(&cache_dir)
            .map_err(|e| AcmeError::Io(format!("Failed to create cache dir: {}", e)))?;
        std::fs::write(&cert_path, &cert_pem)
            .map_err(|e| AcmeError::Io(format!("Failed to write cert: {}", e)))?;
        std::fs::write(&key_path, &private_key_pem)
            .map_err(|e| AcmeError::Io(format!("Failed to write key: {}", e)))?;

        // Parse expiry from cert
        let expires_at = parse_cert_expiry(&cert_pem).unwrap_or_else(|_| {
            SystemTime::now() + Duration::from_secs(90 * 24 * 3600) // default 90 days
        });

        self.managed_certs.write().insert(
            domain.to_string(),
            ManagedCert {
                domain: domain.to_string(),
                expires_at,
            },
        );

        // Challenge cleanup is handled by ChallengeGuard drop on all code paths

        tracing::info!(
            "ACME certificate obtained for {} (expires: {:?}), written to {:?}",
            domain,
            expires_at,
            cert_path
        );

        // Reload cert resolver
        if let Err(e) = self.cert_resolver.load_certificates() {
            tracing::warn!("Failed to reload certificates after ACME issuance: {}", e);
        }

        Ok(cert_pem.as_bytes().to_vec())
    }

    /// Returns key authorization for HTTP-01 challenge path.
    pub fn handle_http_challenge(&self, path: &str) -> Option<String> {
        // Extract token from path: /.well-known/acme-challenge/{token}
        let token = path.strip_prefix("/.well-known/acme-challenge/")?;
        self.http_challenges.get(token).map(|v| v.clone())
    }

    /// Check managed certs for expiring ones and renew.
    pub async fn renew_expiring(&self) -> Result<Vec<String>, AcmeError> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }

        let threshold = SystemTime::now() + Duration::from_secs(30 * 24 * 3600); // 30 days
        let mut renewed = Vec::new();

        let domains_to_renew: Vec<String> = self
            .managed_certs
            .read()
            .values()
            .filter(|cert| cert.expires_at < threshold)
            .map(|cert| cert.domain.clone())
            .collect();

        for domain in domains_to_renew {
            tracing::info!("Renewing ACME certificate for {} (expiring soon)", domain);
            match self.request_certificate(&domain).await {
                Ok(_) => {
                    renewed.push(domain.clone());
                    tracing::info!("Successfully renewed certificate for {}", domain);
                }
                Err(e) => {
                    tracing::error!("Failed to renew certificate for {}: {}", domain, e);
                }
            }
        }

        Ok(renewed)
    }

    /// Spawn a background task that checks for cert renewal every 24 hours.
    pub fn spawn_renewal_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(24 * 3600));
            interval.tick().await; // skip first immediate tick

            loop {
                interval.tick().await;
                tracing::debug!("ACME renewal check");

                match self.renew_expiring().await {
                    Ok(renewed) => {
                        if !renewed.is_empty() {
                            tracing::info!("ACME renewed {} certificate(s)", renewed.len());
                        }
                    }
                    Err(e) => {
                        tracing::error!("ACME renewal check failed: {}", e);
                    }
                }

                // Also reload certs from disk (in case external tools updated them)
                if let Err(e) = self.cert_resolver.load_certificates() {
                    tracing::error!("Failed to reload certificates: {}", e);
                }
            }
        })
    }

    fn get_acme_challenge_type(&self) -> ChallengeType {
        match self.config.challenge_type {
            super::config::InternalAcmeChallengeType::Http01 => ChallengeType::Http01,
            super::config::InternalAcmeChallengeType::Dns01 => ChallengeType::Dns01,
        }
    }

    /// Get the HTTP challenge store for passing to the HTTP server.
    pub fn http_challenges(&self) -> Arc<DashMap<String, String>> {
        self.http_challenges.clone()
    }
}

fn parse_cert_expiry(pem: &str) -> Result<SystemTime, String> {
    // Use x509-parser to extract the not_after field
    let der_start = pem
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or("No certificate block found")?;
    let der_end = pem[der_start..]
        .find("-----END CERTIFICATE-----")
        .ok_or("No end certificate block")?;
    let cert_block = &pem[der_start..der_start + der_end];

    // Extract base64 content between headers
    let b64: String = cert_block
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();

    let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| format!("Failed to parse x509: {:?}", e))?;

    let not_after = cert.tbs_certificate.validity.not_after.to_datetime();
    Ok(SystemTime::from(not_after))
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("ACME is disabled")]
    Disabled,

    #[error("ACME protocol error: {0}")]
    Protocol(String),

    #[error("ACME config error: {0}")]
    Config(String),

    #[error("ACME IO error: {0}")]
    Io(String),
}

// For backward compatibility with existing code
pub type AcmeClient = AcmeManager;

#[derive(Debug, Clone, Default)]
pub struct AcmeState {
    pub last_order: Option<chrono::DateTime<chrono::Utc>>,
    pub pending_orders: Vec<String>,
    pub errors: Vec<String>,
}

impl AcmeClient {
    pub async fn get_state(&self) -> AcmeState {
        let certs = self.managed_certs.read();
        let now = chrono::Utc::now();
        let mut pending_orders = Vec::new();
        let mut last_order: Option<chrono::DateTime<chrono::Utc>> = None;

        for (domain, cert) in certs.iter() {
            let expires_at = chrono::DateTime::<chrono::Utc>::from(cert.expires_at);
            if expires_at > now {
                if last_order.is_none() || expires_at > last_order.unwrap() {
                    last_order = Some(expires_at);
                }
            } else {
                pending_orders.push(domain.clone());
            }
        }

        AcmeState {
            last_order,
            pending_orders,
            errors: Vec::new(),
        }
    }
}
