use std::sync::Arc;
use tokio::sync::RwLock;

use super::cert_resolver::CertResolver;
use super::config::InternalAcmeConfig;

pub struct AcmeClient {
    config: InternalAcmeConfig,
    cert_resolver: Arc<CertResolver>,
    state: Arc<RwLock<AcmeState>>,
}

#[derive(Debug, Clone, Default)]
pub struct AcmeState {
    pub last_order: Option<chrono::DateTime<chrono::Utc>>,
    pub pending_orders: Vec<String>,
    pub errors: Vec<String>,
}

impl AcmeClient {
    pub fn new(config: InternalAcmeConfig, cert_resolver: Arc<CertResolver>) -> Self {
        Self {
            config,
            cert_resolver,
            state: Arc::new(RwLock::new(AcmeState::default())),
        }
    }

    pub async fn request_certificate(&self, domain: &str) -> Result<Vec<u8>, AcmeError> {
        if !self.config.enabled {
            return Err(AcmeError::Disabled);
        }
        tracing::info!(
            "ACME for {} requires external certbot/lego. Place certs in configured cert_path.",
            domain
        );
        Err(AcmeError::UseExternalClient)
    }

    pub async fn renew_expiring(&self) -> Result<Vec<String>, AcmeError> {
        Ok(Vec::new())
    }

    pub async fn get_state(&self) -> AcmeState {
        self.state.read().await.clone()
    }

    pub fn spawn_renewal_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60 * 60 * 24));
            loop {
                interval.tick().await;
                if let Err(e) = self.cert_resolver.load_certificates() {
                    tracing::error!("Failed to reload certificates: {}", e);
                }
            }
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("ACME is disabled")]
    Disabled,
    #[error("Use external ACME client (certbot/lego) - place certificates in configured paths")]
    UseExternalClient,
}
