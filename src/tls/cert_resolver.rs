use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{PathBuf, Path};
use std::sync::Arc;
use parking_lot::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls::crypto::{aws_lc_rs::default_provider, CryptoProvider, KeyProvider};
use tokio::sync::broadcast;
use notify::Watcher;

use super::config::InternalTlsConfig;

#[derive(Clone)]
pub struct CertResolver {
    certs: Arc<RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
    default_cert: Arc<RwLock<Option<Arc<rustls::sign::CertifiedKey>>>>,
    config: InternalTlsConfig,
    reload_tx: broadcast::Sender<()>,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolver")
            .field("config", &self.config)
            .finish()
    }
}

impl CertResolver {
    pub fn new(config: InternalTlsConfig) -> Self {
        let (reload_tx, _) = broadcast::channel(16);
        Self {
            certs: Arc::new(RwLock::new(HashMap::new())),
            default_cert: Arc::new(RwLock::new(None)),
            config,
            reload_tx,
        }
    }

    pub fn reload_tx(&self) -> broadcast::Sender<()> {
        self.reload_tx.clone()
    }

    pub fn load_certificates(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cert_path = match &self.config.cert_path {
            Some(p) => p,
            None => return Err("No certificate path configured".into()),
        };

        let key_path = match &self.config.key_path {
            Some(p) => p,
            None => return Err("No key path configured".into()),
        };

        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;

        let provider = default_provider();
        let signing_key = provider.key_provider.load_private_key(key)
            .map_err(|e| format!("Failed to load private key: {}", e))?;

        let certified_key = rustls::sign::CertifiedKey::new(certs, signing_key);

        *self.default_cert.write() = Some(Arc::new(certified_key.clone()));

        if let Some(watch_dir) = &self.config.watch_dir {
            self.load_certs_from_dir(watch_dir)?;
        }

        let _ = self.reload_tx.send(());
        Ok(())
    }

    fn load_certs_from_dir(&self, dir: &PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().map(|e| e == "pem").unwrap_or(false) {
                if let Some(stem) = path.file_stem() {
                    if let Some(domain) = stem.to_str() {
                        if let Ok(certs) = load_certs(&path) {
                            let key_path = path.with_extension("key");
                            if key_path.exists() {
                                if let Ok(key) = load_private_key(&key_path) {
                                    let provider = default_provider();
                                    if let Ok(signing_key) = provider.key_provider.load_private_key(key) {
                                        let certified_key = rustls::sign::CertifiedKey::new(certs, signing_key);
                                        self.certs.write().insert(domain.to_string(), Arc::new(certified_key));
                                        tracing::info!("Loaded certificate for domain: {}", domain);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn build_server_config(&self) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
        let provider = default_provider();

        let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("Failed to set protocol versions: {}", e))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(self.clone()));

        Ok(Arc::new(server_config))
    }
}

impl rustls::server::ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(sni) = client_hello.server_name() {
            if let Some(cert) = self.certs.read().get(sni) {
                return Some(cert.clone());
            }
        }
        
        self.default_cert.read().as_ref().cloned()
    }
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    
    if certs.is_empty() {
        return Err("No certificates found in file".into());
    }

    Ok(certs)
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            None => break,
            _ => continue,
        }
    }

    Err("No private key found in file".into())
}

pub fn watch_for_cert_changes(resolver: Arc<CertResolver>, watch_dir: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);
        
        let mut watcher = match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if res.is_ok() {
                let _ = tx.blocking_send(());
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Failed to create file watcher: {}", e);
                return;
            }
        };

        if let Err(e) = watcher.watch(watch_dir.as_path(), notify::RecursiveMode::Recursive) {
            tracing::error!("Failed to watch certificate directory: {}", e);
            return;
        }

        tracing::info!("Watching for certificate changes in {:?}", watch_dir);

        loop {
            tokio::select! {
                Some(_) = rx.recv() => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    tracing::info!("Certificate change detected, reloading...");
                    if let Err(e) = resolver.load_certificates() {
                        tracing::error!("Failed to reload certificates: {}", e);
                    } else {
                        tracing::info!("Certificates reloaded successfully");
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(3600)) => {
                    tracing::debug!("Certificate watcher heartbeat");
                }
            }
        }
    })
}
