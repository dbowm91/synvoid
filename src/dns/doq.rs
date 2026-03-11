#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::oneshot;

use crate::config::dns::DnsDoqConfig;
use crate::dns::server::DnsServer;
use crate::tls::cert_resolver::CertResolver;

const DOQ_MAX_QUERY_SIZE: usize = 65535;
const DOQ_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

pub struct DoqServer {
    config: Arc<DnsDoqConfig>,
    cert_resolver: Option<Arc<CertResolver>>,
    dns_server: Arc<RwLock<Option<DnsServer>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    endpoint: Option<quinn::Endpoint>,
}

impl DoqServer {
    pub fn new(config: DnsDoqConfig, cert_resolver: Option<Arc<CertResolver>>) -> Self {
        Self {
            config: Arc::new(config),
            cert_resolver,
            dns_server: Arc::new(RwLock::new(None)),
            shutdown_tx: None,
            endpoint: None,
        }
    }

    pub fn set_dns_server(&self, dns_server: DnsServer) {
        *self.dns_server.write() = Some(dns_server);
    }

    pub fn get_dns_server(&self) -> Arc<RwLock<Option<DnsServer>>> {
        self.dns_server.clone()
    }

    pub async fn start(
        &mut self,
        bind_addr: SocketAddr,
        dns_server: DnsServer,
    ) -> Result<(), String> {
        *self.dns_server.write() = Some(dns_server);
        tracing::warn!("DoQ server is not currently functional - Quinn API has changed. DoQ is disabled.");
        Err("DoQ not implemented - Quinn API has changed".to_string())
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}
