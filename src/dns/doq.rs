use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::oneshot;
use metrics::{counter, gauge, histogram};

use crate::config::dns::DnsDoqConfig;
use crate::dns::server::DnsServer;
use crate::tls::cert_resolver::CertResolver;

const DOQ_MAX_QUERY_SIZE: usize = 65535;

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

    pub fn config(&self) -> &DnsDoqConfig {
        &self.config
    }

    pub async fn start(
        &mut self,
        bind_addr: SocketAddr,
        dns_server: DnsServer,
    ) -> Result<(), String> {
        *self.dns_server.write() = Some(dns_server);

        let tls_config = self.create_tls_config()?;

        let mut server_crypto = (*tls_config).clone();
        server_crypto.alpn_protocols = vec![b"doq".to_vec()];

        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| format!("Failed to create QUIC server config: {}", e))?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

        let transport_config = Arc::get_mut(&mut server_config.transport)
            .expect("Failed to get transport config");

        transport_config.max_concurrent_uni_streams(self.config.max_concurrent_streams.into());
        transport_config.max_concurrent_bidi_streams(self.config.max_concurrent_streams.into());

        let idle_timeout = quinn::IdleTimeout::try_from(Duration::from_secs(self.config.idle_timeout_secs))
            .map_err(|e| format!("Failed to create idle timeout: {}", e))?;
        transport_config.max_idle_timeout(Some(idle_timeout));

        let endpoint = quinn::Endpoint::server(server_config, bind_addr)
            .map_err(|e| format!("Failed to create DoQ endpoint: {}", e))?;

        tracing::info!("DoQ server listening on {}", bind_addr);

        let dns_server = self.dns_server.clone();
        let config = self.config.clone();

        let (tx, rx) = oneshot::channel::<()>();
        self.shutdown_tx = Some(tx);

        self.endpoint = Some(endpoint.clone());

        Self::accept_loop(endpoint, dns_server, config, rx).await;

        Ok(())
    }

    fn create_tls_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        let resolver = self.cert_resolver
            .as_ref()
            .ok_or_else(|| "No TLS certificate resolver available".to_string())?;
        
        let config = resolver.build_server_config()
            .map_err(|e| format!("Failed to build TLS config: {}", e))?;
        
        Ok(config)
    }

    async fn accept_loop(
        endpoint: quinn::Endpoint,
        dns_server: Arc<RwLock<Option<DnsServer>>>,
        config: Arc<DnsDoqConfig>,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    match incoming {
                        Some(conn) => {
                            let dns_server = dns_server.clone();
                            let config = config.clone();
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(conn, dns_server, config).await {
                                    tracing::debug!("DoQ connection error: {}", e);
                                }
                            });
                        }
                        None => {
                            tracing::info!("DoQ endpoint closed");
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::info!("DoQ server received shutdown signal");
                    endpoint.close(0u32.into(), b"Server shutdown");
                    break;
                }
            }
        }

        tracing::info!("DoQ server shutdown complete");
    }

    async fn handle_connection(
        incoming: quinn::Incoming,
        dns_server: Arc<RwLock<Option<DnsServer>>>,
        _config: Arc<DnsDoqConfig>,
    ) -> Result<(), String> {
        let connection = match incoming.await {
            Ok(conn) => conn,
            Err(e) => {
                counter!("maluwaf.doq.connection.errors").increment(1);
                return Err(format!("DoQ handshake failed: {}", e));
            }
        };

        let remote_addr = connection.remote_address();
        let client_ip = remote_addr.ip();

        tracing::debug!("DoQ connection from {}", remote_addr);

        if let Err(e) = Self::validate_source_address(client_ip) {
            tracing::warn!("DoQ source address validation failed for {}: {}", client_ip, e);
            counter!("maluwaf.doq.connection.rejected").increment(1);
            return Err(format!("Source address validation failed: {}", e));
        }

        gauge!("maluwaf.doq.connections").increment(1.0);
        counter!("maluwaf.doq.connections.total").increment(1);

        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let dns_server = dns_server.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_stream(send, recv, dns_server, client_ip).await {
                            tracing::debug!("DoQ stream error: {}", e);
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    tracing::debug!("DoQ connection closed by client");
                    break;
                }
                Err(e) => {
                    tracing::debug!("DoQ connection error: {}", e);
                    break;
                }
            }
        }

        gauge!("maluwaf.doq.connections").decrement(1.0);
        Ok(())
    }

    fn validate_source_address(client_ip: IpAddr) -> Result<(), String> {
        match client_ip {
            IpAddr::V4(ipv4) => {
                if ipv4.is_unspecified() {
                    return Err("unspecified IPv4 address".to_string());
                }
                if ipv4.is_loopback() {
                    return Ok(());
                }
                if ipv4.is_link_local() {
                    return Err("link-local IPv4 address not allowed".to_string());
                }
                if ipv4.is_broadcast() {
                    return Err("broadcast IPv4 address not allowed".to_string());
                }
                if ipv4.is_multicast() {
                    return Err("multicast IPv4 address not allowed".to_string());
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_unspecified() {
                    return Err("unspecified IPv6 address".to_string());
                }
                if ipv6.is_loopback() {
                    return Ok(());
                }
                let octets = ipv6.octets();
                if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                    return Err("link-local IPv6 address not allowed".to_string());
                }
                if ipv6.is_multicast() {
                    return Err("multicast IPv6 address not allowed".to_string());
                }
            }
        }

        Ok(())
    }

    async fn handle_stream(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        dns_server: Arc<RwLock<Option<DnsServer>>>,
        client_ip: IpAddr,
    ) -> Result<(), String> {
        let start = std::time::Instant::now();

        let query_buf = Self::read_query(&mut recv).await?;
        counter!("maluwaf.doq.queries.total").increment(1);

        let response = {
            let dns_server_guard = dns_server.read();
            let server = match dns_server_guard.as_ref() {
                Some(s) => s,
                None => {
                    counter!("maluwaf.doq.query.errors").increment(1);
                    return Err("DNS server not configured".to_string());
                }
            };

            Self::process_query(server, &query_buf, client_ip)
        };

        match response {
            Some(resp) => {
                Self::write_response(&mut send, &resp).await?;
                histogram!("maluwaf.doq.query.duration").record(start.elapsed().as_secs_f64());
            }
            None => {
                counter!("maluwaf.doq.query.errors").increment(1);
            }
        }

        Ok(())
    }

    fn process_query(server: &DnsServer, query: &[u8], client_ip: IpAddr) -> Option<Arc<Vec<u8>>> {
        let ctx = server.query_context();

        if let Some(c) = &ctx.cache {
            let cache_key = crate::dns::cache::CacheKey::new(
                String::new(),
                crate::dns::server::RecordType::NULL,
                Some(client_ip),
            );
            crate::dns::server::DnsServer::handle_query_with_cache(&ctx, query, c, cache_key, Some(client_ip))
        } else {
            crate::dns::server::DnsServer::handle_query(&ctx, query, Some(client_ip))
        }
    }

    async fn read_query(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, String> {
        let mut length_buf = [0u8; 2];
        recv.read_exact(&mut length_buf)
            .await
            .map_err(|e| format!("Failed to read query length: {}", e))?;

        let length = u16::from_be_bytes(length_buf) as usize;

        if length == 0 || length > DOQ_MAX_QUERY_SIZE {
            return Err(format!("Invalid query length: {}", length));
        }

        let mut query_buf = vec![0u8; length];
        recv.read_exact(&mut query_buf)
            .await
            .map_err(|e| format!("Failed to read query: {}", e))?;

        Ok(query_buf)
    }

    async fn write_response(send: &mut quinn::SendStream, response: &[u8]) -> Result<(), String> {
        let length = (response.len() as u16).to_be_bytes();
        send.write_all(&length)
            .await
            .map_err(|e| format!("Failed to send response length: {}", e))?;
        send.write_all(response)
            .await
            .map_err(|e| format!("Failed to send response: {}", e))?;
        send.finish()
            .map_err(|e| format!("Failed to finish stream: {}", e))?;
        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Clone for DoqServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cert_resolver: self.cert_resolver.clone(),
            dns_server: self.dns_server.clone(),
            shutdown_tx: None,
            endpoint: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DoqServer;
    use crate::config::dns::DnsDoqConfig;

    #[test]
    fn test_doq_server_creation() {
        let config = DnsDoqConfig {
            enabled: true,
            port: 7853,
            bind_address: "127.0.0.1".to_string(),
            tls_cert_path: None,
            tls_key_path: None,
            use_system_cert_store: false,
            max_concurrent_streams: 100,
            idle_timeout_secs: 30,
        };

        let server = DoqServer::new(config, None);

        assert!(server.config().enabled);
        assert_eq!(server.config().port, 7853);
        assert_eq!(server.config().max_concurrent_streams, 100);
        assert_eq!(server.config().idle_timeout_secs, 30);
    }

    #[test]
    fn test_doq_config_defaults() {
        let config = DnsDoqConfig::default();

        assert_eq!(config.port, 853);
        assert_eq!(config.max_concurrent_streams, 100);
        assert_eq!(config.idle_timeout_secs, 30);
    }

    #[test]
    fn test_doq_frame_format() {
        let query = build_dns_query();

        let length_bytes = (query.len() as u16).to_be_bytes();
        let mut framed = Vec::new();
        framed.extend_from_slice(&length_bytes);
        framed.extend_from_slice(&query);

        assert_eq!(framed.len(), query.len() + 2);

        let read_length = u16::from_be_bytes([framed[0], framed[1]]) as usize;
        assert_eq!(read_length, query.len());
    }

    #[test]
    fn test_doq_alpn_token() {
        let alpn = b"doq";
        assert_eq!(alpn, b"doq");
    }

    fn build_dns_query() -> Vec<u8> {
        let mut query = Vec::new();

        query.extend_from_slice(&[
            0x00, 0x01,
            0x01, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);

        for label in b"example" {
            query.push(*label);
        }
        query.push(0);

        query.extend_from_slice(&[
            0x00, 0x01,
            0x00, 0x01,
        ]);

        query
    }
}
