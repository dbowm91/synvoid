use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::config::dns::DnsDotConfig;
use crate::dns::cache::CacheKey;
use crate::dns::secure_server::{
    DnsServerConfig, SecureDnsServerBase, MAX_QUERY_SIZE, TLS_HANDSHAKE_TIMEOUT_SECS,
};
use crate::dns::server::{DnsServer, RecordType};
use crate::tls::cert_resolver::CertResolver;

pub const DOT_MAX_QUERY_SIZE: usize = MAX_QUERY_SIZE;

impl DnsServerConfig for DnsDotConfig {
    fn bind_address(&self) -> &str {
        &self.bind_address
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn server_name(&self) -> &'static str {
        "DoT"
    }
}

pub struct DotServer {
    base: SecureDnsServerBase<DnsDotConfig>,
}

impl DotServer {
    pub fn new(config: DnsDotConfig, cert_resolver: Option<Arc<CertResolver>>) -> Self {
        Self {
            base: SecureDnsServerBase::new(config, cert_resolver),
        }
    }

    pub fn set_dns_server(&self, server: DnsServer) {
        self.base.set_dns_server(server);
    }

    pub async fn start(&mut self) -> Result<(), String> {
        let bind_address = self.base.config.bind_address.clone();
        let port = self.base.config.port;
        self.base
            .start_server(&bind_address, port, "DoT server", Self::handle_connection)
            .await
    }

    async fn handle_connection(
        stream: TcpStream,
        client_addr: SocketAddr,
        dns_server: Arc<RwLock<Option<DnsServer>>>,
        acceptor: Arc<TlsAcceptor>,
    ) -> Result<(), String> {
        let tls_stream = tokio::time::timeout(
            std::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
            acceptor.accept(stream),
        )
        .await
        .map_err(|_| "TLS handshake timeout")?
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

        let mut tls_stream = tls_stream;

        loop {
            let client_ip = client_addr.ip();

            let mut length_buf = [0u8; 2];
            match tls_stream.read_exact(&mut length_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(format!("Failed to read length prefix: {}", e));
                }
            };

            let length = u16::from_be_bytes(length_buf) as usize;

            if length > DOT_MAX_QUERY_SIZE || length == 0 {
                return Err(format!("Invalid query length: {}", length));
            }

            let mut query_buf = vec![0u8; length];
            tls_stream
                .read_exact(&mut query_buf)
                .await
                .map_err(|e| format!("Failed to read query: {}", e))?;

            let (zones, zone_trie, cache, ecs_config, acme_dns_challenges) = {
                let dns_server_guard = dns_server.read();
                let server = match dns_server_guard.as_ref() {
                    Some(s) => s,
                    None => {
                        return Err("DNS server not configured".to_string());
                    }
                };

                (
                    server.get_zones(),
                    server.get_zone_trie(),
                    server.get_cache(),
                    server.get_ecs_filter_config(),
                    #[cfg(feature = "dns")]
                    server.acme_dns_challenges.clone(),
                    #[cfg(not(feature = "dns"))]
                    None,
                )
            };

            let ctx = crate::dns::server::QueryContext {
                zones: &zones,
                zone_trie: &zone_trie,
                #[cfg(feature = "mesh")]
                mesh_registry: None,
                geoip_lookup: None,
                min_geo_ttl: 60,
                negative_cache_ttl: 300,
                cache: cache.as_ref(),
                dnssec: None,
                signer_name: None,
                query_validator: None,
                firewall: None,
                connection_limits: None,
                max_idle_time: None,
                zone_transfer: None,
                ecs_filter_config: &ecs_config,
                rate_limiter: None,
                rrl_enabled: false,
                update_handler: None,
                notify_handler: None,
                query_coalescer: None,
                dns64_translator: None,
                #[cfg(feature = "dns")]
                acme_dns_challenges: acme_dns_challenges.as_ref(),
            };

            let response = if let Some(c) = &ctx.cache {
                let cache_key = CacheKey::new(String::new(), RecordType::NULL, Some(client_ip));
                DnsServer::handle_query_with_cache(&ctx, &query_buf, c, cache_key, Some(client_ip))
            } else {
                DnsServer::handle_query(&ctx, &query_buf, Some(client_ip))
            };

            match response {
                Some(resp) => {
                    let response_len = resp.len() as u16;
                    tls_stream
                        .write_all(&response_len.to_be_bytes())
                        .await
                        .map_err(|e| format!("Failed to send response length: {}", e))?;
                    tls_stream
                        .write_all(&resp)
                        .await
                        .map_err(|e| format!("Failed to send response: {}", e))?;
                }
                None => {
                    let empty_response: Vec<u8> = vec![0; 2];
                    tls_stream
                        .write_all(&empty_response)
                        .await
                        .map_err(|e| format!("Failed to send empty response: {}", e))?;
                }
            }
        }
    }

    pub fn shutdown(&mut self) {
        self.base.shutdown();
    }
}

impl Clone for DotServer {
    fn clone(&self) -> Self {
        Self {
            base: self.base.clone(),
        }
    }
}
