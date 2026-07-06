use std::net::SocketAddr;
use std::sync::Arc;

use metrics::{counter, gauge, histogram};
use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::secure_server::{
    DnsServerConfig, SecureDnsServerBase, MAX_QUERY_SIZE, TLS_HANDSHAKE_TIMEOUT_SECS,
};
use crate::server::DnsServer;
use synvoid_config::dns::DnsDotConfig;
use synvoid_tls::cert_resolver::CertResolver;

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
        tracing::info!(bind_address = %bind_address, port = %port, "DoT server starting");
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
        .map_err(|e| {
            tracing::warn!(error = %e, remote_addr = %client_addr, "DoT TLS handshake failed");
            format!("TLS handshake failed: {}", e)
        })?;

        let mut tls_stream = tls_stream;

        tracing::debug!(remote_addr = %client_addr, "DoT connection accepted");

        counter!("synvoid.dot.connections.total").increment(1);
        gauge!("synvoid.dot.connections").increment(1.0);

        let result: Result<(), String> = loop {
            let client_ip = client_addr.ip();

            let mut length_buf = [0u8; 2];
            match tls_stream.read_exact(&mut length_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    tracing::debug!(remote_addr = %client_addr, "DoT connection closed by client");
                    break Ok(());
                }
                Err(e) => {
                    break Err(format!("Failed to read length prefix: {}", e));
                }
            };

            let length = u16::from_be_bytes(length_buf) as usize;

            if length > DOT_MAX_QUERY_SIZE || length == 0 {
                break Err(format!("Invalid query length: {}", length));
            }

            let mut query_buf = vec![0u8; length];
            if let Err(e) = tls_stream.read_exact(&mut query_buf).await {
                break Err(format!("Failed to read query: {}", e));
            }

            counter!("synvoid.dot.queries.total").increment(1);

            let query_start = std::time::Instant::now();
            let response = {
                let dns_server_guard = dns_server.read();
                let server = match dns_server_guard.as_ref() {
                    Some(s) => s,
                    None => {
                        counter!("synvoid.dot.query.errors").increment(1);
                        break Err("DNS server not configured".to_string());
                    }
                };

                let ctx = server.query_context();
                if let Some(c) = &ctx.cache {
                    DnsServer::handle_query_with_cache(
                        &ctx,
                        &query_buf,
                        c,
                        crate::cache::TransportClass::Tcp,
                        Some(client_ip),
                    )
                } else {
                    DnsServer::handle_query(&ctx, &query_buf, Some(client_ip))
                }
            };

            match response {
                Some(resp) => {
                    let response_len = resp.len() as u16;
                    if let Err(e) = tls_stream.write_all(&response_len.to_be_bytes()).await {
                        break Err(format!("Failed to send response length: {}", e));
                    }
                    if let Err(e) = tls_stream.write_all(&resp).await {
                        break Err(format!("Failed to send response: {}", e));
                    }
                    histogram!("synvoid.dot.query.duration")
                        .record(query_start.elapsed().as_secs_f64());
                    tracing::debug!(remote_addr = %client_addr, "DoT query processed");
                }
                None => {
                    counter!("synvoid.dot.query.errors").increment(1);
                    let empty_response: Vec<u8> = vec![0; 2];
                    if let Err(e) = tls_stream.write_all(&empty_response).await {
                        break Err(format!("Failed to send empty response: {}", e));
                    }
                }
            }
        };

        gauge!("synvoid.dot.connections").decrement(1.0);

        result
    }

    pub fn shutdown(&mut self) {
        tracing::info!("DoT server shutting down");
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
