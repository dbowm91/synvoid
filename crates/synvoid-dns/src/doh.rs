use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::RwLock;
use tokio_rustls::TlsAcceptor;

use crate::cache::CacheKey;
use crate::secure_server::{
    DnsServerConfig, SecureDnsServerBase, MAX_QUERY_SIZE, TLS_HANDSHAKE_TIMEOUT_SECS,
};
use crate::server::{DnsServer, RecordType};
use synvoid_config::dns::DnsDohConfig;
use synvoid_tls::cert_resolver::CertResolver;

pub const DOH_MAX_QUERY_SIZE: usize = MAX_QUERY_SIZE;

impl DnsServerConfig for DnsDohConfig {
    fn bind_address(&self) -> &str {
        &self.bind_address
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn server_name(&self) -> &'static str {
        "DoH"
    }
}

pub struct DohServer {
    base: SecureDnsServerBase<DnsDohConfig>,
}

impl DohServer {
    pub fn new(config: DnsDohConfig, cert_resolver: Option<Arc<CertResolver>>) -> Self {
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
            .start_server(&bind_address, port, "DoH server", Self::handle_connection)
            .await
    }

    async fn handle_connection(
        stream: tokio::net::TcpStream,
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

        let io = TokioIo::new(tls_stream);

        let dns_server_clone = dns_server.clone();

        let builder = http2::Builder::new(hyper_util::rt::TokioExecutor::new());

        builder
            .serve_connection(
                io,
                service_fn(move |req| {
                    let dns_server = dns_server_clone.clone();
                    let client_ip = client_addr.ip();
                    async move { Self::handle_request(req, dns_server, client_ip).await }
                }),
            )
            .await
            .map_err(|e| format!("DoH HTTP/2 error: {}", e))?;

        Ok(())
    }

    async fn handle_request(
        req: hyper::Request<Incoming>,
        dns_server: Arc<RwLock<Option<DnsServer>>>,
        client_ip: std::net::IpAddr,
    ) -> Result<hyper::Response<Full<Bytes>>, hyper::Error> {
        let path = req.uri().path();
        let is_json_api = path == "/dns" || path == "/dns-query/json";
        let is_rfc8484 = path == "/dns-query" || path == "/";

        if !is_json_api && !is_rfc8484 {
            return Ok(hyper::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::new()))
                .expect("response builder should not fail"));
        }

        if req.method() != hyper::Method::GET && req.method() != hyper::Method::POST {
            return Ok(hyper::Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::new()))
                .expect("response builder should not fail"));
        }

        let dns_query = if *req.method() == hyper::Method::POST {
            let body = match req.collect().await {
                Ok(b) => b.to_bytes(),
                Err(_e) => {
                    return Ok(hyper::Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from("Failed to read request body")))
                        .expect("response builder should not fail"));
                }
            };
            body.to_vec()
        } else {
            let uri = req.uri();
            if let Some(query) = uri.query() {
                if let Some(dns_param) = query.strip_prefix("dns=") {
                    match Self::base64url_decode(dns_param) {
                        Ok(data) => data,
                        Err(_) => {
                            return Ok(hyper::Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Full::new(Bytes::from("Invalid base64url encoding")))
                                .expect("response builder should not fail"));
                        }
                    }
                } else {
                    return Ok(hyper::Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from("Missing dns parameter")))
                        .expect("response builder should not fail"));
                }
            } else {
                return Ok(hyper::Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Missing dns parameter")))
                    .expect("response builder should not fail"));
            }
        };

        if dns_query.len() > DOH_MAX_QUERY_SIZE {
            return Ok(hyper::Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Full::new(Bytes::new()))
                .expect("response builder should not fail"));
        }

        let (zones, zone_trie, cache, ecs_config, acme_dns_challenges) = {
            let dns_server_guard = dns_server.read();
            let server = dns_server_guard
                .as_ref()
                .expect("DNS server not configured");

            (
                server.get_zones(),
                server.get_zone_trie(),
                server.get_cache(),
                server.get_ecs_filter_config(),
                server.acme_dns_challenges.clone(),
            )
        };

        let ctx = crate::server::QueryContext {
            zones: &zones,
            zone_trie: &zone_trie,
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
            acme_dns_challenges: acme_dns_challenges.as_ref(),
            cookie_server: None,
        };

        let response = if let Some(c) = &ctx.cache {
            let cache_key = CacheKey::new(String::new(), RecordType::NULL, Some(client_ip));
            DnsServer::handle_query_with_cache(&ctx, &dns_query, c, cache_key, Some(client_ip))
        } else {
            DnsServer::handle_query(&ctx, &dns_query, Some(client_ip))
        };

        match response {
            Some(resp) => {
                if is_json_api {
                    let encoded = Self::base64url_encode(&resp);
                    let json = serde_json::json!({
                        "status": "success",
                        "answer": encoded
                    });
                    let body = serde_json::to_string(&json).unwrap_or_default();
                    Ok(hyper::Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(body)))
                        .expect("response builder should not fail"))
                } else {
                    Ok(hyper::Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/dns-message")
                        .body(Full::new(Bytes::from(resp.as_ref().clone())))
                        .expect("response builder should not fail"))
                }
            }
            None => Ok(hyper::Response::builder()
                .status(500)
                .body(Full::new(Bytes::new()))
                .expect("response builder should not fail")),
        }
    }

    fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let padded = if !input.len().is_multiple_of(4) {
            format!("{}{}", input, "=".repeat(4 - input.len() % 4))
        } else {
            input.to_string()
        };

        URL_SAFE_NO_PAD
            .decode(&padded)
            .map_err(|e| format!("Base64 decode error: {}", e))
    }

    fn base64url_encode(data: &[u8]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        URL_SAFE_NO_PAD.encode(data)
    }

    pub fn shutdown(&mut self) {
        self.base.shutdown();
    }
}

impl Clone for DohServer {
    fn clone(&self) -> Self {
        Self {
            base: self.base.clone(),
        }
    }
}
