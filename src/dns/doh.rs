use std::net::SocketAddr;
use std::sync::Arc;

use http::StatusCode;
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::RwLock;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};

use crate::config::dns::DnsDohConfig;
use crate::dns::server::{DnsServer, RecordType};
use crate::dns::cache::CacheKey;
use crate::tls::cert_resolver::CertResolver;

const DOH_MAX_QUERY_SIZE: usize = 65535;

pub struct DohServer {
    config: Arc<DnsDohConfig>,
    cert_resolver: Option<Arc<CertResolver>>,
    dns_server: Arc<RwLock<Option<DnsServer>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl DohServer {
    pub fn new(config: DnsDohConfig, cert_resolver: Option<Arc<CertResolver>>) -> Self {
        Self {
            config: Arc::new(config),
            cert_resolver,
            dns_server: Arc::new(RwLock::new(None)),
            shutdown_tx: None,
        }
    }

    pub fn set_dns_server(&self, server: DnsServer) {
        *self.dns_server.write() = Some(server);
    }

    pub async fn start(&mut self) -> Result<(), String> {
        let bind_addr = format!("{}:{}", self.config.bind_address, self.config.port)
            .parse::<SocketAddr>()
            .map_err(|e| format!("Invalid DoH bind address: {}", e))?;

        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind DoH socket: {}", e))?;

        tracing::info!("DoH server listening on {} (HTTP/2)", bind_addr);

        let acceptor = self.create_tls_acceptor()?;

        let dns_server = self.dns_server.clone();
        let config = self.config.clone();

        let (tx, rx) = oneshot::channel::<()>();
        self.shutdown_tx = Some(tx);

        tokio::spawn(async move {
            Self::accept_loop(listener, dns_server, config, acceptor, rx).await;
        });

        Ok(())
    }

    fn create_tls_acceptor(&self) -> Result<TlsAcceptor, String> {
        if let Some(ref resolver) = self.cert_resolver {
            let server_config = resolver.build_server_config()
                .map_err(|e| format!("Failed to build TLS config: {}", e))?;
            Ok(TlsAcceptor::from(server_config))
        } else {
            Err("No TLS certificate resolver available".to_string())
        }
    }

    async fn accept_loop(
        listener: TcpListener,
        dns_server: Arc<RwLock<Option<DnsServer>>>,
        config: Arc<DnsDohConfig>,
        acceptor: TlsAcceptor,
        shutdown_rx: oneshot::Receiver<()>,
    ) {
        let acceptor = Arc::new(acceptor);
        
        tokio::select! {
            _ = shutdown_rx => {
                tracing::info!("DoH server shutting down");
            }
            _ = async {
                loop {
                    match listener.accept().await {
                        Ok((stream, client_addr)) => {
                            let dns_server = dns_server.clone();
                            let acceptor = acceptor.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, client_addr, dns_server, acceptor).await {
                                    tracing::debug!("DoH connection error from {}: {}", client_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("DoH accept error: {}", e);
                        }
                    }
                }
            } => {}
        }
    }

    async fn handle_connection(
        stream: tokio::net::TcpStream,
        client_addr: SocketAddr,
        dns_server: Arc<RwLock<Option<DnsServer>>>,
        acceptor: Arc<TlsAcceptor>,
    ) -> Result<(), String> {
        use std::time::Duration;

        let tls_stream = tokio::time::timeout(
            Duration::from_secs(10),
            acceptor.accept(stream),
        )
        .await
        .map_err(|_| "TLS handshake timeout")?
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

        let io = TokioIo::new(tls_stream);

        let dns_server_clone = dns_server.clone();

        let mut builder = http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        
        builder.serve_connection(
            io,
            service_fn(move |req| {
                let dns_server = dns_server_clone.clone();
                let client_ip = client_addr.ip();
                async move {
                    Self::handle_request(req, dns_server, client_ip).await
                }
            }),
        ).await.map_err(|e| format!("DoH HTTP/2 error: {}", e))?;

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
                .unwrap());
        }

        if req.method() != hyper::Method::GET && req.method() != hyper::Method::POST {
            return Ok(hyper::Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }

        let dns_query = if *req.method() == hyper::Method::POST {
            let body = match req.collect().await {
                Ok(b) => b.to_bytes(),
                Err(_e) => {
                    return Ok(hyper::Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from("Failed to read request body")))
                        .unwrap());
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
                            .unwrap());
                        }
                    }
                } else {
                    return Ok(hyper::Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from("Missing dns parameter")))
                        .unwrap());
                }
            } else {
                return Ok(hyper::Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Missing dns parameter")))
                    .unwrap());
            }
        };

        if dns_query.len() > DOH_MAX_QUERY_SIZE {
            return Ok(hyper::Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }

        let dns_server_guard = dns_server.read();
        let server = match dns_server_guard.as_ref() {
            Some(s) => s,
            None => {
                return Ok(hyper::Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
        };

        let zones = server.get_zones();
        let zone_trie = server.get_zone_trie();
        let zone_index = server.get_zone_index();
        let cache = server.get_cache();
        let dnssec = server.get_dnssec();
        let signer_name = server.get_signer_name();
        let ecs_config = server.get_ecs_filter_config();

        let response = if let Some(ref c) = cache {
            let cache_key = CacheKey::new(String::new(), RecordType::NULL, Some(client_ip));
            DnsServer::handle_query_with_cache(
                &zones,
                &zone_trie,
                &dns_query,
                None,
                None,
                60,
                c,
                cache_key,
                dnssec.as_ref(),
                signer_name.as_ref(),
                Some(client_ip),
                None,
                &ecs_config,
                None,
                None,
            )
        } else {
            DnsServer::handle_query(
                &zones,
                &zone_trie,
                &dns_query,
                None,
                None,
                60,
                Some(client_ip),
                &ecs_config,
                None,
                None,
            )
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
                        .unwrap())
                } else {
                    Ok(hyper::Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/dns-message")
                        .body(Full::new(Bytes::from(resp.as_ref().clone())))
                        .unwrap())
                }
            }
            None => {
                Ok(hyper::Response::builder()
                    .status(500)
                    .body(Full::new(Bytes::new()))
                    .unwrap())
            }
        }
    }

    fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let padded = if input.len() % 4 != 0 {
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
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Clone for DohServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cert_resolver: self.cert_resolver.clone(),
            dns_server: self.dns_server.clone(),
            shutdown_tx: None,
        }
    }
}
