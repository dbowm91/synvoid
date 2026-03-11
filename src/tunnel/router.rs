use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc};
use metrics::{gauge, counter};

use crate::config::main::TunnelConfig;
use crate::tunnel::quic::{QuicRuntime, QuicTunnelServer, QuicTunnelClient, QuicConnection, QUIC_TUNNEL_REGISTRY};

pub struct TunnelRouter {
    config: TunnelConfig,
    sessions: Arc<DashMap<String, TunnelRouteSession>>,
    quic_runtime: Option<Arc<QuicRuntime>>,
    quic_server: Option<QuicTunnelServer>,
    quic_client: Option<QuicTunnelClient>,
    shutdown_tx: broadcast::Sender<()>,
    dedicated_worker_handle: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Clone)]
pub struct TunnelRouteSession {
    pub id: String,
    pub peer_id: String,
    pub remote_addr: String,
    pub session_type: TunnelSessionType,
    pub connected_at: std::time::Instant,
    pub mappings: HashMap<String, TunnelMapping>,
}

#[derive(Clone)]
pub enum TunnelSessionType {
    Server,
    Client,
    Peer,
}

#[derive(Clone)]
pub struct TunnelMapping {
    pub identifier: String,
    pub port: u16,
    pub protocol: String,
    pub upstream_host: Option<String>,
    pub upstream_port: Option<u16>,
}

impl TunnelRouter {
    pub fn new(config: TunnelConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (shutdown_tx, _) = broadcast::channel(1);
        
        let quic_runtime = if config.quic.enabled {
            let runtime = QuicRuntime::new(config.quic.clone())?
                .with_timeouts(config.quic.max_idle_timeout_secs, config.quic.keepalive_interval_secs)
                .with_stream_limits(config.quic.max_concurrent_streams, config.quic.max_stream_buffer_size);
            Some(Arc::new(runtime))
        } else {
            None
        };

        Ok(Self {
            config,
            sessions: Arc::new(DashMap::new()),
            quic_runtime,
            quic_server: None,
            quic_client: None,
            shutdown_tx,
            dedicated_worker_handle: None,
        })
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref runtime) = self.quic_runtime {
            QUIC_TUNNEL_REGISTRY.set_runtime(runtime.clone()).await;
            
            let dedicated_worker = self.config.quic.dedicated_worker;

            if dedicated_worker {
                tracing::info!("QUIC tunnel using dedicated worker thread");
                self.start_dedicated_worker(runtime.clone()).await?;
            } else {
                tracing::info!("QUIC tunnel using shared worker pool");
                self.start_embedded(runtime.clone()).await?;
            }

            gauge!("rustwaf.tunnel.quic.enabled").set(1.0);
            tracing::info!("QUIC tunnel router started (dedicated_worker={})", dedicated_worker);
        } else {
            tracing::info!("QUIC tunnel disabled");
        }

        Ok(())
    }

    async fn start_dedicated_worker(
        &mut self,
        runtime: Arc<QuicRuntime>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = self.config.clone();
        let sessions = self.sessions.clone();

        let handle = tokio::spawn(async move {
            if config.quic.server.enabled {
                match runtime.start_server().await {
                    Ok(mut connection_rx) => {
                        tracing::info!("QUIC server started, listening for connections");
                        
                        loop {
                            tokio::select! {
                                Some(connection) = connection_rx.recv() => {
                                    tracing::info!("New QUIC connection from: {}", 
                                        connection.remote_addr);
                                    
                                    counter!("rustwaf.tunnel.quic.connections").increment(1);
                                    
                                    let runtime_clone = runtime.clone();
                                    let sessions_clone = sessions.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = Self::handle_raw_connection(
                                            connection,
                                            runtime_clone,
                                            sessions_clone,
                                        ).await {
                                            tracing::debug!("Connection handler error: {}", e);
                                        }
                                    });
                                }
                                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                                    tracing::debug!("QUIC tunnel heartbeat");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("QUIC server failed to start: {}", e);
                    }
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            tracing::info!("Dedicated QUIC worker shutting down");
        });

        self.dedicated_worker_handle = Some(handle);
        
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        
        Ok(())
    }

    async fn handle_raw_connection(
        connection: crate::tunnel::quic::runtime::IncomingConnection,
        runtime: Arc<QuicRuntime>,
        sessions: Arc<DashMap<String, TunnelRouteSession>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = TunnelRouteSession {
            id: session_id.clone(),
            peer_id: String::new(),
            remote_addr: connection.remote_addr.to_string(),
            session_type: TunnelSessionType::Server,
            connected_at: std::time::Instant::now(),
            mappings: HashMap::new(),
        };
        
        sessions.insert(session_id.clone(), session);
        counter!("rustwaf.tunnel.quic.sessions").increment(1);
        
        Ok(())
    }

    async fn start_embedded(
        &mut self,
        runtime: Arc<QuicRuntime>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (proxy_tx, mut proxy_rx) = mpsc::channel::<crate::tunnel::quic::TunnelProxyRequest>(100);
        
        let mut server = QuicTunnelServer::new(
            self.config.quic.clone(),
            runtime.clone(),
            proxy_tx,
        );
        server.start().await?;
        self.quic_server = Some(server);

        let mut client = QuicTunnelClient::new(
            self.config.quic.clone(),
            runtime.clone(),
        );
        client.start().await?;
        self.quic_client = Some(client);

        let sessions = self.sessions.clone();
        tokio::spawn(async move {
            while let Some(req) = proxy_rx.recv().await {
                tracing::debug!("Proxy request for session {}: {}:{}",
                    req.session_id, req.identifier, req.port);
                
                let session = TunnelRouteSession {
                    id: req.session_id.clone(),
                    peer_id: String::new(),
                    remote_addr: String::new(),
                    session_type: TunnelSessionType::Server,
                    connected_at: std::time::Instant::now(),
                    mappings: [(
                        req.identifier.clone(),
                        TunnelMapping {
                            identifier: req.identifier.clone(),
                            port: req.port,
                            protocol: "tcp".to_string(),
                            upstream_host: Some("127.0.0.1".to_string()),
                            upstream_port: Some(req.port),
                        }
                    )].into_iter().collect(),
                };
                
                sessions.insert(req.session_id, session);
                
                let _ = req.response_tx.send(Ok(req.data)).await;
            }
        });

        Ok(())
    }

    pub async fn resolve_tunnel_backend(&self, identifier: &str) -> Option<TunnelBackend> {
        if let Some(ref client) = self.quic_client {
            if let Some((host, port)) = client.resolve_upstream(identifier).await {
                return Some(TunnelBackend::Direct { host, port });
            }
        }

        for session in self.sessions.iter() {
            if let Some(mapping) = session.mappings.get(identifier) {
                return Some(TunnelBackend::Direct {
                    host: mapping.upstream_host.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
                    port: mapping.upstream_port.unwrap_or(mapping.port),
                });
            }
        }

        None
    }

    pub async fn list_sessions(&self) -> Vec<TunnelRouteSession> {
        self.sessions.iter().map(|s| s.clone()).collect()
    }

    pub fn is_quic_enabled(&self) -> bool {
        self.quic_runtime.is_some()
    }

    pub fn is_dedicated_worker(&self) -> bool {
        self.dedicated_worker_handle.is_some()
    }

    pub fn quic_runtime(&self) -> Option<&Arc<QuicRuntime>> {
        self.quic_runtime.as_ref()
    }

    pub fn shutdown(&self) {
        if let Some(ref server) = self.quic_server {
            server.shutdown();
        }
        if let Some(ref client) = self.quic_client {
            client.shutdown();
        }
        let _ = self.shutdown_tx.send(());
    }
}

#[derive(Clone)]
pub enum TunnelBackend {
    Direct { host: String, port: u16 },
    Tunnel { session_id: String, identifier: String },
}

impl TunnelBackend {
    pub fn to_upstream_string(&self) -> String {
        match self {
            TunnelBackend::Direct { host, port } => format!("{}:{}", host, port),
            TunnelBackend::Tunnel { .. } => String::new(),
        }
    }
}
