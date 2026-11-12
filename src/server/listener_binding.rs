//! Process-wide HTTP/HTTPS/HTTP3 listener binding.
//!
//! Binding happens before worker readiness. Every configured listener is
//! claimed here as one transaction: if any socket cannot be bound, the
//! already-bound sockets are dropped and startup fails instead of serving a
//! partial listener set.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::{Arc, LazyLock, RwLock};

use synvoid_config::HttpListenerPlan;

#[derive(Debug, thiserror::Error)]
pub enum HttpListenerBindError {
    #[error("listener '{id}' ({addr}) TCP bind failed: {source}")]
    Tcp {
        id: String,
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("listener '{id}' ({addr}) UDP bind failed: {source}")]
    Udp {
        id: String,
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("listener '{id}' ({addr}) could not be made non-blocking: {source}")]
    NonBlocking {
        id: String,
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("listener '{id}' ({addr}) clone failed: {source}")]
    Clone {
        id: String,
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// A validated plan plus the sockets it actually owns.
pub struct BoundHttpListener {
    pub plan: HttpListenerPlan,
    pub tcp: Option<TcpListener>,
    pub udp: Option<UdpSocket>,
}

impl std::fmt::Debug for BoundHttpListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundHttpListener")
            .field("plan", &self.plan)
            .field("tcp", &self.tcp.is_some())
            .field("udp", &self.udp.is_some())
            .finish()
    }
}

impl BoundHttpListener {
    pub fn try_clone(&self) -> Result<Self, HttpListenerBindError> {
        let tcp = self
            .tcp
            .as_ref()
            .map(TcpListener::try_clone)
            .transpose()
            .map_err(|source| HttpListenerBindError::Clone {
                id: self.plan.name().to_string(),
                addr: self.plan.addr,
                source,
            })?;
        let udp = self
            .udp
            .as_ref()
            .map(UdpSocket::try_clone)
            .transpose()
            .map_err(|source| HttpListenerBindError::Clone {
                id: self.plan.name().to_string(),
                addr: self.plan.addr,
                source,
            })?;
        Ok(Self {
            plan: self.plan.clone(),
            tcp,
            udp,
        })
    }

    pub fn configured_addr(&self) -> SocketAddr {
        self.plan.addr
    }

    pub fn tcp_bound_addr(&self) -> Option<SocketAddr> {
        self.tcp.as_ref().and_then(|l| l.local_addr().ok())
    }

    pub fn udp_bound_addr(&self) -> Option<SocketAddr> {
        self.udp.as_ref().and_then(|s| s.local_addr().ok())
    }
}

#[derive(Debug, Clone)]
pub struct HttpListenerSnapshot {
    pub id: String,
    pub transport: String,
    pub configured_addr: String,
    pub bound_addr: Option<String>,
    pub tls: bool,
    pub http2: bool,
    pub http3: bool,
    pub default_site: Option<String>,
    pub site_count: usize,
    pub state: String,
    pub active_connections: usize,
}

static LISTENER_SNAPSHOTS: LazyLock<RwLock<Vec<HttpListenerSnapshot>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));

pub fn http_listener_snapshots() -> Vec<HttpListenerSnapshot> {
    LISTENER_SNAPSHOTS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn publish_snapshots(listeners: &[BoundHttpListener], state: &str) {
    let snapshots = listeners
        .iter()
        .map(|listener| {
            let bound = listener
                .tcp_bound_addr()
                .or_else(|| listener.udp_bound_addr())
                .map(|addr| addr.to_string());
            HttpListenerSnapshot {
                id: listener.plan.id.to_string(),
                transport: listener.plan.transport().to_string(),
                configured_addr: listener.plan.addr.to_string(),
                bound_addr: bound,
                tls: listener.plan.tls,
                http2: listener.plan.http2,
                http3: listener.plan.http3,
                default_site: listener.plan.default_site.clone(),
                site_count: listener.plan.site_ids.len(),
                state: state.to_string(),
                active_connections: 0,
            }
        })
        .collect();
    *LISTENER_SNAPSHOTS
        .write()
        .unwrap_or_else(|e| e.into_inner()) = snapshots;
}

/// Bind every planned listener, all-or-nothing.
pub fn bind_http_listeners(
    plans: &[HttpListenerPlan],
    reuse_port: bool,
) -> Result<Arc<Vec<BoundHttpListener>>, HttpListenerBindError> {
    let mut bound = Vec::with_capacity(plans.len());
    for plan in plans {
        let tcp = if plan.tcp {
            let listener = if reuse_port {
                synvoid_platform::socket_bind::bind_tcp_reuse(plan.addr)
            } else {
                synvoid_platform::socket_bind::bind_tcp(plan.addr)
            }
            .map_err(|source| HttpListenerBindError::Tcp {
                id: plan.name().to_string(),
                addr: plan.addr,
                source,
            })?;
            listener.set_nonblocking(true).map_err(|source| {
                HttpListenerBindError::NonBlocking {
                    id: plan.name().to_string(),
                    addr: plan.addr,
                    source,
                }
            })?;
            Some(listener)
        } else {
            None
        };
        let udp = if plan.http3 {
            let socket = if reuse_port {
                synvoid_platform::socket_bind::bind_udp_reuse(plan.addr)
            } else {
                synvoid_platform::socket_bind::bind_udp(plan.addr)
            }
            .map_err(|source| HttpListenerBindError::Udp {
                id: plan.name().to_string(),
                addr: plan.addr,
                source,
            })?;
            socket
                .set_nonblocking(true)
                .map_err(|source| HttpListenerBindError::NonBlocking {
                    id: plan.name().to_string(),
                    addr: plan.addr,
                    source,
                })?;
            Some(socket)
        } else {
            None
        };
        let listener = BoundHttpListener {
            plan: plan.clone(),
            tcp,
            udp,
        };
        metrics::counter!(
            "synvoid.http.listener_bound_total",
            "listener" => plan.name().to_string(),
            "transport" => plan.transport()
        )
        .increment(1);
        tracing::info!(
            listener = %plan.id,
            transport = plan.transport(),
            configured = %plan.addr,
            bound_tcp = ?listener.tcp_bound_addr(),
            bound_udp = ?listener.udp_bound_addr(),
            tls = plan.tls,
            alpn = if plan.tls { if plan.http2 { "h2,http/1.1" } else { "http/1.1" } } else { "http/1.1" },
            http3 = plan.http3,
            default_site = ?plan.default_site,
            "HTTP listener bound"
        );
        bound.push(listener);
    }
    publish_snapshots(&bound, "bound");
    tracing::info!(count = bound.len(), "HTTP listener bind summary");
    Ok(Arc::new(bound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn plan(name: &str, port: u16, tls: bool, http3: bool) -> HttpListenerPlan {
        HttpListenerPlan {
            id: synvoid_config::ListenerId::new(name),
            tcp: true,
            addr: format!("127.0.0.1:{port}").parse().unwrap(),
            tls,
            http2: tls,
            http3,
            ipv6_only: false,
            default_site: None,
            site_ids: Vec::new(),
        }
    }

    fn free_tcp_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn binds_multiple_listeners() {
        let plans = vec![
            plan("one", free_tcp_port(), false, false),
            plan("two", free_tcp_port(), false, false),
        ];
        let bound = bind_http_listeners(&plans, false).expect("bind all");
        assert_eq!(bound.len(), 2);
        assert!(bound.iter().all(|listener| listener.tcp.is_some()));
        assert!(bound.iter().all(|listener| listener.udp.is_none()));
    }

    #[test]
    fn binds_https_and_h3_same_numeric_port() {
        let port = free_tcp_port();
        let plans = vec![plan("both", port, true, true)];
        let bound = bind_http_listeners(&plans, false).expect("bind TCP and UDP");
        assert_eq!(bound.len(), 1);
        assert!(bound[0].tcp.is_some());
        assert!(bound[0].udp.is_some());
        assert_eq!(bound[0].tcp_bound_addr().unwrap().port(), port);
        assert_eq!(bound[0].udp_bound_addr().unwrap().port(), port);
    }

    #[test]
    fn bind_failure_releases_already_bound_sockets() {
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let free_port = free_tcp_port();
        let plans = vec![
            plan("free", free_port, false, false),
            plan("occupied", occupied_port, false, false),
        ];
        assert!(bind_http_listeners(&plans, false).is_err());
        drop(occupied);
        let rebind = TcpListener::bind(("127.0.0.1", free_port));
        assert!(rebind.is_ok(), "rollback must release the first socket");
    }
}
