use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct SocketOptionsBase {
    pub reuse_port: bool,
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
}

impl Default for SocketOptionsBase {
    fn default() -> Self {
        Self {
            reuse_port: true,
            send_buffer_size: 262144,
            recv_buffer_size: 262144,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ListenerConfigBase {
    pub port: u16,
    pub bind_address: String,
    pub bind_address_v6: Option<String>,
    pub expected_protocol: String,
    pub upstream_address: String,
    pub upstream_address_v6: Option<String>,
    pub filter_enabled: bool,
    pub strict_mode: bool,
}

impl Default for ListenerConfigBase {
    fn default() -> Self {
        Self {
            port: 0,
            bind_address: "0.0.0.0".to_string(),
            bind_address_v6: None,
            expected_protocol: "unknown".to_string(),
            upstream_address: "127.0.0.1:0".to_string(),
            upstream_address_v6: None,
            filter_enabled: true,
            strict_mode: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ListenerInstance<C> {
    pub config: C,
    pub listen_addr: SocketAddr,
}

impl<C> ListenerInstance<C> {
    pub fn new(config: C, listen_addr: SocketAddr) -> Self {
        Self {
            config,
            listen_addr,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionContext {
    pub client_ip: std::net::IpAddr,
    pub server_name: String,
    pub port: u16,
    pub expected_protocol: String,
}

impl ConnectionContext {
    pub fn new(
        client_ip: std::net::IpAddr,
        server_name: String,
        port: u16,
        expected_protocol: String,
    ) -> Self {
        Self {
            client_ip,
            server_name,
            port,
            expected_protocol,
        }
    }
}
