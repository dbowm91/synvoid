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
