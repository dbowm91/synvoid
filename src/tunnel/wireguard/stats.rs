use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeerStats {
    pub public_key: String,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<String>,
    pub latest_handshake: Option<u64>,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgInterfaceStats {
    pub name: String,
    pub public_key: String,
    pub listen_port: u16,
    pub fwmark: Option<u32>,
    pub peers: Vec<WgPeerStats>,
}

impl WgInterfaceStats {
    pub fn new(name: &str, public_key: &str, listen_port: u16) -> Self {
        Self {
            name: name.to_string(),
            public_key: public_key.to_string(),
            listen_port,
            fwmark: None,
            peers: Vec::new(),
        }
    }

    pub fn peer_by_public_key(&self, public_key: &str) -> Option<&WgPeerStats> {
        self.peers.iter().find(|p| p.public_key == public_key)
    }

    pub fn total_rx(&self) -> u64 {
        self.peers.iter().map(|p| p.transfer_rx).sum()
    }

    pub fn total_tx(&self) -> u64 {
        self.peers.iter().map(|p| p.transfer_tx).sum()
    }

    pub fn connected_peers(&self) -> usize {
        self.peers
            .iter()
            .filter(|p| p.latest_handshake.is_some_and(|h| h > 0))
            .count()
    }
}

#[cfg(target_os = "linux")]
pub fn parse_wg_show_output(output: &str) -> Result<Vec<WgInterfaceStats>, WgStatsError> {
    let mut interfaces = Vec::new();
    let mut current_interface: Option<WgInterfaceStats> = None;
    let mut current_peer: Option<WgPeerStats> = None;

    for line in output.lines() {
        let line = line.trim();
        
        if line.is_empty() {
            if let Some(peer) = current_peer.take() {
                if let Some(ref mut iface) = current_interface {
                    iface.peers.push(peer);
                }
            }
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0].trim();
        let value = parts[1].trim();

        match key.to_lowercase().as_str() {
            "interface" => {
                if let Some(peer) = current_peer.take() {
                    if let Some(ref mut iface) = current_interface {
                        iface.peers.push(peer);
                    }
                }
                if let Some(iface) = current_interface.take() {
                    interfaces.push(iface);
                }
                current_interface = Some(WgInterfaceStats::new(value, "", 0));
            }
            "public key" => {
                if current_peer.is_some() {
                    if let Some(ref mut iface) = current_interface {
                        if let Some(peer) = current_peer.take() {
                            iface.peers.push(peer);
                        }
                    }
                    current_peer = Some(WgPeerStats {
                        public_key: value.to_string(),
                        endpoint: None,
                        allowed_ips: Vec::new(),
                        latest_handshake: None,
                        transfer_rx: 0,
                        transfer_tx: 0,
                        persistent_keepalive: None,
                    });
                } else if let Some(ref mut iface) = current_interface {
                    iface.public_key = value.to_string();
                }
            }
            "listening port" => {
                if let Some(ref mut iface) = current_interface {
                    iface.listen_port = value.parse().unwrap_or(0);
                }
            }
            "fwmark" => {
                if let Some(ref mut iface) = current_interface {
                    iface.fwmark = value.parse().ok();
                }
            }
            "peer" => {
                if let Some(ref mut iface) = current_interface {
                    if let Some(peer) = current_peer.take() {
                        iface.peers.push(peer);
                    }
                }
                current_peer = Some(WgPeerStats {
                    public_key: value.to_string(),
                    endpoint: None,
                    allowed_ips: Vec::new(),
                    latest_handshake: None,
                    transfer_rx: 0,
                    transfer_tx: 0,
                    persistent_keepalive: None,
                });
            }
            "endpoint" => {
                if let Some(ref mut peer) = current_peer {
                    peer.endpoint = value.parse().ok();
                }
            }
            "allowed ips" => {
                if let Some(ref mut peer) = current_peer {
                    peer.allowed_ips = value.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
            "latest handshake" => {
                if let Some(ref mut peer) = current_peer {
                    peer.latest_handshake = parse_handshake_time(value);
                }
            }
            "transfer" => {
                if let Some(ref mut peer) = current_peer {
                    let parts: Vec<&str> = value.split(',').collect();
                    for part in parts {
                        let part = part.trim();
                        if part.ends_with(" received") || part.starts_with("received") {
                            let num: String = part
                                .chars()
                                .filter(|c| c.is_ascii_digit())
                                .collect();
                            peer.transfer_rx = num.parse().unwrap_or(0);
                        } else if part.ends_with(" sent") || part.starts_with("sent") {
                            let num: String = part
                                .chars()
                                .filter(|c| c.is_ascii_digit())
                                .collect();
                            peer.transfer_tx = num.parse().unwrap_or(0);
                        }
                    }
                }
            }
            "persistent keepalive" => {
                if let Some(ref mut peer) = current_peer {
                    let num: String = value
                        .chars()
                        .filter(|c| c.is_ascii_digit())
                        .collect();
                    peer.persistent_keepalive = num.parse().ok();
                }
            }
            _ => {}
        }
    }

    if let Some(peer) = current_peer {
        if let Some(ref mut iface) = current_interface {
            iface.peers.push(peer);
        }
    }
    if let Some(iface) = current_interface {
        interfaces.push(iface);
    }

    Ok(interfaces)
}

#[cfg(target_os = "linux")]
fn parse_handshake_time(value: &str) -> Option<u64> {
    let mut seconds = 0u64;
    let parts: Vec<&str> = value.split_whitespace().collect();
    
    for i in 0..parts.len() - 1 {
        let num: u64 = parts[i].parse().ok()?;
        let unit = parts[i + 1].to_lowercase();
        
        match unit.as_str() {
            "second" | "seconds" => seconds += num,
            "minute" | "minutes" => seconds += num * 60,
            "hour" | "hours" => seconds += num * 3600,
            "day" | "days" => seconds += num * 86400,
            _ => {}
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    
    Some(now.as_secs() - seconds)
}

#[derive(Debug, thiserror::Error)]
pub enum WgStatsError {
    #[error("Failed to execute wg command: {0}")]
    CommandError(String),
    #[error("Failed to parse wg output: {0}")]
    ParseError(String),
}

#[cfg(target_os = "linux")]
pub async fn get_interface_stats(interface: &str) -> Result<WgInterfaceStats, WgStatsError> {
    use tokio::process::Command;

    let output = Command::new("wg")
        .arg("show")
        .arg(interface)
        .output()
        .await
        .map_err(|e| WgStatsError::CommandError(e.to_string()))?;

    if !output.status.success() {
        return Err(WgStatsError::CommandError(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let interfaces = parse_wg_show_output(&stdout)?;
    
    interfaces
        .into_iter()
        .next()
        .ok_or_else(|| WgStatsError::ParseError("No interface found in output".to_string()))
}

#[cfg(target_os = "linux")]
pub async fn get_all_stats() -> Result<Vec<WgInterfaceStats>, WgStatsError> {
    use tokio::process::Command;

    let output = Command::new("wg")
        .arg("show")
        .arg("all")
        .output()
        .await
        .map_err(|e| WgStatsError::CommandError(e.to_string()))?;

    if !output.status.success() {
        return Err(WgStatsError::CommandError(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_wg_show_output(&stdout)
}

#[cfg(target_os = "linux")]
pub async fn get_peer_stats(interface: &str, public_key: &str) -> Result<Option<WgPeerStats>, WgStatsError> {
    let stats = get_interface_stats(interface).await?;
    Ok(stats.peer_by_public_key(public_key).cloned())
}

#[allow(dead_code)]
pub struct WgStatsCollector {
    interface: String,
    last_stats: Option<WgInterfaceStats>,
    last_update: Option<Instant>,
}

impl WgStatsCollector {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            last_stats: None,
            last_update: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub async fn refresh(&mut self) -> Result<&WgInterfaceStats, WgStatsError> {
        let stats = get_interface_stats(&self.interface).await?;
        self.last_stats = Some(stats);
        self.last_update = Some(Instant::now());
        Ok(self.last_stats.as_ref().unwrap())
    }

    pub fn stats(&self) -> Option<&WgInterfaceStats> {
        self.last_stats.as_ref()
    }

    pub fn last_update(&self) -> Option<Instant> {
        self.last_update
    }

    pub fn age(&self) -> Option<Duration> {
        self.last_update.map(|t| t.elapsed())
    }

    #[cfg(target_os = "linux")]
    pub fn rate_since_last(&self) -> Option<(u64, u64)> {
        let stats = self.last_stats.as_ref()?;
        let age = self.age()?;
        let secs = age.as_secs().max(1);
        
        let rx = stats.total_rx();
        let tx = stats.total_tx();
        
        Some((rx / secs, tx / secs))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wg_show_output() {
        let output = r#"
interface: wg0
  public key: ABC123
  private key: (hidden)
  listening port: 51820

peer: XYZ789
  endpoint: 1.2.3.4:51820
  allowed ips: 10.0.0.2/32
  latest handshake: 1 minute, 30 seconds ago
  transfer: 1.50 MiB received, 2.25 MiB sent
"#;

        let interfaces = parse_wg_show_output(output).unwrap();
        assert_eq!(interfaces.len(), 1);
        
        let iface = &interfaces[0];
        assert_eq!(iface.name, "wg0");
        assert_eq!(iface.public_key, "ABC123");
        assert_eq!(iface.listen_port, 51820);
        assert_eq!(iface.peers.len(), 1);
        
        let peer = &iface.peers[0];
        assert_eq!(peer.public_key, "XYZ789");
        assert!(peer.endpoint.is_some());
        assert_eq!(peer.allowed_ips.len(), 1);
        assert!(peer.latest_handshake.is_some());
    }
}
