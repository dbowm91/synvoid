use synvoid_config::protection::IpFeedConfig;
use synvoid_http_client::{create_simple_http_client, get_with_timeout, HttpClient};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFeedEntry {
    pub ip: String,
    pub source: String,
    pub added_at: u64,
}

#[derive(Clone, Debug)]
enum BlockedNetwork {
    Ipv4(Ipv4Addr, u8),
    Ipv6(Ipv6Addr, u8),
}

impl BlockedNetwork {
    fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (BlockedNetwork::Ipv4(net, prefix), IpAddr::V4(target)) => {
                let network = u32::from(*net);
                let target_bits = u32::from(*target);
                let mask = !((1u32 << (32 - *prefix)) - 1);
                (network & mask) == (target_bits & mask)
            }
            (BlockedNetwork::Ipv6(net, prefix), IpAddr::V6(target)) => {
                let network = net.octets();
                let target_bits = target.octets();
                let prefix_bytes = prefix / 8;
                let prefix_bits = prefix % 8;

                if network[..prefix_bytes as usize] != target_bits[..prefix_bytes as usize] {
                    return false;
                }

                if prefix_bits > 0 {
                    let mask = !(0xFF >> prefix_bits);
                    return (network[prefix_bytes as usize] & mask)
                        == (target_bits[prefix_bytes as usize] & mask);
                }

                true
            }
            _ => false,
        }
    }
}

pub struct IpFeedManager {
    blocked_networks: Arc<RwLock<Vec<BlockedNetwork>>>,
    blocked_ips: Arc<RwLock<HashSet<IpAddr>>>,
    config: IpFeedConfig,
    last_update: Arc<RwLock<u64>>,
    client: HttpClient,
}

impl IpFeedManager {
    pub fn new(config: IpFeedConfig) -> Arc<Self> {
        Self::with_url(config, String::new())
    }

    pub fn with_url(config: IpFeedConfig, url: String) -> Arc<Self> {
        let client = create_simple_http_client(Duration::from_secs(30));

        Arc::new(Self {
            blocked_networks: Arc::new(RwLock::new(Vec::new())),
            blocked_ips: Arc::new(RwLock::new(HashSet::new())),
            config: IpFeedConfig { url, ..config },
            last_update: Arc::new(RwLock::new(0)),
            client,
        })
    }

    pub fn start_background_fetching(self: &Arc<Self>) {
        let self_clone = Arc::clone(self);

        tokio::spawn(async move {
            loop {
                self_clone.fetch_and_update().await;

                let interval =
                    Duration::from_secs(self_clone.config.update_interval_hours as u64 * 3600);
                time::sleep(interval).await;
            }
        });
    }

    pub async fn fetch_and_update(&self) {
        tracing::info!("Fetching IP feed from {}", self.config.url);

        match self.fetch_feed(&self.config.url).await {
            Ok((networks, ips)) => {
                let trimmed_networks: Vec<BlockedNetwork> = networks
                    .into_iter()
                    .take(self.config.max_permanent_blocks / 256)
                    .collect();

                let trimmed_ips: HashSet<IpAddr> = ips
                    .into_iter()
                    .take(self.config.max_permanent_blocks)
                    .collect();

                let network_count = trimmed_networks.len();
                let ip_count = trimmed_ips.len();

                *self.blocked_networks.write() = trimmed_networks;
                *self.blocked_ips.write() = trimmed_ips;

                let now = synvoid_utils::safe_unix_timestamp();
                *self.last_update.write() = now;

                tracing::info!(
                    "IP feed updated: {} networks, {} IPs blocked (max: {})",
                    network_count,
                    ip_count,
                    self.config.max_permanent_blocks
                );
            }
            Err(e) => {
                tracing::error!("Failed to fetch IP feed: {}", e);
            }
        }
    }

    async fn fetch_feed(&self, url: &str) -> Result<(Vec<BlockedNetwork>, Vec<IpAddr>), String> {
        let response = get_with_timeout(&self.client, url, Duration::from_secs(30))
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !response.status.is_success() {
            return Err(format!("HTTP error: {}", response.status));
        }

        let body_str = String::from_utf8_lossy(&response.body);
        self.parse_feed(&body_str)
    }

    fn parse_feed(&self, content: &str) -> Result<(Vec<BlockedNetwork>, Vec<IpAddr>), String> {
        let mut networks = Vec::new();
        let mut ips = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let ip_or_cidr = if line.contains('#') {
                line.split('#').next().unwrap_or("").trim()
            } else {
                line
            };

            if ip_or_cidr.contains('/') {
                if let Some(network) = self.parse_cidr(ip_or_cidr) {
                    networks.push(network);
                }
            } else if let Ok(addr) = ip_or_cidr.parse::<IpAddr>() {
                ips.push(addr);
            }
        }

        Ok((networks, ips))
    }

    fn parse_cidr(&self, cidr: &str) -> Option<BlockedNetwork> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip_str = parts[0];
        let prefix: u8 = parts[1].parse().ok()?;

        if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
            if prefix <= 32 {
                return Some(BlockedNetwork::Ipv4(ipv4, prefix));
            }
        } else if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
            if prefix <= 128 {
                return Some(BlockedNetwork::Ipv6(ipv6, prefix));
            }
        }

        None
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        let networks = self.blocked_networks.read();
        for network in networks.iter() {
            if network.contains(ip) {
                return true;
            }
        }

        let ips = self.blocked_ips.read();
        ips.contains(ip)
    }

    pub fn get_count(&self) -> usize {
        self.blocked_networks.read().len() + self.blocked_ips.read().len()
    }

    pub fn get_last_update(&self) -> u64 {
        *self.last_update.read()
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

pub struct MultiFeedManager {
    feeds: Vec<Arc<IpFeedManager>>,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    config: IpFeedConfig,
}

impl MultiFeedManager {
    pub fn new(config: IpFeedConfig) -> Arc<Self> {
        let urls = vec![
            "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt".to_string(),
            "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-ipv4.txt".to_string(),
            "https://raw.githubusercontent.com/borestad/firehol-mirror/main/firehol level1.netset".to_string(),
            "https://raw.githubusercontent.com/stamparm/ipsum/main/ipsum.txt".to_string(),
            "https://raw.githubusercontent.com/ShadowWhisperer/IPs/main/BlockList/IPsV4.txt".to_string(),
            "https://www.spamhaus.org/drop/drop.txt".to_string(),
        ];

        let feeds: Vec<Arc<IpFeedManager>> = urls
            .into_iter()
            .map(|url| IpFeedManager::with_url(config.clone(), url))
            .collect();

        Arc::new(Self { feeds, config })
    }

    pub fn start_all(&self) {
        for feed in &self.feeds {
            if feed.is_enabled() {
                feed.start_background_fetching();
            }
        }
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        for feed in &self.feeds {
            if feed.is_blocked(ip) {
                return true;
            }
        }
        false
    }

    pub fn get_total_count(&self) -> usize {
        self.feeds.iter().map(|f| f.get_count()).sum()
    }

    pub async fn fetch_all(&self) {
        for feed in &self.feeds {
            if feed.is_enabled() {
                feed.fetch_and_update().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_blocked_network_ipv4_contains() {
        use std::net::{IpAddr, Ipv4Addr};

        fn test_contains(network: &super::BlockedNetwork, ip: IpAddr, expected: bool) {
            assert_eq!(network.contains(&ip), expected);
        }

        let network = super::BlockedNetwork::Ipv4(Ipv4Addr::new(192, 168, 1, 0), 24);

        test_contains(&network, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), true);
        test_contains(&network, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), true);
        test_contains(&network, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)), true);
        test_contains(&network, IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), false);
    }

    #[test]
    fn test_blocked_network_ipv6_contains() {
        use std::net::{IpAddr, Ipv6Addr};

        let network =
            super::BlockedNetwork::Ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32);

        assert!(network.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0))));
        assert!(network.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))));
        assert!(!network.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db9, 0, 0, 0, 0, 0, 0))));
    }
}
