use crate::config::main::IpFeedConfig;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFeedEntry {
    pub ip: String,
    pub source: String,
    pub added_at: u64,
}

pub struct IpFeedManager {
    blocked_ips: Arc<RwLock<HashSet<IpAddr>>>,
    config: IpFeedConfig,
    last_update: Arc<RwLock<u64>>,
    client: reqwest::Client,
}

impl IpFeedManager {
    pub fn new(config: IpFeedConfig) -> Arc<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("rustwaf-ip-denylist/1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Arc::new(Self {
            blocked_ips: Arc::new(RwLock::new(HashSet::new())),
            config,
            last_update: Arc::new(RwLock::new(0)),
            client,
        })
    }

    pub fn start_background_fetching(self: &Arc<Self>) {
        let self_clone = Arc::clone(self);
        
        tokio::spawn(async move {
            loop {
                self_clone.fetch_and_update().await;
                
                let interval = Duration::from_secs(self_clone.config.update_interval_hours as u64 * 3600);
                time::sleep(interval).await;
            }
        });
    }

    pub async fn fetch_and_update(&self) {
        tracing::info!("Fetching IP feed from {}", self.config.url);
        
        match self.fetch_feed(&self.config.url).await {
            Ok(ips) => {
                let trimmed: HashSet<IpAddr> = ips
                    .into_iter()
                    .take(self.config.max_permanent_blocks)
                    .collect();

                let count = trimmed.len();
                *self.blocked_ips.write() = trimmed;
                
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                *self.last_update.write() = now;

                tracing::info!("IP feed updated: {} IPs blocked (max: {})", count, self.config.max_permanent_blocks);
            }
            Err(e) => {
                tracing::error!("Failed to fetch IP feed: {}", e);
            }
        }
    }

    async fn fetch_feed(&self, url: &str) -> Result<Vec<IpAddr>, String> {
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("HTTP error: {}", response.status()));
        }

        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        self.parse_feed(&body)
    }

    fn parse_feed(&self, content: &str) -> Result<Vec<IpAddr>, String> {
        let mut ips = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let ip_or_cidr = if line.contains('#') {
                line.split('#').next().unwrap().trim()
            } else {
                line
            };

            let ip = if ip_or_cidr.contains('/') {
                if let Some(ip) = self.parse_cidr_first_ip(ip_or_cidr) {
                    ip
                } else {
                    continue;
                }
            } else {
                ip_or_cidr.to_string()
            };

            if let Ok(addr) = ip.parse::<IpAddr>() {
                ips.push(addr);
            }
        }

        Ok(ips)
    }

    fn parse_cidr_first_ip(&self, cidr: &str) -> Option<String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        
        let ip = parts[0].to_string();
        
        if ip.parse::<IpAddr>().is_ok() {
            Some(ip)
        } else {
            None
        }
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.read().contains(ip)
    }

    pub fn get_count(&self) -> usize {
        self.blocked_ips.read().len()
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
    config: IpFeedConfig,
}

impl MultiFeedManager {
    pub fn new(config: IpFeedConfig) -> Arc<Self> {
        let urls = vec![
            "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt".to_string(),
            "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-ipv4.txt".to_string(),
            "https://raw.githubusercontent.com/borestad/firehol-mirror/master/firehol level1.netset".to_string(),
            "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt".to_string(),
            "https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/BlockList/IPsV4.txt".to_string(),
            "https://www.spamhaus.org/drop/drop.txt".to_string(),
        ];

        let feeds: Vec<Arc<IpFeedManager>> = urls
            .into_iter()
            .map(|url| {
                let mut feed_config = config.clone();
                feed_config.url = url;
                IpFeedManager::new(feed_config)
            })
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
    use super::*;

    #[test]
    fn test_parse_cidr() {
        let manager = IpFeedManager::new(IpFeedConfig::default());
        
        assert_eq!(manager.parse_cidr_first_ip("192.168.1.0/24"), Some("192.168.1.0".to_string()));
        assert_eq!(manager.parse_cidr_first_ip("10.0.0.0/8"), Some("10.0.0.0".to_string()));
        assert_eq!(manager.parse_cidr_first_ip("invalid"), None);
    }

    #[test]
    fn test_parse_feed() {
        let manager = IpFeedManager::new(IpFeedConfig::default());
        
        let content = r#"
# Comment
192.168.1.1
10.0.0.1
"#;
        
        let ips = manager.parse_feed(content).unwrap();
        assert_eq!(ips.len(), 2);
    }
}
