use parking_lot::RwLock;
use rand::Rng;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const HONEYPOT_PREFIX: &str = "/_waf_hp_";

#[derive(Debug, Clone)]
pub struct HoneypotEntry {
    pub paths: Vec<String>,
    pub created_at: u64,
}

pub struct HoneypotTracker {
    entries: RwLock<HashMap<IpAddr, HoneypotEntry>>,
    paths_per_ip: usize,
    ttl_secs: u64,
}

impl HoneypotTracker {
    pub fn new(paths_per_ip: usize, ttl_secs: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            paths_per_ip: paths_per_ip.max(1),
            ttl_secs,
        }
    }

    pub fn generate_for_ip(&self, ip: &IpAddr) -> Vec<String> {
        let now = current_timestamp();

        let paths: Vec<String> = (0..self.paths_per_ip)
            .map(|_| generate_honeypot_path())
            .collect();

        let entry = HoneypotEntry {
            paths: paths.clone(),
            created_at: now,
        };

        self.entries.write().insert(*ip, entry);
        paths
    }

    pub fn get_or_generate(&self, ip: &IpAddr) -> Vec<String> {
        {
            let entries = self.entries.read();
            if let Some(entry) = entries.get(ip) {
                let now = current_timestamp();
                if now < entry.created_at + self.ttl_secs {
                    return entry.paths.clone();
                }
            }
        }
        self.generate_for_ip(ip)
    }

    pub fn is_honeypot_hit(&self, ip: &IpAddr, path: &str) -> bool {
        if !path.starts_with(HONEYPOT_PREFIX) {
            return false;
        }

        let entries = self.entries.read();
        if let Some(entry) = entries.get(ip) {
            return entry
                .paths
                .iter()
                .any(|p| path == p || path.starts_with(&format!("{}/", p)));
        }
        false
    }

    pub fn cleanup_expired(&self) {
        let now = current_timestamp();
        self.entries
            .write()
            .retain(|_, entry| now < entry.created_at + self.ttl_secs);
    }

    pub fn generate_html(&self, ip: &IpAddr) -> String {
        let paths = self.get_or_generate(ip);
        let mut html = String::new();

        for path in paths {
            html.push_str(&format!(
                r#"<a href="{}" style="display:none;visibility:hidden;opacity:0;position:absolute;left:-9999px;width:0;height:0;overflow:hidden;" tabindex="-1" aria-hidden="true">.</a>"#,
                path
            ));
        }

        html
    }

    pub fn paths_per_ip(&self) -> usize {
        self.paths_per_ip
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }
}

fn generate_random_path() -> String {
    let mut rng = rand::thread_rng();
    let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

    let segment1: String = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    let segment2: String = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    format!("{}/{}", segment1, segment2)
}

pub fn generate_honeypot_path() -> String {
    format!("{}{}", HONEYPOT_PREFIX, generate_random_path())
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_honeypot_generation() {
        let tracker = HoneypotTracker::new(3, 3600);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let paths = tracker.generate_for_ip(&ip);
        assert_eq!(paths.len(), 3);

        for path in &paths {
            assert!(path.starts_with(HONEYPOT_PREFIX));
        }
    }

    #[test]
    fn test_honeypot_hit_detection() {
        let tracker = HoneypotTracker::new(2, 3600);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let paths = tracker.generate_for_ip(&ip);
        let first_path = &paths[0];

        assert!(tracker.is_honeypot_hit(&ip, first_path));
        assert!(!tracker.is_honeypot_hit(&ip, "/normal/path"));
    }

    #[test]
    fn test_different_ips_different_paths() {
        let tracker = HoneypotTracker::new(5, 3600);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        let paths1 = tracker.generate_for_ip(&ip1);
        let paths2 = tracker.generate_for_ip(&ip2);

        assert!(tracker.is_honeypot_hit(&ip1, &paths1[0]));
        assert!(!tracker.is_honeypot_hit(&ip2, &paths1[0]));
    }
}
