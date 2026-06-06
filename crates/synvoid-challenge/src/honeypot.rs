use parking_lot::RwLock;
use rand::Rng;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use synvoid_utils::current_timestamp;

pub const HONEYPOT_PREFIX: &str = "/_waf_hp_";

#[derive(Debug)]
pub struct HoneypotTrapPath {
    pub trap_path: String,
    pub app_path: String,
    hits: AtomicU64,
}

impl HoneypotTrapPath {
    fn new(trap_path: String, app_path: String) -> Self {
        Self {
            trap_path,
            app_path,
            hits: AtomicU64::new(0),
        }
    }

    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    fn get_hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }
}

impl Clone for HoneypotTrapPath {
    fn clone(&self) -> Self {
        HoneypotTrapPath {
            trap_path: self.trap_path.clone(),
            app_path: self.app_path.clone(),
            hits: AtomicU64::new(self.hits.load(Ordering::Relaxed)),
        }
    }
}

#[derive(Debug)]
pub struct HoneypotEntry {
    pub traps: Vec<HoneypotTrapPath>,
    pub created_at: u64,
}

impl Clone for HoneypotEntry {
    fn clone(&self) -> Self {
        HoneypotEntry {
            traps: self.traps.clone(),
            created_at: self.created_at,
        }
    }
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

    pub fn generate_for_ip(&self, ip: &IpAddr, app_path: &str) -> Vec<String> {
        let now = current_timestamp();

        let traps: Vec<HoneypotTrapPath> = (0..self.paths_per_ip)
            .map(|_| HoneypotTrapPath::new(generate_honeypot_path(), app_path.to_string()))
            .collect();

        let paths: Vec<String> = traps.iter().map(|t| t.trap_path.clone()).collect();

        let mut entries = self.entries.write();
        if let Some(existing) = entries.get_mut(ip) {
            existing.traps.extend(traps);
        } else {
            let entry = HoneypotEntry {
                traps,
                created_at: now,
            };
            entries.insert(*ip, entry);
        }
        drop(entries);

        paths
    }

    pub fn get_or_generate(&self, ip: &IpAddr, app_path: &str) -> Vec<String> {
        {
            let entries = self.entries.read();
            if let Some(entry) = entries.get(ip) {
                let now = current_timestamp();
                if now < entry.created_at + self.ttl_secs {
                    return entry.traps.iter().map(|t| t.trap_path.clone()).collect();
                }
            }
        }
        self.generate_for_ip(ip, app_path)
    }

    pub fn is_honeypot_hit(&self, ip: &IpAddr, path: &str) -> Option<String> {
        if !path.starts_with(HONEYPOT_PREFIX) {
            return None;
        }

        let entries = self.entries.read();
        if let Some(entry) = entries.get(ip) {
            for trap in &entry.traps {
                if path == trap.trap_path || path.starts_with(&format!("{}/", trap.trap_path)) {
                    let app_path = trap.app_path.clone();
                    trap.record_hit();
                    return Some(app_path);
                }
            }
        }
        None
    }

    pub fn generate_html(&self, ip: &IpAddr, app_path: &str) -> String {
        let paths = self.get_or_generate(ip, app_path);
        let mut html = String::new();

        for path in paths {
            html.push_str(&format!(
                r#"<a href="{}" rel="nofollow" data-waf-honeypot="true" data-waf-app-path="{}" style="display:none;visibility:hidden;opacity:0;position:absolute;left:-9999px;width:0;height:0;overflow:hidden;" tabindex="-1" aria-hidden="true">.</a>"#,
                path, app_path
            ));
        }

        html
    }

    pub fn get_path_stats(&self) -> HashMap<String, PathHitStats> {
        let entries = self.entries.read();
        let mut stats_map: HashMap<String, PathHitStats> = HashMap::new();

        for entry in entries.values() {
            for trap in &entry.traps {
                let hits = trap.get_hits();
                let app_path = trap.app_path.clone();
                stats_map
                    .entry(app_path.clone())
                    .or_insert_with(|| PathHitStats {
                        app_path,
                        total_traps: 0,
                        total_hits: 0,
                    })
                    .total_hits += hits;
                stats_map.get_mut(&trap.app_path).unwrap().total_traps += 1;
            }
        }

        stats_map
    }

    pub fn paths_per_ip(&self) -> usize {
        self.paths_per_ip
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PathHitStats {
    pub app_path: String,
    pub total_traps: u64,
    pub total_hits: u64,
}

fn generate_random_path() -> String {
    let mut rng = rand::rng();
    let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

    let segment1: String = (0..8)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    let segment2: String = (0..8)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    format!("{}/{}", segment1, segment2)
}

pub fn generate_honeypot_path() -> String {
    format!("{}{}", HONEYPOT_PREFIX, generate_random_path())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_honeypot_generation() {
        let tracker = HoneypotTracker::new(3, 3600);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let paths = tracker.generate_for_ip(&ip, "/test");
        assert_eq!(paths.len(), 3);

        for path in &paths {
            assert!(path.starts_with(HONEYPOT_PREFIX));
        }
    }

    #[test]
    fn test_honeypot_hit_detection() {
        let tracker = HoneypotTracker::new(2, 3600);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let paths = tracker.generate_for_ip(&ip, "/test");
        let first_path = &paths[0];

        let app_path = tracker.is_honeypot_hit(&ip, first_path);
        assert!(app_path.is_some());
        assert_eq!(app_path.unwrap(), "/test");
        assert!(tracker.is_honeypot_hit(&ip, "/normal/path").is_none());
    }

    #[test]
    fn test_different_ips_different_paths() {
        let tracker = HoneypotTracker::new(5, 3600);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        let paths1 = tracker.generate_for_ip(&ip1, "/app1");
        let _paths2 = tracker.generate_for_ip(&ip2, "/app2");

        let app_path = tracker.is_honeypot_hit(&ip1, &paths1[0]);
        assert!(app_path.is_some());
        assert_eq!(app_path.unwrap(), "/app1");
        assert!(tracker.is_honeypot_hit(&ip2, &paths1[0]).is_none());
    }

    #[test]
    fn test_path_tracking() {
        let tracker = HoneypotTracker::new(2, 3600);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        tracker.generate_for_ip(&ip, "/login");
        tracker.generate_for_ip(&ip, "/admin");

        let stats = tracker.get_path_stats();
        assert!(stats.contains_key("/login"));
        assert!(stats.contains_key("/admin"));
    }

    #[test]
    fn test_hit_counting() {
        let tracker = HoneypotTracker::new(1, 3600);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let paths = tracker.generate_for_ip(&ip, "/test");

        tracker.is_honeypot_hit(&ip, &paths[0]);
        tracker.is_honeypot_hit(&ip, &paths[0]);

        let stats = tracker.get_path_stats();
        let test_stats = stats.get("/test").unwrap();
        assert_eq!(test_stats.total_hits, 2);
    }
}
