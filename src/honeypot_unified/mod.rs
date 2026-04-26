use crate::utils::current_timestamp;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;

static UNIFIED_HONEYPOT_MANAGER: OnceLock<UnifiedHoneypotManager> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    pub fn score(&self) -> u8 {
        match self {
            ThreatLevel::None => 0,
            ThreatLevel::Low => 25,
            ThreatLevel::Medium => 50,
            ThreatLevel::High => 75,
            ThreatLevel::Critical => 100,
        }
    }

    pub fn from_score(score: u8) -> Self {
        match score {
            0..=10 => ThreatLevel::None,
            11..=30 => ThreatLevel::Low,
            31..=60 => ThreatLevel::Medium,
            61..=85 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpHoneypotProfile {
    pub ip: IpAddr,
    pub url_hits: AtomicU64,
    pub port_connections: AtomicU64,
    pub protocols_probed: RwLock<Vec<String>>,
    pub last_hit: AtomicU64,
    pub threat_level: AtomicU8,
}

impl IpHoneypotProfile {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            url_hits: AtomicU64::new(0),
            port_connections: AtomicU64::new(0),
            protocols_probed: RwLock::new(Vec::new()),
            last_hit: AtomicU64::new(0),
            threat_level: AtomicU8::new(0),
        }
    }

    pub fn record_url_hit(&self) {
        self.url_hits.fetch_add(1, Ordering::Relaxed);
        self.update_threat_level();
        self.last_hit.store(current_timestamp(), Ordering::Relaxed);
    }

    pub fn record_port_connection(&self, protocol: &str) {
        self.port_connections.fetch_add(1, Ordering::Relaxed);
        {
            let mut protocols = self.protocols_probed.write();
            if !protocols.contains(&protocol.to_string()) {
                protocols.push(protocol.to_string());
            }
        }
        self.update_threat_level();
        self.last_hit.store(current_timestamp(), Ordering::Relaxed);
    }

    fn update_threat_level(&self) {
        let url_hits = self.url_hits.load(Ordering::Relaxed);
        let port_conns = self.port_connections.load(Ordering::Relaxed);
        let protocols = self.protocols_probed.read().len() as u8;

        let score = std::cmp::min(100, (url_hits as u8 * 10) + (port_conns as u8 * 15) + (protocols * 20));
        let level = ThreatLevel::from_score(score);
        self.threat_level.store(level.score(), Ordering::Relaxed);
    }

    pub fn get_url_hits(&self) -> u64 {
        self.url_hits.load(Ordering::Relaxed)
    }

    pub fn get_port_connections(&self) -> u64 {
        self.port_connections.load(Ordering::Relaxed)
    }

    pub fn get_protocols(&self) -> Vec<String> {
        self.protocols_probed.read().clone()
    }

    pub fn get_threat_level(&self) -> ThreatLevel {
        ThreatLevel::from_score(self.threat_level.load(Ordering::Relaxed))
    }

    pub fn get_combined_score(&self) -> u8 {
        let self_score = self.threat_level.load(Ordering::Relaxed);
        let url_hits = self.url_hits.load(Ordering::Relaxed);
        let port_conns = self.port_connections.load(Ordering::Relaxed);

        let hit_bonus = std::cmp::min(30, ((url_hits + port_conns) / 10) as u8);
        self_score.saturating_add(hit_bonus).min(100)
    }
}

pub struct UnifiedHoneypotManager {
    profiles: RwLock<HashMap<IpAddr, IpHoneypotProfile>>,
}

impl UnifiedHoneypotManager {
    pub fn new() -> Self {
        Self {
            profiles: RwLock::new(HashMap::new()),
        }
    }

    pub fn get() -> &'static Self {
        UNIFIED_HONEYPOT_MANAGER.get_or_init(|| Self::new())
    }

    pub fn get_or_create_profile(&self, ip: IpAddr) -> &IpHoneypotProfile {
        let profiles = self.profiles.read();
        if let Some(profile) = profiles.get(&ip) {
            return profile;
        }
        drop(profiles);

        let mut profiles = self.profiles.write();
        profiles.entry(ip).or_insert_with(|| IpHoneypotProfile::new(ip))
    }

    pub fn record_url_hit(&self, ip: IpAddr) {
        let profile = self.get_or_create_profile(ip);
        profile.record_url_hit();
    }

    pub fn record_port_connection(&self, ip: IpAddr, protocol: &str) {
        let profile = self.get_or_create_profile(ip);
        profile.record_port_connection(protocol);
    }

    pub fn get_profile(&self, ip: &IpAddr) -> Option<IpHoneypotProfile> {
        let profiles = self.profiles.read();
        profiles.get(ip).map(|p| IpHoneypotProfile {
            ip: p.ip,
            url_hits: AtomicU64::new(p.get_url_hits()),
            port_connections: AtomicU64::new(p.get_port_connections()),
            protocols_probed: RwLock::new(p.get_protocols()),
            last_hit: AtomicU64::new(0),
            threat_level: AtomicU8::new(p.get_threat_level().score()),
        })
    }

    pub fn get_combined_threat_score(&self, ip: &IpAddr) -> u8 {
        let profiles = self.profiles.read();
        if let Some(profile) = profiles.get(ip) {
            return profile.get_combined_score();
        }
        0
    }

    pub fn get_all_profiles(&self) -> Vec<(IpAddr, u8)> {
        let profiles = self.profiles.read();
        profiles
            .iter()
            .map(|(&ip, p)| (ip, p.get_combined_score()))
            .collect()
    }

    pub fn clear_expired(&self, max_age_secs: u64) {
        let now = current_timestamp();
        let mut profiles = self.profiles.write();
        profiles.retain(|_, p| {
            let last_hit = p.last_hit.load(Ordering::Relaxed);
            now.saturating_sub(last_hit) < max_age_secs
        });
    }

    pub fn get_corrrelated_ips(&self, ip: &IpAddr) -> Vec<IpAddr> {
        let profiles = self.profiles.read();
        let target_score = profiles
            .get(ip)
            .map(|p| p.get_combined_score())
            .unwrap_or(0);

        let threshold = target_score.saturating_sub(10);
        profiles
            .iter()
            .filter(|(_, p)| p.get_combined_score() >= threshold)
            .map(|(&ip, _)| ip)
            .collect()
    }
}

impl Default for UnifiedHoneypotManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn unified_honeypot_manager() -> &'static UnifiedHoneypotManager {
    UnifiedHoneypotManager::get()
}