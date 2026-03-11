pub mod connection_limiter;
pub mod syn_flood;
pub mod udp_flood;

pub use connection_limiter::{ConnectionLimiter, ConnectionStats};
pub use syn_flood::{SynFloodProtector, SynFloodStats};
pub use udp_flood::{UdpFloodProtector, UdpFloodStats, UdpProtocolLimits};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloodDecision {
    Allowed,
    RateLimited,
    Blackholed,
}

#[derive(Debug, Clone)]
pub struct FloodConfig {
    pub syn_rate_per_ip: u32,
    pub syn_rate_global: u32,
    pub connection_rate_per_ip: u32,
    pub connection_rate_global: u32,
    pub half_open_max: u32,
    pub half_open_per_ip_max: u32,
    pub udp_rate_per_ip: u32,
    pub udp_rate_global: u32,
    pub blackhole_threshold: f64,
    pub blackhole_duration_secs: u64,
}

impl Default for FloodConfig {
    fn default() -> Self {
        Self {
            syn_rate_per_ip: 50,
            syn_rate_global: 10000,
            connection_rate_per_ip: 100,
            connection_rate_global: 20000,
            half_open_max: 1000,
            half_open_per_ip_max: 10,
            udp_rate_per_ip: 1000,
            udp_rate_global: 100000,
            blackhole_threshold: 0.9,
            blackhole_duration_secs: 60,
        }
    }
}

pub struct FloodProtector {
    config: FloodConfig,
    syn_protector: SynFloodProtector,
    connection_limiter: ConnectionLimiter,
    udp_protector: UdpFloodProtector,
    start_instant: Instant,
    blackhole_until: AtomicU64,
    global_blackhole: AtomicBool,
}

impl FloodProtector {
    pub fn new(config: FloodConfig) -> Self {
        let syn_protector = SynFloodProtector::new(
            config.syn_rate_per_ip,
            config.syn_rate_global,
            config.half_open_max,
            config.half_open_per_ip_max,
        );

        let connection_limiter =
            ConnectionLimiter::new(config.connection_rate_per_ip, config.connection_rate_global);

        let udp_protector = UdpFloodProtector::new(config.udp_rate_per_ip, config.udp_rate_global);

        Self {
            config,
            syn_protector,
            connection_limiter,
            udp_protector,
            start_instant: Instant::now(),
            blackhole_until: AtomicU64::new(0),
            global_blackhole: AtomicBool::new(false),
        }
    }

    pub fn check_tcp_connection(&self, ip: std::net::IpAddr) -> FloodDecision {
        if self.is_in_blackhole() {
            return FloodDecision::Blackholed;
        }

        if let FloodDecision::RateLimited = self.syn_protector.check_syn(ip) {
            metrics::counter!("rustwaf.flood.syn_limited").increment(1);
            return FloodDecision::RateLimited;
        }

        match self.connection_limiter.try_register_connection(ip) {
            FloodDecision::RateLimited => {
                metrics::counter!("rustwaf.flood.connection_limited").increment(1);
                return FloodDecision::RateLimited;
            }
            FloodDecision::Allowed => {}
            FloodDecision::Blackholed => {
                return FloodDecision::Blackholed;
            }
        }

        self.syn_protector.register_ack(ip);

        FloodDecision::Allowed
    }

    pub fn register_connection(&self, ip: std::net::IpAddr) {
        self.syn_protector.register_ack(ip);
    }

    pub fn register_half_open(&self, ip: std::net::IpAddr) {
        self.syn_protector.register_half_open(ip);
    }

    pub fn complete_connection(&self, ip: std::net::IpAddr) {
        self.syn_protector.complete_half_open(ip);
    }

    pub fn check_udp(&self, ip: std::net::IpAddr) -> FloodDecision {
        if self.is_in_blackhole() {
            return FloodDecision::Blackholed;
        }

        if let FloodDecision::RateLimited = self.udp_protector.check_packet(ip) {
            metrics::counter!("rustwaf.flood.udp_limited").increment(1);
            return FloodDecision::RateLimited;
        }

        FloodDecision::Allowed
    }

    pub fn enter_blackhole(&self) {
        let now = self.start_instant.elapsed().as_secs();
        let until = now + self.config.blackhole_duration_secs;
        self.blackhole_until.store(until, Ordering::Relaxed);
        self.global_blackhole.store(true, Ordering::Relaxed);

        tracing::warn!(
            duration_secs = self.config.blackhole_duration_secs,
            "Entering flood blackhole mode"
        );
    }

    pub fn exit_blackhole(&self) {
        self.blackhole_until.store(0, Ordering::Relaxed);
        self.global_blackhole.store(false, Ordering::Relaxed);
        tracing::info!("Exiting flood blackhole mode");
    }

    pub fn is_in_blackhole(&self) -> bool {
        if !self.global_blackhole.load(Ordering::Relaxed) {
            return false;
        }

        let now = self.start_instant.elapsed().as_secs();
        let until = self.blackhole_until.load(Ordering::Relaxed);

        if now >= until {
            self.exit_blackhole();
            return false;
        }

        true
    }

    pub fn get_stats(&self) -> FloodStats {
        FloodStats {
            syn_stats: self.syn_protector.get_stats(),
            connection_stats: self.connection_limiter.get_stats(),
            udp_stats: self.udp_protector.get_stats(),
            in_blackhole: self.global_blackhole.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FloodStats {
    pub syn_stats: SynFloodStats,
    pub connection_stats: ConnectionStats,
    pub udp_stats: UdpFloodStats,
    pub in_blackhole: bool,
}
