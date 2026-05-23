pub mod connection_limiter;
pub mod syn_flood;
pub mod udp_flood;

#[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
pub mod ebpf_flood;

pub use connection_limiter::{ConnectionLimiter, ConnectionStats};
pub use syn_flood::{SynFloodProtector, SynFloodStats};
pub use udp_flood::{UdpFloodProtector, UdpFloodStats, UdpProtocolLimits};

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::RunningFlag;

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
    pub backend: FloodBackend,
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
            backend: FloodBackend::Userspace,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FloodBackend {
    #[default]
    Userspace,
    #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
    Ebpf,
}

impl std::fmt::Display for FloodBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Userspace => write!(f, "userspace"),
            #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
            Self::Ebpf => write!(f, "ebpf"),
        }
    }
}

pub trait SynFloodBackend: Send + Sync {
    fn check_syn(&self, ip: IpAddr) -> FloodDecision;
    fn register_half_open(&self, ip: IpAddr);
    fn register_ack(&self, ip: IpAddr);
    fn complete_half_open(&self, ip: IpAddr);
    fn get_stats(&self) -> SynFloodStats;
}

pub struct SynFloodBackendWrapper {
    #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
    ebpf_backend: Option<ebpf_flood::EbpfSynFloodProtector>,
    userspace_backend: SynFloodProtector,
    backend_type: FloodBackend,
}

impl SynFloodBackendWrapper {
    #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
    pub fn get_ebpf_protector(&self) -> Option<&ebpf_flood::EbpfSynFloodProtector> {
        self.ebpf_backend.as_ref()
    }

    pub fn new(config: &FloodConfig, preferred_backend: FloodBackend) -> Self {
        let actual_backend = Self::select_backend(config, preferred_backend);

        #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
        {
            let backend_value = match actual_backend {
                FloodBackend::Userspace => 0.0,
                FloodBackend::Ebpf => 1.0,
            };
            metrics::gauge!("synvoid.flood.syn_backend").set(backend_value);
        }

        tracing::info!("Using SYN flood protection backend: {}", actual_backend);

        let userspace_backend = SynFloodProtector::new(
            config.syn_rate_per_ip,
            config.syn_rate_global,
            config.half_open_max,
            config.half_open_per_ip_max,
        );

        #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
        let mut ebpf_backend: Option<ebpf_flood::EbpfSynFloodProtector> =
            if actual_backend == FloodBackend::Ebpf {
                match ebpf_flood::EbpfSynFloodProtector::new(config.clone()) {
                    Ok(mut backend) => {
                        if let Err(e) = backend.enable() {
                            tracing::warn!(
                                "Failed to enable eBPF backend: {}, falling back to userspace",
                                e
                            );
                            None
                        } else {
                            Some(backend)
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to create eBPF backend: {}, falling back to userspace",
                            e
                        );
                        None
                    }
                }
            } else {
                None
            };

        Self {
            #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
            ebpf_backend,
            userspace_backend,
            backend_type: actual_backend,
        }
    }

    fn select_backend(_config: &FloodConfig, _preferred: FloodBackend) -> FloodBackend {
        #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
        {
            if preferred == FloodBackend::Ebpf {
                if ebpf_flood::EbpfSynFloodProtector::is_available() {
                    return FloodBackend::Ebpf;
                } else {
                    tracing::warn!(
                        "eBPF backend requested but not available, falling back to userspace"
                    );
                }
            }
        }

        FloodBackend::Userspace
    }

    pub fn check_syn(&self, ip: IpAddr) -> FloodDecision {
        #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
        {
            if let Some(ref ebpf) = self.ebpf_backend {
                return ebpf.check_syn(ip);
            }
        }
        self.userspace_backend.check_syn(ip)
    }

    pub fn register_half_open(&self, ip: IpAddr) {
        #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
        {
            if let Some(ref ebpf) = self.ebpf_backend {
                return ebpf.register_half_open(ip);
            }
        }
        self.userspace_backend.register_half_open(ip);
    }

    pub fn register_ack(&self, ip: IpAddr) {
        #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
        {
            if let Some(ref ebpf) = self.ebpf_backend {
                return ebpf.register_ack(ip);
            }
        }
        self.userspace_backend.register_ack(ip);
    }

    pub fn complete_half_open(&self, ip: IpAddr) {
        #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
        {
            if let Some(ref ebpf) = self.ebpf_backend {
                return ebpf.complete_half_open(ip);
            }
        }
        self.userspace_backend.complete_half_open(ip);
    }

    pub fn get_stats(&self) -> SynFloodStats {
        #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
        {
            if let Some(ref ebpf) = self.ebpf_backend {
                return ebpf.get_stats();
            }
        }
        self.userspace_backend.get_stats()
    }

    pub fn backend_type(&self) -> FloodBackend {
        self.backend_type
    }
}

pub struct FloodProtector {
    config: FloodConfig,
    syn_protector: SynFloodBackendWrapper,
    connection_limiter: ConnectionLimiter,
    udp_protector: UdpFloodProtector,
    start_instant: Instant,
    blackhole_until: AtomicU64,
    global_blackhole: RunningFlag,
}

impl FloodProtector {
    pub fn get_syn_protector(&self) -> &SynFloodBackendWrapper {
        &self.syn_protector
    }

    pub fn new(config: FloodConfig) -> Self {
        let flood_backend = config.backend;
        let syn_protector = SynFloodBackendWrapper::new(&config, flood_backend);

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
            global_blackhole: RunningFlag::new(),
        }
    }

    pub fn check_tcp_connection(&self, ip: std::net::IpAddr) -> FloodDecision {
        if self.is_in_blackhole() {
            return FloodDecision::Blackholed;
        }

        if let FloodDecision::RateLimited = self.syn_protector.check_syn(ip) {
            metrics::counter!("synvoid.flood.syn_limited").increment(1);
            return FloodDecision::RateLimited;
        }

        match self.connection_limiter.try_register_connection(ip) {
            FloodDecision::RateLimited => {
                metrics::counter!("synvoid.flood.connection_limited").increment(1);
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
            metrics::counter!("synvoid.flood.udp_limited").increment(1);
            return FloodDecision::RateLimited;
        }

        FloodDecision::Allowed
    }

    pub fn enter_blackhole(&self) {
        let now = self.start_instant.elapsed().as_secs();
        let until = now + self.config.blackhole_duration_secs;
        self.blackhole_until.store(until, Ordering::Relaxed);
        self.global_blackhole.stop();

        tracing::warn!(
            duration_secs = self.config.blackhole_duration_secs,
            "Entering flood blackhole mode"
        );
    }

    pub fn exit_blackhole(&self) {
        self.blackhole_until.store(0, Ordering::Relaxed);
        self.global_blackhole.set(true);
        tracing::info!("Exiting flood blackhole mode");
    }

    pub fn is_in_blackhole(&self) -> bool {
        if !self.global_blackhole.is_running() {
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
            in_blackhole: self.global_blackhole.is_running(),
            backend: self.syn_protector.backend_type(),
        }
    }

    pub fn backend(&self) -> FloodBackend {
        self.syn_protector.backend_type()
    }
}

#[derive(Debug, Clone)]
pub struct FloodStats {
    pub syn_stats: SynFloodStats,
    pub connection_stats: ConnectionStats,
    pub udp_stats: UdpFloodStats,
    pub in_blackhole: bool,
    pub backend: FloodBackend,
}
