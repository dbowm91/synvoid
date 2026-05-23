use crate::waf::flood::{FloodConfig, FloodDecision, SynFloodProtector, SynFloodStats};
use aya::{
    maps::{Array, PerCpuArray},
    programs::xdp::Xdp,
    Ebpf,
};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

pub mod maps {
    use std::net::Ipv4Addr;

    pub const CONFIG_KEY: u32 = 0;

    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct FloodConfig {
        pub enabled: u8,
        pub global_rate_pps: u32,
        pub per_ip_rate_pps: u32,
        pub max_half_open: u32,
        pub per_ip_max_connections: u32,
        pub window_size_secs: u32,
        pub _pad: [u8; 3],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Ipv4Key {
        pub addr: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Ipv6Key {
        pub addr: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct FloodStats {
        pub syn_seen: u64,
        pub syn_dropped_global_rate: u64,
        pub syn_dropped_per_ip_rate: u64,
        pub half_open_exceeded: u64,
        pub connections_tracked: u64,
        pub packets_passed: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct WindowState {
        pub global_count: u32,
        pub window_start_ns: u64,
    }

    impl From<&super::FloodConfig> for FloodConfig {
        fn from(config: &super::FloodConfig) -> Self {
            Self {
                enabled: 1,
                global_rate_pps: config.syn_rate_global,
                per_ip_rate_pps: config.syn_rate_per_ip,
                max_half_open: config.half_open_max,
                per_ip_max_connections: config.half_open_per_ip_max,
                window_size_secs: 1,
                _pad: [0; 3],
            }
        }
    }
}

pub struct EbpfSynFloodProtector {
    config: FloodConfig,
    ebpf: Option<Ebpf>,
    attached_interfaces: HashSet<String>,
    userspace_fallback: Option<SynFloodProtector>,
}

impl EbpfSynFloodProtector {
    pub fn new(config: FloodConfig) -> Result<Self, EbpfFloodError> {
        Self::check_availability()?;

        let userspace_fallback = SynFloodProtector::new(
            config.syn_rate_per_ip,
            config.syn_rate_global,
            config.half_open_max,
            config.half_open_per_ip_max,
        );

        Ok(Self {
            config,
            ebpf: None,
            attached_interfaces: HashSet::new(),
            userspace_fallback: Some(userspace_fallback),
        })
    }

    fn check_availability() -> Result<(), EbpfFloodError> {
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return Err(EbpfFloodError::NotAvailable(
                "BTF not available in kernel".to_string(),
            ));
        }

        let content = std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
            .unwrap_or_else(|_| "1".to_string());

        if content.trim() == "2" {
            return Err(EbpfFloodError::PermissionDenied);
        }

        Ok(())
    }

    pub fn is_available() -> bool {
        Self::check_availability().is_ok()
    }

    fn load_ebpf_bytecode() -> Result<Vec<u8>, EbpfFloodError> {
        let bytecode_paths = vec![
            "/usr/lib/synvoid/ebpf/synvoid-flood.bpf".to_string(),
            "/usr/local/lib/synvoid/ebpf/synvoid-flood.bpf".to_string(),
            "./ebpf-flood/target/bpfel-unknown-none/release/synvoid-flood".to_string(),
        ];

        for path in &bytecode_paths {
            if std::path::Path::new(path).exists() {
                tracing::info!("Loading eBPF flood bytecode from: {}", path);
                return std::fs::read(path).map_err(|e| {
                    EbpfFloodError::BytecodeError(format!("Failed to read eBPF bytecode: {}", e))
                });
            }
        }

        Err(EbpfFloodError::BytecodeError(
            "eBPF bytecode not found. Build with: cd ebpf-flood && cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release".to_string(),
        ))
    }

    fn load_ebpf_program(&mut self) -> Result<(), EbpfFloodError> {
        let bytecode = Self::load_ebpf_bytecode()?;

        let ebpf = Ebpf::load(&bytecode).map_err(|e| {
            EbpfFloodError::LoadError(format!("Failed to load eBPF program: {}", e))
        })?;

        self.ebpf = Some(ebpf);
        self.update_config()?;

        Ok(())
    }

    fn update_config(&self) -> Result<(), EbpfFloodError> {
        let ebpf = self
            .ebpf
            .as_ref()
            .ok_or_else(|| EbpfFloodError::NotLoaded)?;

        let mut config_map: Array<_, maps::FloodConfig> = ebpf
            .map("CONFIG_MAP")
            .ok_or_else(|| EbpfFloodError::MapNotFound("CONFIG_MAP".to_string()))?
            .try_into()
            .map_err(|e| EbpfFloodError::MapError(format!("Failed to access CONFIG_MAP: {}", e)))?;

        let config = maps::FloodConfig::from(&self.config);
        config_map
            .set(&maps::CONFIG_KEY, config, 0)
            .map_err(|e| EbpfFloodError::MapError(format!("Failed to set config: {}", e)))?;

        Ok(())
    }

    pub fn enable(&mut self) -> Result<(), EbpfFloodError> {
        if self.ebpf.is_some() {
            return Ok(());
        }

        self.load_ebpf_program()?;

        let ebpf = self
            .ebpf
            .as_mut()
            .ok_or_else(|| EbpfFloodError::NotLoaded)?;

        let xdp_program: &mut Xdp = ebpf
            .program_mut("filter_syn")
            .ok_or_else(|| EbpfFloodError::ProgramNotFound("filter_syn".to_string()))?
            .try_into()
            .map_err(|e| {
                EbpfFloodError::ProgramError(format!("Failed to get XDP program: {}", e))
            })?;

        xdp_program.load().map_err(|e| {
            EbpfFloodError::ProgramError(format!("Failed to load XDP program: {}", e))
        })?;

        let interfaces = self.get_interfaces();
        for iface in &interfaces {
            xdp_program
                .attach(iface, aya::programs::xdp::XdpFlags::default())
                .map_err(|e| {
                    EbpfFloodError::AttachError(format!("Failed to attach XDP to {}: {}", iface, e))
                })?;

            tracing::info!("Attached XDP SYN flood filter to interface: {}", iface);
            self.attached_interfaces.insert(iface.clone());
        }

        tracing::info!("eBPF SYN flood protection enabled");
        Ok(())
    }

    pub fn disable(&mut self) -> Result<(), EbpfFloodError> {
        for iface in self.attached_interfaces.drain() {
            tracing::info!("Detaching XDP SYN flood filter from interface: {}", iface);
        }

        self.ebpf = None;
        tracing::info!("eBPF SYN flood protection disabled");
        Ok(())
    }

    fn get_interfaces(&self) -> Vec<String> {
        let mut interfaces = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if let Some(name_str) = name.to_str() {
                    if name_str != "lo" {
                        interfaces.push(name_str.to_string());
                    }
                }
            }
        }
        interfaces
    }

    pub fn check_syn(&self, ip: IpAddr) -> FloodDecision {
        if let Some(ref fallback) = self.userspace_fallback {
            fallback.check_syn(ip)
        } else {
            FloodDecision::Allowed
        }
    }

    pub fn register_half_open(&self, ip: IpAddr) {
        if let Some(ref fallback) = self.userspace_fallback {
            fallback.register_half_open(ip);
        }
    }

    pub fn register_ack(&self, ip: IpAddr) {
        if let Some(ref fallback) = self.userspace_fallback {
            fallback.register_ack(ip);
        }
    }

    pub fn complete_half_open(&self, ip: IpAddr) {
        if let Some(ref fallback) = self.userspace_fallback {
            fallback.complete_half_open(ip);
        }
    }

    pub fn get_stats(&self) -> super::SynFloodStats {
        if let Some(ebpf) = self.ebpf.as_ref() {
            if let Ok(stats_map) = ebpf.map::<PerCpuArray<_, maps::FloodStats>>("STATS") {
                if let Ok(per_cpu_stats) = stats_map.get(&0, 0) {
                    let mut total = maps::FloodStats::default();
                    for stats in per_cpu_stats {
                        total.syn_seen += stats.syn_seen;
                        total.syn_dropped_global_rate += stats.syn_dropped_global_rate;
                        total.syn_dropped_per_ip_rate += stats.syn_dropped_per_ip_rate;
                        total.half_open_exceeded += stats.half_open_exceeded;
                        total.connections_tracked += stats.connections_tracked;
                        total.packets_passed += stats.packets_passed;
                    }
                    return super::SynFloodStats {
                        global_syn_rate: total.syn_seen,
                        half_open_connections: total.connections_tracked as u32,
                        unique_half_open_ips: 0,
                    };
                }
            }
        }

        super::SynFloodStats {
            global_syn_rate: 0,
            half_open_connections: 0,
            unique_half_open_ips: 0,
        }
    }

    pub fn update_config(&mut self, config: FloodConfig) -> Result<(), EbpfFloodError> {
        let was_enabled = self.ebpf.is_some();

        if was_enabled {
            self.disable()?;
        }

        self.config = config;

        if was_enabled {
            self.enable()?;
        }

        Ok(())
    }

    pub fn block_ip(&self, ip: IpAddr) -> Result<(), EbpfFloodError> {
        let ebpf = self
            .ebpf
            .as_ref()
            .ok_or_else(|| EbpfFloodError::NotLoaded)?;

        match ip {
            IpAddr::V4(v4) => {
                let mut blocklist: HashMap<_, maps::Ipv4Key, u8> = ebpf
                    .map("IP_BLOCKLIST_V4")
                    .ok_or_else(|| EbpfFloodError::MapNotFound("IP_BLOCKLIST_V4".to_string()))?
                    .try_into()
                    .map_err(|e| {
                        EbpfFloodError::MapError(format!("Failed to access IP_BLOCKLIST_V4: {}", e))
                    })?;

                let key = maps::Ipv4Key { addr: v4.into() };
                blocklist.insert(key, 1, 0).map_err(|e| {
                    EbpfFloodError::MapError(format!("Failed to block IPv4: {}", e))
                })?;
            }
            IpAddr::V6(v6) => {
                let mut blocklist: HashMap<_, maps::Ipv6Key, u8> = ebpf
                    .map("IP_BLOCKLIST_V6")
                    .ok_or_else(|| EbpfFloodError::MapNotFound("IP_BLOCKLIST_V6".to_string()))?
                    .try_into()
                    .map_err(|e| {
                        EbpfFloodError::MapError(format!("Failed to access IP_BLOCKLIST_V6: {}", e))
                    })?;

                let key = maps::Ipv6Key { addr: v6.octets() };
                blocklist.insert(key, 1, 0).map_err(|e| {
                    EbpfFloodError::MapError(format!("Failed to block IPv6: {}", e))
                })?;
            }
        }

        Ok(())
    }

    pub fn unblock_ip(&self, ip: IpAddr) -> Result<(), EbpfFloodError> {
        let ebpf = self
            .ebpf
            .as_ref()
            .ok_or_else(|| EbpfFloodError::NotLoaded)?;

        match ip {
            IpAddr::V4(v4) => {
                let mut blocklist: HashMap<_, maps::Ipv4Key, u8> = ebpf
                    .map("IP_BLOCKLIST_V4")
                    .ok_or_else(|| EbpfFloodError::MapNotFound("IP_BLOCKLIST_V4".to_string()))?
                    .try_into()
                    .map_err(|e| {
                        EbpfFloodError::MapError(format!("Failed to access IP_BLOCKLIST_V4: {}", e))
                    })?;

                let key = maps::Ipv4Key { addr: v4.into() };
                blocklist.remove(&key).map_err(|e| {
                    EbpfFloodError::MapError(format!("Failed to unblock IPv4: {}", e))
                })?;
            }
            IpAddr::V6(v6) => {
                let mut blocklist: HashMap<_, maps::Ipv6Key, u8> = ebpf
                    .map("IP_BLOCKLIST_V6")
                    .ok_or_else(|| EbpfFloodError::MapNotFound("IP_BLOCKLIST_V6".to_string()))?
                    .try_into()
                    .map_err(|e| {
                        EbpfFloodError::MapError(format!("Failed to access IP_BLOCKLIST_V6: {}", e))
                    })?;

                let key = maps::Ipv6Key { addr: v6.octets() };
                blocklist.remove(&key).map_err(|e| {
                    EbpfFloodError::MapError(format!("Failed to unblock IPv6: {}", e))
                })?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum EbpfFloodError {
    NotAvailable(String),
    PermissionDenied,
    BytecodeError(String),
    LoadError(String),
    NotLoaded,
    ProgramNotFound(String),
    ProgramError(String),
    AttachError(String),
    MapNotFound(String),
    MapError(String),
}

impl std::fmt::Display for EbpfFloodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAvailable(s) => write!(f, "eBPF not available: {}", s),
            Self::PermissionDenied => write!(f, "eBPF permission denied"),
            Self::BytecodeError(s) => write!(f, "Bytecode error: {}", s),
            Self::LoadError(s) => write!(f, "Load error: {}", s),
            Self::NotLoaded => write!(f, "eBPF program not loaded"),
            Self::ProgramNotFound(s) => write!(f, "Program not found: {}", s),
            Self::ProgramError(s) => write!(f, "Program error: {}", s),
            Self::AttachError(s) => write!(f, "Attach error: {}", s),
            Self::MapNotFound(s) => write!(f, "Map not found: {}", s),
            Self::MapError(s) => write!(f, "Map error: {}", s),
        }
    }
}

impl std::error::Error for EbpfFloodError {}
