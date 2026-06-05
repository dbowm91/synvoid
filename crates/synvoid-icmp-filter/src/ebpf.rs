use crate::{
    config::{Direction, IcmpFilterConfig},
    error::{IcmpFilterError, Result},
    traits::{FilterBackend, FilterStatus, IcmpFilter},
};
use aya::{
    maps::{Array, HashMap, PerCpuArray},
    programs::{
        tc::{SchedClassifier, TcAttachType},
        xdp::Xdp,
    },
    Ebpf,
};
use std::collections::HashSet;
use std::net::IpAddr;

mod maps {
    pub const CONFIG_KEY: u32 = 0;
    pub const MAX_TYPE_RULES: u32 = 32;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Config {
        pub enabled: u8,
        pub filter_inbound: u8,
        pub filter_outbound: u8,
        pub rate_limit_enabled: u8,
        pub packets_per_second: u32,
        pub burst: u32,
        pub block_all_icmp: u8,
        pub _pad: [u8; 3],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct IcmpStats {
        pub packets_seen: u64,
        pub packets_dropped: u64,
        pub rate_limited: u64,
        pub exempt_passed: u64,
        pub type_rule_blocked: u64,
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
    #[derive(Clone, Copy, Default)]
    pub struct IcmpTypeRule {
        pub icmp_type: u8,
        pub icmp_code: u8,
        pub action: u8,
    }

    impl IcmpTypeRule {
        pub const ACTION_ALLOW: u8 = 0;
        pub const ACTION_BLOCK: u8 = 1;
        pub const CODE_WILDCARD: u8 = 255;
    }
}

#[derive(Debug)]
pub struct EbpfFilter {
    config: IcmpFilterConfig,
    enabled: bool,
    attached_interfaces: HashSet<String>,
    ebpf: Option<Ebpf>,
}

impl EbpfFilter {
    pub fn new(config: IcmpFilterConfig) -> Result<Self> {
        config.validate().map_err(IcmpFilterError::Config)?;
        Self::check_ebpf_available()?;
        Ok(Self {
            config,
            enabled: false,
            attached_interfaces: HashSet::new(),
            ebpf: None,
        })
    }

    fn check_ebpf_available() -> Result<()> {
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return Err(IcmpFilterError::Ebpf(
                "BTF not available in kernel".to_string(),
            ));
        }

        let content = std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
            .unwrap_or_else(|_| "1".to_string());

        if content.trim() == "2" {
            return Err(IcmpFilterError::PermissionDenied);
        }

        Ok(())
    }

    fn get_interfaces(&self) -> Vec<String> {
        match &self.config.interfaces {
            crate::icmp_filter::config::InterfaceSpec::All => {
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
            crate::icmp_filter::config::InterfaceSpec::Specific(ifaces) => ifaces.clone(),
        }
    }

    fn load_ebpf_bytecode(custom_path: Option<&str>) -> Result<Vec<u8>> {
        let bytecode_paths = if let Some(path) = custom_path {
            vec![path.to_string()]
        } else {
            vec![
                "/usr/lib/synvoid/ebpf/synvoid-icmp.bpf".to_string(),
                "/usr/local/lib/synvoid/ebpf/synvoid-icmp.bpf".to_string(),
                "./ebpf-icmp/target/bpfel-unknown-none/release/synvoid-icmp".to_string(),
            ]
        };

        for path in &bytecode_paths {
            if std::path::Path::new(path).exists() {
                tracing::info!("Loading eBPF bytecode from: {}", path);
                return std::fs::read(path).map_err(|e| {
                    IcmpFilterError::Ebpf(format!("Failed to read eBPF bytecode: {}", e))
                });
            }
        }

        Err(IcmpFilterError::Ebpf(
            "eBPF bytecode not found. Build with: cd ebpf-icmp && cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release".to_string(),
        ))
    }

    fn load_ebpf_program(&mut self) -> Result<()> {
        let bytecode = Self::load_ebpf_bytecode(self.config.ebpf_bytecode_path.as_deref())?;

        let ebpf = Ebpf::load(&bytecode)
            .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to load eBPF program: {}", e)))?;

        self.ebpf = Some(ebpf);
        self.update_bpf_maps()?;

        Ok(())
    }

    fn update_bpf_maps(&mut self) -> Result<()> {
        let ebpf = self
            .ebpf
            .as_mut()
            .ok_or_else(|| IcmpFilterError::Ebpf("eBPF program not loaded".to_string()))?;

        let mut config_map: Array<_, maps::Config> = ebpf
            .map("CONFIG_MAP")
            .ok_or_else(|| IcmpFilterError::Ebpf("CONFIG_MAP not found".to_string()))?
            .try_into()
            .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to access CONFIG_MAP: {}", e)))?;

        let has_type_rules = self.config.has_type_rules();
        let config = maps::Config {
            enabled: 1,
            filter_inbound: if self.config.direction == Direction::Both
                || self.config.direction == Direction::Inbound
            {
                1
            } else {
                0
            },
            filter_outbound: if self.config.direction == Direction::Both
                || self.config.direction == Direction::Outbound
            {
                1
            } else {
                0
            },
            rate_limit_enabled: self
                .config
                .rate_limit
                .as_ref()
                .map(|r| r.enabled as u8)
                .unwrap_or(0),
            packets_per_second: self
                .config
                .rate_limit
                .as_ref()
                .map(|r| r.packets_per_second)
                .unwrap_or(0),
            burst: self
                .config
                .rate_limit
                .as_ref()
                .map(|r| r.burst)
                .unwrap_or(0),
            block_all_icmp: if has_type_rules { 0 } else { 1 },
            _pad: [0; 3],
        };

        config_map
            .set(&maps::CONFIG_KEY, config, 0)
            .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to set config: {}", e)))?;

        let mut exempt_ipv4: HashMap<_, maps::Ipv4Key, u8> = ebpf
            .map("EXEMPT_IPV4")
            .ok_or_else(|| IcmpFilterError::Ebpf("EXEMPT_IPV4 map not found".to_string()))?
            .try_into()
            .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to access EXEMPT_IPV4: {}", e)))?;

        let mut exempt_ipv6: HashMap<_, maps::Ipv6Key, u8> = ebpf
            .map("EXEMPT_IPV6")
            .ok_or_else(|| IcmpFilterError::Ebpf("EXEMPT_IPV6 map not found".to_string()))?
            .try_into()
            .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to access EXEMPT_IPV6: {}", e)))?;

        for ip in &self.config.exempt_ips {
            match ip {
                IpAddr::V4(addr) => {
                    let key = maps::Ipv4Key {
                        addr: u32::from_be_bytes(addr.octets()),
                    };
                    exempt_ipv4.insert(key, 1, 0).map_err(|e| {
                        IcmpFilterError::Ebpf(format!("Failed to add exempt IPv4: {}", e))
                    })?;
                }
                IpAddr::V6(addr) => {
                    let key = maps::Ipv6Key {
                        addr: addr.octets(),
                    };
                    exempt_ipv6.insert(key, 1, 0).map_err(|e| {
                        IcmpFilterError::Ebpf(format!("Failed to add exempt IPv6: {}", e))
                    })?;
                }
            }
        }

        self.update_icmp_type_rules(ebpf)?;

        Ok(())
    }

    fn update_icmp_type_rules(&self, ebpf: &mut Ebpf) -> Result<()> {
        let mut rules_v4: Array<_, maps::IcmpTypeRule> = ebpf
            .map("ICMP_TYPE_RULES_V4")
            .ok_or_else(|| IcmpFilterError::Ebpf("ICMP_TYPE_RULES_V4 map not found".to_string()))?
            .try_into()
            .map_err(|e| {
                IcmpFilterError::Ebpf(format!("Failed to access ICMP_TYPE_RULES_V4: {}", e))
            })?;

        let mut rules_v6: Array<_, maps::IcmpTypeRule> = ebpf
            .map("ICMP_TYPE_RULES_V6")
            .ok_or_else(|| IcmpFilterError::Ebpf("ICMP_TYPE_RULES_V6 map not found".to_string()))?
            .try_into()
            .map_err(|e| {
                IcmpFilterError::Ebpf(format!("Failed to access ICMP_TYPE_RULES_V6: {}", e))
            })?;

        let mut idx = 0;
        for rule in &self.config.icmp_type_rules {
            if idx >= maps::MAX_TYPE_RULES {
                tracing::warn!(
                    "Max ICMPv4 type rules ({}) reached, ignoring extra rules",
                    maps::MAX_TYPE_RULES
                );
                break;
            }

            let ebpf_rule = maps::IcmpTypeRule {
                icmp_type: rule.icmp_type,
                icmp_code: rule.icmp_code.unwrap_or(maps::IcmpTypeRule::CODE_WILDCARD),
                action: if rule.is_block() {
                    maps::IcmpTypeRule::ACTION_BLOCK
                } else {
                    maps::IcmpTypeRule::ACTION_ALLOW
                },
            };

            rules_v4
                .set(&idx, ebpf_rule, 0)
                .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to set ICMPv4 rule: {}", e)))?;

            idx += 1;
        }

        let mut idx = 0;
        for rule in &self.config.icmpv6_type_rules {
            if idx >= maps::MAX_TYPE_RULES {
                tracing::warn!(
                    "Max ICMPv6 type rules ({}) reached, ignoring extra rules",
                    maps::MAX_TYPE_RULES
                );
                break;
            }

            let ebpf_rule = maps::IcmpTypeRule {
                icmp_type: rule.icmp_type,
                icmp_code: rule.icmp_code.unwrap_or(maps::IcmpTypeRule::CODE_WILDCARD),
                action: if rule.is_block() {
                    maps::IcmpTypeRule::ACTION_BLOCK
                } else {
                    maps::IcmpTypeRule::ACTION_ALLOW
                },
            };

            rules_v6
                .set(&idx, ebpf_rule, 0)
                .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to set ICMPv6 rule: {}", e)))?;

            idx += 1;
        }

        Ok(())
    }

    fn load_and_attach_program(&mut self) -> Result<()> {
        let interfaces = self.get_interfaces();

        if interfaces.is_empty() {
            return Err(IcmpFilterError::Config(
                "No interfaces to attach to".to_string(),
            ));
        }

        self.load_ebpf_program()?;

        let ebpf = self
            .ebpf
            .as_mut()
            .ok_or_else(|| IcmpFilterError::Ebpf("eBPF program not loaded".to_string()))?;

        let filter_inbound =
            self.config.direction == Direction::Both || self.config.direction == Direction::Inbound;
        let filter_outbound = self.config.direction == Direction::Both
            || self.config.direction == Direction::Outbound;

        if filter_inbound {
            let xdp_program: &mut Xdp = ebpf
                .program_mut("filter_inbound")
                .ok_or_else(|| {
                    IcmpFilterError::Ebpf("filter_inbound program not found".to_string())
                })?
                .try_into()
                .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to get XDP program: {}", e)))?;

            xdp_program
                .load()
                .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to load XDP program: {}", e)))?;

            for iface in &interfaces {
                xdp_program
                    .attach(iface, aya::programs::xdp::XdpFlags::default())
                    .map_err(|e| {
                        IcmpFilterError::Ebpf(format!("Failed to attach XDP to {}: {}", iface, e))
                    })?;

                tracing::info!("Attached XDP program to interface: {}", iface);
                self.attached_interfaces.insert(iface.clone());
            }
        }

        if filter_outbound {
            let tc_program: &mut SchedClassifier = ebpf
                .program_mut("filter_outbound")
                .ok_or_else(|| {
                    IcmpFilterError::Ebpf("filter_outbound program not found".to_string())
                })?
                .try_into()
                .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to get TC program: {}", e)))?;

            tc_program
                .load()
                .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to load TC program: {}", e)))?;

            for iface in &interfaces {
                self.setup_tc_qdisc(iface)?;

                tc_program
                    .attach(iface, TcAttachType::Egress)
                    .map_err(|e| {
                        IcmpFilterError::Ebpf(format!("Failed to attach TC to {}: {}", iface, e))
                    })?;

                tracing::info!("Attached TC classifier to interface: {}", iface);
            }
        }

        Ok(())
    }

    fn setup_tc_qdisc(&self, iface: &str) -> Result<()> {
        let output = std::process::Command::new("tc")
            .args(["qdisc", "show", "dev", iface])
            .output()
            .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to check qdisc: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("clsact") {
            let output = std::process::Command::new("tc")
                .args(["qdisc", "add", "dev", iface, "clsact"])
                .output()
                .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to add clsact qdisc: {}", e)))?;

            if !output.status.success() {
                return Err(IcmpFilterError::Ebpf(format!(
                    "Failed to setup clsact qdisc on {}: {}",
                    iface,
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        }

        Ok(())
    }

    fn detach_program(&mut self) -> Result<()> {
        for iface in self.attached_interfaces.drain() {
            tracing::info!("Detaching programs from interface: {}", iface);

            let output = std::process::Command::new("tc")
                .args(["filter", "del", "dev", &iface, "egress"])
                .output()
                .ok();

            if let Some(output) = output {
                if output.status.success() {
                    tracing::debug!("Removed TC filter from {}", iface);
                }
            }
        }

        self.ebpf = None;

        Ok(())
    }

    pub fn is_available() -> bool {
        std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
    }

    pub fn get_stats(&self) -> Result<maps::IcmpStats> {
        let ebpf = self
            .ebpf
            .as_ref()
            .ok_or_else(|| IcmpFilterError::Ebpf("eBPF program not loaded".to_string()))?;

        let stats_map: PerCpuArray<_, maps::IcmpStats> = ebpf
            .map("STATS_INBOUND")
            .ok_or_else(|| IcmpFilterError::Ebpf("STATS_INBOUND map not found".to_string()))?
            .try_into()
            .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to access stats: {}", e)))?;

        let per_cpu_stats = stats_map
            .get(&0, 0)
            .map_err(|e| IcmpFilterError::Ebpf(format!("Failed to get stats: {}", e)))?;

        let mut total = maps::IcmpStats::default();
        for stats in per_cpu_stats {
            total.packets_seen += stats.packets_seen;
            total.packets_dropped += stats.packets_dropped;
            total.rate_limited += stats.rate_limited;
            total.exempt_passed += stats.exempt_passed;
            total.type_rule_blocked += stats.type_rule_blocked;
        }

        Ok(total)
    }
}

impl IcmpFilter for EbpfFilter {
    fn enable(&mut self) -> Result<()> {
        if self.enabled {
            return Err(IcmpFilterError::AlreadyEnabled);
        }

        self.load_and_attach_program()?;
        self.enabled = true;
        tracing::info!("ICMP filter enabled via eBPF XDP/TC");
        Ok(())
    }

    fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Err(IcmpFilterError::AlreadyDisabled);
        }

        self.detach_program()?;
        self.enabled = false;
        tracing::info!("ICMP filter disabled via eBPF XDP/TC");
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn is_enforcing(&self) -> bool {
        self.enabled
    }

    fn backend(&self) -> FilterBackend {
        FilterBackend::Ebpf
    }

    fn status(&self) -> FilterStatus {
        FilterStatus {
            enabled: self.enabled,
            backend: FilterBackend::Ebpf,
            config: self.config.clone(),
        }
    }

    fn update_config(&mut self, config: IcmpFilterConfig) -> Result<()> {
        config.validate().map_err(IcmpFilterError::Config)?;
        let was_enabled = self.enabled;

        if was_enabled {
            self.detach_program()?;
        }

        self.config = config;

        if was_enabled && self.config.enabled {
            self.load_and_attach_program()?;
        }

        Ok(())
    }

    fn config(&self) -> &IcmpFilterConfig {
        &self.config
    }
}

impl Drop for EbpfFilter {
    fn drop(&mut self) {
        if self.enabled {
            if let Err(e) = self.detach_program() {
                tracing::warn!("Failed to detach eBPF program on drop: {}", e);
            }
        }
    }
}
