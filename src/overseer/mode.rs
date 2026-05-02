use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpgradeMode {
    ReusePort,
    PortSwap { temp_port_offset: u16 },
}

impl UpgradeMode {
    pub fn name(&self) -> &'static str {
        match self {
            UpgradeMode::ReusePort => "SO_REUSEPORT",
            UpgradeMode::PortSwap { .. } => "Port Swap",
        }
    }

    pub fn requires_temp_ports(&self) -> bool {
        matches!(self, UpgradeMode::PortSwap { .. })
    }
}

impl Default for UpgradeMode {
    fn default() -> Self {
        detect_upgrade_mode()
    }
}

pub fn detect_upgrade_mode() -> UpgradeMode {
    if probe_reuseport_support() {
        UpgradeMode::ReusePort
    } else {
        UpgradeMode::PortSwap {
            temp_port_offset: 1000,
        }
    }
}

pub fn probe_reuseport_support() -> bool {
    use std::net::TcpListener;

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let listener1 = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(_) => return false,
    };

    let bound_addr = match listener1.local_addr() {
        Ok(a) => a,
        Err(_) => return false,
    };

    drop(listener1);

    TcpListener::bind(bound_addr).is_ok()
}

#[cfg(unix)]
pub fn is_kernel_version_at_least(major: u32, minor: u32) -> bool {
    use sysinfo::System;

    let release = System::kernel_version().unwrap_or_default();
    let parts: Vec<&str> = release.split('.').collect();
    if let (Some(maj), Some(min)) = (parts.first(), parts.get(1)) {
        let maj_num: u32 = maj.parse().unwrap_or(0);
        let min_num: u32 = min.split('-').next().unwrap_or("0").parse().unwrap_or(0);
        return maj_num > major || (maj_num == major && min_num >= minor);
    }
    false
}

#[cfg(not(unix))]
pub fn is_kernel_version_at_least(_major: u32, _minor: u32) -> bool {
    false
}
