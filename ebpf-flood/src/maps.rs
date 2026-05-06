use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use aya_ebpf_macros::map;

/// eBPF maps for SYN flood protection.
/// # Safety
/// Map access is safe as long as the map is properly initialized before use.

pub const CONFIG_KEY: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy, Default)]
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
#[derive(Clone, Copy, Default)]
pub struct FloodStats {
    pub syn_seen: u64,
    pub syn_dropped_global_rate: u64,
    pub syn_dropped_per_ip_rate: u64,
    pub half_open_exceeded: u64,
    pub connections_tracked: u64,
    pub packets_passed: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SynCounter {
    pub count: u32,
    pub window_start: u64,
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
pub struct WindowState {
    pub global_count: u32,
    pub window_start_ns: u64,
}

#[map]
pub static CONFIG_MAP: Array<FloodConfig> = Array::with_max_entries(1, 0);

#[map]
pub static GLOBAL_COUNTER: PerCpuArray<WindowState> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static SYN_COUNTS_V4: HashMap<Ipv4Key, SynCounter> = HashMap::with_max_entries(65536, 0);

#[map]
pub static SYN_COUNTS_V6: HashMap<Ipv6Key, SynCounter> = HashMap::with_max_entries(16384, 0);

#[map]
pub static IP_BLOCKLIST_V4: HashMap<Ipv4Key, u8> = HashMap::with_max_entries(65536, 0);

#[map]
pub static IP_BLOCKLIST_V6: HashMap<Ipv6Key, u8> = HashMap::with_max_entries(16384, 0);

#[map]
pub static STATS: PerCpuArray<FloodStats> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
pub fn get_config() -> Option<FloodConfig> {
    CONFIG_MAP.get(CONFIG_KEY).copied()
}

#[inline(always)]
pub fn update_stats(f: impl FnOnce(&mut FloodStats)) {
    if let Some(ptr) = STATS.get_ptr_mut(0) {
        unsafe { f(&mut *ptr) };
    }
}

#[inline(always)]
pub fn get_ipv4_key(addr: u32) -> Ipv4Key {
    Ipv4Key { addr }
}

#[inline(always)]
pub fn get_ipv6_key(addr: [u8; 16]) -> Ipv6Key {
    Ipv6Key { addr }
}
