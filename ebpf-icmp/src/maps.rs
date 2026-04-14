use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use aya_ebpf_macros::map;

/// eBPF maps for ICMP filtering.
/// # Safety
/// Map access is safe as long as the map is properly initialized before use.

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
pub struct IcmpTypeRule {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub action: u8,
}

impl IcmpTypeRule {
    pub const ACTION_BLOCK: u8 = 1;
    pub const CODE_WILDCARD: u8 = 255;
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
pub struct TokenBucketState {
    pub tokens: u64,
    pub last_update_ns: u64,
}

#[map]
pub static CONFIG_MAP: Array<Config> = Array::with_max_entries(1, 0);

#[map]
pub static EXEMPT_IPV4: HashMap<Ipv4Key, u8> = HashMap::with_max_entries(1024, 0);

#[map]
pub static EXEMPT_IPV6: HashMap<Ipv6Key, u8> = HashMap::with_max_entries(1024, 0);

#[map]
pub static STATS_INBOUND: PerCpuArray<IcmpStats> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static STATS_OUTBOUND: PerCpuArray<IcmpStats> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static TOKEN_BUCKET_INBOUND: PerCpuArray<TokenBucketState> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
pub static TOKEN_BUCKET_OUTBOUND: PerCpuArray<TokenBucketState> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
pub static ICMP_TYPE_RULES_V4: Array<IcmpTypeRule> = Array::with_max_entries(MAX_TYPE_RULES, 0);

#[map]
pub static ICMP_TYPE_RULES_V6: Array<IcmpTypeRule> = Array::with_max_entries(MAX_TYPE_RULES, 0);

#[inline(always)]
pub fn get_config() -> Option<Config> {
    CONFIG_MAP.get(CONFIG_KEY).copied()
}

#[inline(always)]
pub fn update_stats_inbound(f: impl FnOnce(&mut IcmpStats)) {
    if let Some(ptr) = STATS_INBOUND.get_ptr_mut(0) {
        unsafe { f(&mut *ptr) };
    }
}

#[inline(always)]
pub fn update_stats_outbound(f: impl FnOnce(&mut IcmpStats)) {
    if let Some(ptr) = STATS_OUTBOUND.get_ptr_mut(0) {
        unsafe { f(&mut *ptr) };
    }
}

#[inline(always)]
pub fn is_exempt_ipv4(addr: u32) -> bool {
    let key = Ipv4Key { addr };
    unsafe { EXEMPT_IPV4.get(&key).is_some() }
}

#[inline(always)]
pub fn is_exempt_ipv6(addr: [u8; 16]) -> bool {
    let key = Ipv6Key { addr };
    unsafe { EXEMPT_IPV6.get(&key).is_some() }
}

#[inline(always)]
pub fn is_exempt_ipv4_dst(addr: u32) -> bool {
    is_exempt_ipv4(addr)
}

#[inline(always)]
pub fn is_exempt_ipv6_dst(addr: [u8; 16]) -> bool {
    is_exempt_ipv6(addr)
}

#[inline(always)]
pub fn check_icmp_type_rule_v4(icmp_type: u8, icmp_code: u8) -> Option<bool> {
    check_icmp_type_rule_impl(&ICMP_TYPE_RULES_V4, icmp_type, icmp_code)
}

#[inline(always)]
pub fn check_icmp_type_rule_v6(icmp_type: u8, icmp_code: u8) -> Option<bool> {
    check_icmp_type_rule_impl(&ICMP_TYPE_RULES_V6, icmp_type, icmp_code)
}

#[inline(always)]
fn check_icmp_type_rule_impl(
    rules_map: &Array<IcmpTypeRule>,
    icmp_type: u8,
    icmp_code: u8,
) -> Option<bool> {
    let mut i: u32 = 0;
    while i < MAX_TYPE_RULES as u32 {
        if let Some(rule) = rules_map.get(i) {
            let r = *rule;
            if r.icmp_type == 0 && r.icmp_code == 0 && r.action == 0 {
                break;
            }
            let type_matches = r.icmp_type == icmp_type;
            let code_matches =
                r.icmp_code == IcmpTypeRule::CODE_WILDCARD || r.icmp_code == icmp_code;
            if type_matches && code_matches {
                return Some(r.action == IcmpTypeRule::ACTION_BLOCK);
            }
        }
        i += 1;
    }
    None
}
