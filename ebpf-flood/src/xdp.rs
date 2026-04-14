use aya_ebpf::{bindings::xdp_action, helpers::bpf_ktime_get_ns, programs::XdpContext};
use aya_ebpf_macros::xdp;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::IpHdr;
use network_types::ip::Ipv4Hdr;
use network_types::ip::Ipv6Hdr;
use network_types::tcp::TcpHdr;

use crate::maps::{
    get_config, get_ipv4_key, get_ipv6_key, update_stats, FloodStats, Ipv4Key, Ipv6Key, SynCounter,
    CONFIG_KEY, GLOBAL_COUNTER, STATS, SYN_COUNTS_V4, SYN_COUNTS_V6,
};

const TCP_SYN: u8 = 0x02;
const NSEC_PER_SEC: u64 = 1_000_000_000;

#[inline(always)]
fn xdp_pass() -> u32 {
    xdp_action::XDP_PASS
}

#[inline(always)]
fn xdp_drop() -> u32 {
    xdp_action::XDP_DROP
}

#[inline(always)]
fn get_syn_key_and_src(ctx: &XdpContext) -> Option<(bool, u32, [u8; 16])> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + core::mem::size_of::<EthHdr>() > data_end {
        return None;
    }

    let eth_hdr: *const EthHdr = data as *const EthHdr;
    if eth_hdr.is_null() {
        return None;
    }

    let eth = unsafe { *eth_hdr };
    let ether_type = match eth.ether_type() {
        Ok(et) => et,
        Err(_) => return None,
    };

    if ether_type != EtherType::Ipv4 && ether_type != EtherType::Ipv6 {
        return None;
    }

    let is_ipv4 = matches!(ether_type, EtherType::Ipv4);

    let ip_offset = core::mem::size_of::<EthHdr>();
    if data + ip_offset + core::mem::size_of::<IpHdr>() > data_end {
        return None;
    }

    let ip_hdr: *const IpHdr = (data + ip_offset) as *const IpHdr;
    if ip_hdr.is_null() {
        return None;
    }

    let src_port: u16;
    let mut src_addr_ipv4: u32 = 0;
    let mut src_addr_ipv6: [u8; 16] = [0; 16];

    if is_ipv4 {
        let ipv4_offset = ip_offset + core::mem::size_of::<IpHdr>();
        if data + ipv4_offset + core::mem::size_of::<Ipv4Hdr>() > data_end {
            return None;
        }
        let ipv4 = unsafe {
            *((ip_hdr as *const u8).add(core::mem::size_of::<IpHdr>()) as *const Ipv4Hdr)
        };
        src_addr_ipv4 = u32::from(ipv4.src_addr());
    } else {
        let ipv6_offset = ip_offset + core::mem::size_of::<IpHdr>();
        if data + ipv6_offset + core::mem::size_of::<Ipv6Hdr>() > data_end {
            return None;
        }
        let ipv6 = unsafe {
            *((ip_hdr as *const u8).add(core::mem::size_of::<IpHdr>()) as *const Ipv6Hdr)
        };
        src_addr_ipv6 = ipv6.src_addr().octets();
    }

    let tcp_offset = if is_ipv4 {
        ip_offset + core::mem::size_of::<Ipv4Hdr>()
    } else {
        ip_offset + core::mem::size_of::<Ipv6Hdr>()
    };

    if data + tcp_offset + core::mem::size_of::<TcpHdr>() > data_end {
        return None;
    }

    let tcp_hdr: *const TcpHdr = (data + tcp_offset) as *const TcpHdr;
    if tcp_hdr.is_null() {
        return None;
    }

    let tcp = unsafe { *tcp_hdr };
    src_port = u16::from_be_bytes(tcp.source);
    let flags = tcp.syn() as u8;

    if (flags & TCP_SYN) == 0 {
        return None;
    }

    if is_ipv4 {
        Some((true, src_addr_ipv4, [0; 16]))
    } else {
        Some((false, 0, src_addr_ipv6))
    }
}

#[inline(always)]
fn get_current_time_ns() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

#[inline(always)]
fn rotate_window_if_needed(counter: &mut SynCounter, now_ns: u64, window_ns: u64) {
    if now_ns - counter.window_start >= window_ns {
        counter.count = 0;
        counter.window_start = now_ns;
    }
}

#[xdp]
pub fn filter_syn(ctx: XdpContext) -> u32 {
    let config = match get_config() {
        Some(c) => c,
        None => return xdp_pass(),
    };

    if config.enabled == 0 {
        return xdp_pass();
    }

    let (is_ipv4, src_ipv4, src_ipv6) = match get_syn_key_and_src(&ctx) {
        Some(v) => v,
        None => return xdp_pass(),
    };

    update_stats(|s| s.syn_seen += 1);

    let now_ns = get_current_time_ns();
    let window_ns = (config.window_size_secs as u64) * NSEC_PER_SEC;

    if let Some(global) = GLOBAL_COUNTER.get_ptr_mut(0) {
        let global = unsafe { &mut *global };
        if now_ns - global.window_start_ns >= window_ns {
            global.global_count = 0;
            global.window_start_ns = now_ns;
        }

        global.global_count += 1;

        if global.global_count > config.global_rate_pps {
            update_stats(|s| s.syn_dropped_global_rate += 1);
            return xdp_drop();
        }
    } else {
        return xdp_pass();
    }

    if is_ipv4 {
        let key = get_ipv4_key(src_ipv4);
        let mut entry = unsafe {
            SYN_COUNTS_V4.get(&key).copied().unwrap_or(SynCounter {
                count: 0,
                window_start: now_ns,
            })
        };

        rotate_window_if_needed(&mut entry, now_ns, window_ns);

        entry.count += 1;

        if entry.count > config.per_ip_rate_pps {
            update_stats(|s| s.syn_dropped_per_ip_rate += 1);
            return xdp_drop();
        }

        let _ = SYN_COUNTS_V4.insert(&key, &entry, 0);
    } else {
        let key = get_ipv6_key(src_ipv6);
        let mut entry = unsafe {
            SYN_COUNTS_V6.get(&key).copied().unwrap_or(SynCounter {
                count: 0,
                window_start: now_ns,
            })
        };

        rotate_window_if_needed(&mut entry, now_ns, window_ns);

        entry.count += 1;

        if entry.count > config.per_ip_rate_pps {
            update_stats(|s| s.syn_dropped_per_ip_rate += 1);
            return xdp_drop();
        }

        let _ = SYN_COUNTS_V6.insert(&key, &entry, 0);
    }

    update_stats(|s| s.packets_passed += 1);
    xdp_pass()
}
