use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_ebpf_macros::xdp;

use crate::icmp::{parse_icmp_packet_xdp, PacketInfo};
use crate::maps::{
    check_icmp_type_rule_v4, check_icmp_type_rule_v6, get_config, is_exempt_ipv4, is_exempt_ipv6,
    update_stats_inbound, Config,
};
use crate::token_bucket::try_consume_inbound;

#[inline(always)]
fn xdp_pass() -> u32 {
    xdp_action::XDP_PASS
}

#[inline(always)]
fn xdp_drop() -> u32 {
    xdp_action::XDP_DROP
}

#[xdp]
pub fn filter_inbound(ctx: XdpContext) -> u32 {
    let config = match get_config() {
        Some(c) => c,
        None => return xdp_pass(),
    };

    if config.enabled == 0 || config.filter_inbound == 0 {
        return xdp_pass();
    }

    let packet_info = parse_icmp_packet_xdp(&ctx);

    match packet_info {
        PacketInfo::IcmpV4 {
            src_addr,
            dst_addr: _,
            icmp_type,
            icmp_code,
        } => process_inbound_icmpv4(src_addr, icmp_type, icmp_code, &config),
        PacketInfo::IcmpV6 {
            src_addr,
            dst_addr: _,
            icmp_type,
            icmp_code,
        } => process_inbound_icmpv6(src_addr, icmp_type, icmp_code, &config),
        PacketInfo::NotIcmp => xdp_pass(),
    }
}

#[inline(always)]
fn process_inbound_icmpv4(src_addr: u32, icmp_type: u8, icmp_code: u8, config: &Config) -> u32 {
    update_stats_inbound(|s| s.packets_seen += 1);

    if is_exempt_ipv4(src_addr) {
        update_stats_inbound(|s| s.exempt_passed += 1);
        return xdp_pass();
    }

    if let Some(should_block) = check_icmp_type_rule_v4(icmp_type, icmp_code) {
        if should_block {
            update_stats_inbound(|s| {
                s.packets_dropped += 1;
                s.type_rule_blocked += 1;
            });
            return xdp_drop();
        } else {
            return xdp_pass();
        }
    }

    if config.block_all_icmp == 0 {
        return xdp_pass();
    }

    if config.rate_limit_enabled != 0 {
        if !try_consume_inbound(config.packets_per_second, config.burst) {
            update_stats_inbound(|s| {
                s.packets_dropped += 1;
                s.rate_limited += 1;
            });
            return xdp_drop();
        }
    } else {
        update_stats_inbound(|s| s.packets_dropped += 1);
        return xdp_drop();
    }

    xdp_pass()
}

#[inline(always)]
fn process_inbound_icmpv6(
    src_addr: [u8; 16],
    icmp_type: u8,
    icmp_code: u8,
    config: &Config,
) -> u32 {
    update_stats_inbound(|s| s.packets_seen += 1);

    if is_exempt_ipv6(src_addr) {
        update_stats_inbound(|s| s.exempt_passed += 1);
        return xdp_pass();
    }

    if let Some(should_block) = check_icmp_type_rule_v6(icmp_type, icmp_code) {
        if should_block {
            update_stats_inbound(|s| {
                s.packets_dropped += 1;
                s.type_rule_blocked += 1;
            });
            return xdp_drop();
        } else {
            return xdp_pass();
        }
    }

    if config.block_all_icmp == 0 {
        return xdp_pass();
    }

    if config.rate_limit_enabled != 0 {
        if !try_consume_inbound(config.packets_per_second, config.burst) {
            update_stats_inbound(|s| {
                s.packets_dropped += 1;
                s.rate_limited += 1;
            });
            return xdp_drop();
        }
    } else {
        update_stats_inbound(|s| s.packets_dropped += 1);
        return xdp_drop();
    }

    xdp_pass()
}
