use aya_ebpf::programs::TcContext;
use aya_ebpf_macros::classifier;

use crate::icmp::{parse_icmp_packet_tc, PacketInfo};
use crate::maps::{
    check_icmp_type_rule_v4, check_icmp_type_rule_v6, get_config, is_exempt_ipv4_dst,
    is_exempt_ipv6_dst, update_stats_outbound, Config,
};
use crate::token_bucket::try_consume_outbound;

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

#[classifier]
pub fn filter_outbound(ctx: TcContext) -> i32 {
    let config = match get_config() {
        Some(c) => c,
        None => return TC_ACT_OK,
    };

    if config.enabled == 0 || config.filter_outbound == 0 {
        return TC_ACT_OK;
    }

    let packet_info = parse_icmp_packet_tc(&ctx);

    match packet_info {
        PacketInfo::IcmpV4 {
            src_addr: _,
            dst_addr,
            icmp_type,
            icmp_code,
        } => process_outbound_icmpv4(dst_addr, icmp_type, icmp_code, &config),
        PacketInfo::IcmpV6 {
            src_addr: _,
            dst_addr,
            icmp_type,
            icmp_code,
        } => process_outbound_icmpv6(dst_addr, icmp_type, icmp_code, &config),
        PacketInfo::NotIcmp => TC_ACT_OK,
    }
}

#[inline(always)]
fn process_outbound_icmpv4(dst_addr: u32, icmp_type: u8, icmp_code: u8, config: &Config) -> i32 {
    update_stats_outbound(|s| s.packets_seen += 1);

    if is_exempt_ipv4_dst(dst_addr) {
        update_stats_outbound(|s| s.exempt_passed += 1);
        return TC_ACT_OK;
    }

    if let Some(should_block) = check_icmp_type_rule_v4(icmp_type, icmp_code) {
        if should_block {
            update_stats_outbound(|s| {
                s.packets_dropped += 1;
                s.type_rule_blocked += 1;
            });
            return TC_ACT_SHOT;
        } else {
            return TC_ACT_OK;
        }
    }

    if config.block_all_icmp == 0 {
        return TC_ACT_OK;
    }

    if config.rate_limit_enabled != 0 {
        if !try_consume_outbound(config.packets_per_second, config.burst) {
            update_stats_outbound(|s| {
                s.packets_dropped += 1;
                s.rate_limited += 1;
            });
            return TC_ACT_SHOT;
        }
    } else {
        update_stats_outbound(|s| s.packets_dropped += 1);
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

#[inline(always)]
fn process_outbound_icmpv6(
    dst_addr: [u8; 16],
    icmp_type: u8,
    icmp_code: u8,
    config: &Config,
) -> i32 {
    update_stats_outbound(|s| s.packets_seen += 1);

    if is_exempt_ipv6_dst(dst_addr) {
        update_stats_outbound(|s| s.exempt_passed += 1);
        return TC_ACT_OK;
    }

    if let Some(should_block) = check_icmp_type_rule_v6(icmp_type, icmp_code) {
        if should_block {
            update_stats_outbound(|s| {
                s.packets_dropped += 1;
                s.type_rule_blocked += 1;
            });
            return TC_ACT_SHOT;
        } else {
            return TC_ACT_OK;
        }
    }

    if config.block_all_icmp == 0 {
        return TC_ACT_OK;
    }

    if config.rate_limit_enabled != 0 {
        if !try_consume_outbound(config.packets_per_second, config.burst) {
            update_stats_outbound(|s| {
                s.packets_dropped += 1;
                s.rate_limited += 1;
            });
            return TC_ACT_SHOT;
        }
    } else {
        update_stats_outbound(|s| s.packets_dropped += 1);
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}
