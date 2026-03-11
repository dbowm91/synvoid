use aya_ebpf::programs::{TcContext, XdpContext};
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};

/// eBPF ICMP packet parsing.
/// # Safety
/// All packet parsing in this module uses raw pointer dereferences. The safety invariant is that
/// we always check bounds against `data_end` before dereferencing pointers, ensuring we don't
/// access memory outside the packet buffer.

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;

#[repr(C)]
pub struct IcmpHdr {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_checksum: u16,
}

pub enum PacketInfo {
    IcmpV4 {
        src_addr: u32,
        dst_addr: u32,
        icmp_type: u8,
        icmp_code: u8,
    },
    IcmpV6 {
        src_addr: [u8; 16],
        dst_addr: [u8; 16],
        icmp_type: u8,
        icmp_code: u8,
    },
    NotIcmp,
}

#[inline(always)]
pub fn parse_icmp_packet_xdp(ctx: &XdpContext) -> PacketInfo {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let eth_hdr = data as *const EthHdr;
    if unsafe { eth_hdr.add(1) } as usize > data_end {
        return PacketInfo::NotIcmp;
    }

    match u16::from_be(unsafe { (*eth_hdr).ether_type }) {
        ETH_P_IP => parse_icmpv4_xdp(ctx),
        ETH_P_IPV6 => parse_icmpv6_xdp(ctx),
        _ => PacketInfo::NotIcmp,
    }
}

#[inline(always)]
fn parse_icmpv4_xdp(ctx: &XdpContext) -> PacketInfo {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let offset = EthHdr::LEN;

    let ipv4_hdr = unsafe { (data as *const u8).add(offset) as *const Ipv4Hdr };
    if unsafe { ipv4_hdr.add(1) } as usize > data_end {
        return PacketInfo::NotIcmp;
    }

    let protocol = unsafe { (*ipv4_hdr).proto };
    if protocol != IpProto::Icmp {
        return PacketInfo::NotIcmp;
    }

    let src_addr = unsafe { (*ipv4_hdr).src_addr().into() };
    let dst_addr = unsafe { (*ipv4_hdr).dst_addr().into() };

    let icmp_offset = offset + Ipv4Hdr::LEN;
    let icmp_hdr_ptr = unsafe { (data as *const u8).add(icmp_offset) as *const IcmpHdr };
    if unsafe { icmp_hdr_ptr.add(1) } as usize > data_end {
        return PacketInfo::NotIcmp;
    }

    let icmp_type = unsafe { (*icmp_hdr_ptr).icmp_type };
    let icmp_code = unsafe { (*icmp_hdr_ptr).icmp_code };

    PacketInfo::IcmpV4 {
        src_addr,
        dst_addr,
        icmp_type,
        icmp_code,
    }
}

#[inline(always)]
fn parse_icmpv6_xdp(ctx: &XdpContext) -> PacketInfo {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let offset = EthHdr::LEN;

    let ipv6_hdr = unsafe { (data as *const u8).add(offset) as *const Ipv6Hdr };
    if unsafe { ipv6_hdr.add(1) } as usize > data_end {
        return PacketInfo::NotIcmp;
    }

    let next_hdr = unsafe { (*ipv6_hdr).next_hdr };
    if next_hdr != IpProto::Ipv6Icmp {
        return PacketInfo::NotIcmp;
    }

    let mut src_addr = [0u8; 16];
    let src = unsafe { (*ipv6_hdr).src_addr() };
    src_addr.copy_from_slice(&src.octets());

    let mut dst_addr = [0u8; 16];
    let dst = unsafe { (*ipv6_hdr).dst_addr() };
    dst_addr.copy_from_slice(&dst.octets());

    let icmp_offset = offset + Ipv6Hdr::LEN;
    let icmp_hdr_ptr = unsafe { (data as *const u8).add(icmp_offset) as *const IcmpHdr };
    if unsafe { icmp_hdr_ptr.add(1) } as usize > data_end {
        return PacketInfo::NotIcmp;
    }

    let icmp_type = unsafe { (*icmp_hdr_ptr).icmp_type };
    let icmp_code = unsafe { (*icmp_hdr_ptr).icmp_code };

    PacketInfo::IcmpV6 {
        src_addr,
        dst_addr,
        icmp_type,
        icmp_code,
    }
}

#[inline(always)]
pub fn parse_icmp_packet_tc(ctx: &TcContext) -> PacketInfo {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + EthHdr::LEN > data_end {
        return PacketInfo::NotIcmp;
    }

    let eth_hdr = data as *const EthHdr;
    let eth_type = unsafe { u16::from_be((*eth_hdr).ether_type) };

    match eth_type {
        ETH_P_IP => parse_icmpv4_tc(ctx),
        ETH_P_IPV6 => parse_icmpv6_tc(ctx),
        _ => PacketInfo::NotIcmp,
    }
}

#[inline(always)]
fn parse_icmpv4_tc(ctx: &TcContext) -> PacketInfo {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let offset = EthHdr::LEN;

    let ipv4_hdr = unsafe { (data as *const u8).add(offset) as *const Ipv4Hdr };
    if (ipv4_hdr as usize) + core::mem::size_of::<Ipv4Hdr>() > data_end {
        return PacketInfo::NotIcmp;
    }

    let protocol = unsafe { (*ipv4_hdr).proto };
    if protocol != IpProto::Icmp {
        return PacketInfo::NotIcmp;
    }

    let src_addr = unsafe { (*ipv4_hdr).src_addr().into() };
    let dst_addr = unsafe { (*ipv4_hdr).dst_addr().into() };

    let icmp_offset = offset + Ipv4Hdr::LEN;
    let icmp_hdr_ptr = unsafe { (data as *const u8).add(icmp_offset) as *const IcmpHdr };
    if (icmp_hdr_ptr as usize) + core::mem::size_of::<IcmpHdr>() > data_end {
        return PacketInfo::NotIcmp;
    }

    let icmp_type = unsafe { (*icmp_hdr_ptr).icmp_type };
    let icmp_code = unsafe { (*icmp_hdr_ptr).icmp_code };

    PacketInfo::IcmpV4 {
        src_addr,
        dst_addr,
        icmp_type,
        icmp_code,
    }
}

#[inline(always)]
fn parse_icmpv6_tc(ctx: &TcContext) -> PacketInfo {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let offset = EthHdr::LEN;

    let ipv6_hdr = unsafe { (data as *const u8).add(offset) as *const Ipv6Hdr };
    if (ipv6_hdr as usize) + core::mem::size_of::<Ipv6Hdr>() > data_end {
        return PacketInfo::NotIcmp;
    }

    let next_hdr = unsafe { (*ipv6_hdr).next_hdr };
    if next_hdr != IpProto::Ipv6Icmp {
        return PacketInfo::NotIcmp;
    }

    let mut src_addr = [0u8; 16];
    let src = unsafe { (*ipv6_hdr).src_addr() };
    src_addr.copy_from_slice(&src.octets());

    let mut dst_addr = [0u8; 16];
    let dst = unsafe { (*ipv6_hdr).dst_addr() };
    dst_addr.copy_from_slice(&dst.octets());

    let icmp_offset = offset + Ipv6Hdr::LEN;
    let icmp_hdr_ptr = unsafe { (data as *const u8).add(icmp_offset) as *const IcmpHdr };
    if (icmp_hdr_ptr as usize) + core::mem::size_of::<IcmpHdr>() > data_end {
        return PacketInfo::NotIcmp;
    }

    let icmp_type = unsafe { (*icmp_hdr_ptr).icmp_type };
    let icmp_code = unsafe { (*icmp_hdr_ptr).icmp_code };

    PacketInfo::IcmpV6 {
        src_addr,
        dst_addr,
        icmp_type,
        icmp_code,
    }
}
