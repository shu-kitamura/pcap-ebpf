#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use pcap_common::{PacketInfo, Protocol};

#[map]
static EVENTS: PerfEventArray<PacketInfo> = PerfEventArray::<PacketInfo>::new(0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start: usize = ctx.data();
    let end: usize = ctx.data_end();
    let len: usize = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[xdp]
pub fn pcap(ctx: XdpContext) -> u32 {
    match try_pcap(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_pcap(ctx: XdpContext) -> Result<u32, ()> {
    let mut cursor: usize = 0;

    // eth -> ip
    let ethhdr: *const EthHdr = ptr_at(&ctx, cursor)?;
    cursor += EthHdr::LEN;
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // get IP address.
    let iphdr: *const Ipv4Hdr = ptr_at(&ctx, cursor)?;
    cursor += Ipv4Hdr::LEN;
    let src_addr: u32 = u32::from_be(unsafe { (*iphdr).src_addr });
    let dst_addr: u32 = u32::from_be(unsafe { (*iphdr).dst_addr });

    // ip -> tcp/udp
    let (src_port, dst_port, proto) = match unsafe { (*iphdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, cursor)?;
            let source = u16::from_be(unsafe { (*tcphdr).source });
            let dest = u16::from_be(unsafe { (*tcphdr).dest });
            (source, dest, Protocol::TCP)
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, cursor)?;
            let source = u16::from_be(unsafe { (*udphdr).source });
            let dest = u16::from_be(unsafe { (*udphdr).dest });
            (source, dest, Protocol::UDP)
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let packet_info = PacketInfo::new(src_addr, dst_addr, src_port, dst_port, proto);
    EVENTS.output(&ctx, &packet_info, 0);

    Ok(xdp_action::XDP_PASS)
}
