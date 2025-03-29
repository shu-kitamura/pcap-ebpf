#![no_std]

use core::{fmt, net::Ipv4Addr};

#[derive(Copy, Clone)]
pub enum Protocol {
    TCP,
    UDP,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PacketInfo {
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    protocol: Protocol,
}

impl PacketInfo {
    pub fn new(
        src_addr: u32,
        dst_addr: u32,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Self {
        PacketInfo {
            src_addr: Ipv4Addr::from(src_addr),
            dst_addr: Ipv4Addr::from(dst_addr),
            src_port,
            dst_port,
            protocol,
        }
    }
}

impl fmt::Display for PacketInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}",
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            match self.protocol {
                Protocol::TCP => "TCP",
                Protocol::UDP => "UDP",
            }
        )
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketInfo {}
