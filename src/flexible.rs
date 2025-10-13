use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use nix::sys::socket::{SockaddrIn, SockaddrIn6, SockaddrLike};

#[derive(Debug, Clone)]
pub enum FlexibleIp {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl From<IpAddr> for FlexibleIp {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(v4) => FlexibleIp::Ipv4(v4),
            IpAddr::V6(v6) => FlexibleIp::Ipv6(v6),
        }
    }
}

impl From<FlexibleIp> for IpAddr {
    fn from(value: FlexibleIp) -> Self {
        match value {
            FlexibleIp::Ipv4(v4) => IpAddr::V4(v4),
            FlexibleIp::Ipv6(v6) => IpAddr::V6(v6),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlexibleAddr {
    pub ip: FlexibleIp,
    pub port: u16,
}

impl<'a> From<FlexibleAddr> for Box<dyn SockaddrLike + 'a> {
    fn from(value: FlexibleAddr) -> Box<dyn SockaddrLike + 'a> {
        match value.ip {
            FlexibleIp::Ipv4(v4) => Box::new(SockaddrIn::from(SocketAddrV4::new(v4, value.port))),
            FlexibleIp::Ipv6(v6) => Box::new(SockaddrIn6::from(SocketAddrV6::new(v6, value.port, 0, 0))),
        }
    }
}

impl From<FlexibleAddr> for SocketAddr {
    fn from(value: FlexibleAddr) -> Self {
        match value.ip {
            FlexibleIp::Ipv4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, value.port)),
            FlexibleIp::Ipv6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, value.port, 0, 0)),
        }
    }
}