#![allow(unused_variables, dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use bytes::BytesMut;
use tokio::sync::broadcast;

const TUN_MTU: usize = 1500;
const DEFAULT_TUN_QUEUE_SIZE: usize = 4096;

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub address: IpAddr,
    pub netmask: IpAddr,
    pub mtu: u16,
    pub up: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "wg0".to_string(),
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            netmask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
            mtu: 1420,
            up: true,
        }
    }
}

impl TunConfig {
    pub fn new(name: &str, address: IpAddr, netmask: IpAddr) -> Self {
        Self {
            name: name.to_string(),
            address,
            netmask,
            mtu: 1420,
            up: true,
        }
    }

    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }
}

pub struct TunPacket {
    data: BytesMut,
}

impl TunPacket {
    pub fn new(data: Vec<u8>) -> Self {
        let mut buf = BytesMut::with_capacity(data.len());
        buf.extend_from_slice(&data);
        Self { data: buf }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data.to_vec()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn protocol(&self) -> Option<TunProtocol> {
        if self.data.len() < 4 {
            return None;
        }

        let version = (self.data[0] >> 4) & 0x0F;
        match version {
            4 => Some(TunProtocol::IPv4),
            6 => Some(TunProtocol::IPv6),
            _ => None,
        }
    }

    pub fn src_addr(&self) -> Option<IpAddr> {
        if self.data.len() < 20 {
            return None;
        }

        let version = (self.data[0] >> 4) & 0x0F;
        match version {
            4 => {
                let octets = [self.data[12], self.data[13], self.data[14], self.data[15]];
                Some(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            6 if self.data.len() >= 40 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&self.data[8..24]);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }

    pub fn dst_addr(&self) -> Option<IpAddr> {
        if self.data.len() < 20 {
            return None;
        }

        let version = (self.data[0] >> 4) & 0x0F;
        match version {
            4 => {
                let octets = [self.data[16], self.data[17], self.data[18], self.data[19]];
                Some(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            6 if self.data.len() >= 40 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&self.data[24..40]);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunProtocol {
    IPv4,
    IPv6,
}

pub mod platform {
    use super::*;
    use std::io;

    pub struct AsyncTunDevice {
        name: String,
    }

    impl AsyncTunDevice {
        pub fn create(_config: TunConfig) -> Result<Self, io::Error> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN support requires platform-specific dependencies (not yet available)",
            ))
        }

        pub async fn create_async(_config: TunConfig) -> Result<Self, io::Error> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN support requires platform-specific dependencies (not yet available)",
            ))
        }

        pub fn name(&self) -> &str {
            &self.name
        }
    }

    pub struct TunInterface {
        name: String,
        config: TunConfig,
    }

    impl TunInterface {
        pub fn create(_config: TunConfig) -> Result<(Self, AsyncTunDevice), io::Error> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN support requires platform-specific dependencies (not yet available)",
            ))
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn config(&self) -> &TunConfig {
            &self.config
        }

        pub fn add_route(&self, _destination: &str) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN support requires platform-specific dependencies (not yet available)",
            ))
        }

        pub fn delete_route(&self, _destination: &str) -> io::Result<()> {
            Ok(())
        }

        pub fn shutdown(&self) {}

        pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
            let (_, rx) = broadcast::channel(1);
            rx
        }
    }

    pub struct TunReader;

    impl TunReader {
        pub fn new(_device: Arc<AsyncTunDevice>, _shutdown_rx: broadcast::Receiver<()>) -> Self {
            Self
        }

        pub async fn read_packet(&mut self) -> io::Result<Option<TunPacket>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN support requires platform-specific dependencies (not yet available)",
            ))
        }
    }

    pub struct TunWriter;

    impl TunWriter {
        pub fn new(_device: Arc<AsyncTunDevice>, _shutdown_rx: broadcast::Receiver<()>) -> Self {
            Self
        }

        pub async fn write_packet(&mut self, _packet: &TunPacket) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN support requires platform-specific dependencies (not yet available)",
            ))
        }
    }

    pub fn is_tun_available() -> bool {
        false
    }
}

pub use platform::{is_tun_available, AsyncTunDevice, TunInterface, TunReader, TunWriter};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_config_new() {
        let config = TunConfig::new(
            "custom_wg0",
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
        );

        assert_eq!(config.name, "custom_wg0");
        assert_eq!(config.mtu, 1420);
        assert!(config.up);
    }

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();

        assert_eq!(config.name, "wg0");
        assert_eq!(config.mtu, 1420);
        assert!(config.up);
    }

    #[test]
    fn test_tun_config_builder() {
        let config = TunConfig::new(
            "custom_wg0",
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
        )
        .with_mtu(1280);

        assert_eq!(config.name, "custom_wg0");
        assert_eq!(config.mtu, 1280);
    }

    #[test]
    fn test_tun_packet_new() {
        let data = vec![1, 2, 3, 4, 5];
        let packet = TunPacket::new(data.clone());

        assert_eq!(packet.len(), 5);
        assert!(!packet.is_empty());
        assert_eq!(packet.data(), &data);
    }

    #[test]
    fn test_tun_packet_into_vec() {
        let data = vec![1, 2, 3, 4, 5];
        let packet = TunPacket::new(data.clone());
        let vec = packet.into_vec();

        assert_eq!(vec, data);
    }

    #[test]
    fn test_tun_packet_protocol_ipv4() {
        let ipv4_data = vec![
            0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let packet = TunPacket::new(ipv4_data);

        assert_eq!(packet.protocol(), Some(TunProtocol::IPv4));
    }

    #[test]
    fn test_tun_packet_protocol_ipv6() {
        let mut ipv6_data = vec![0u8; 40];
        ipv6_data[0] = 0x60;

        let packet = TunPacket::new(ipv6_data);

        assert_eq!(packet.protocol(), Some(TunProtocol::IPv6));
    }

    #[test]
    fn test_tun_packet_src_addr_ipv4() {
        let mut data = vec![0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[192, 168, 1, 100]);
        data.extend_from_slice(&[10, 0, 0, 1]);

        let packet = TunPacket::new(data);
        let src = packet.src_addr().unwrap();

        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_tun_packet_dst_addr_ipv4() {
        let mut data = vec![0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[192, 168, 1, 100]);
        data.extend_from_slice(&[10, 0, 0, 1]);

        let packet = TunPacket::new(data);
        let dst = packet.dst_addr().unwrap();

        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }
}
