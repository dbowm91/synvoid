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

#[cfg(feature = "tun-rs")]
pub mod platform {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use pin_project_lite::pin_project;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tun_rs::{Device, DeviceBuilder, TunReader, TunWriter};

    pin_project! {
        pub struct AsyncTunDevice {
            device: Device,
            name: String,
        }
    }

    impl AsyncTunDevice {
        pub fn create(config: TunConfig) -> Result<Self, io::Error> {
            let mut builder = DeviceBuilder::new();

            builder.name(&config.name);

            match config.address {
                IpAddr::V4(addr) => {
                    let prefix_len = Self::netmask_to_prefix_len(config.netmask);
                    builder.ipv4(addr, prefix_len, None);
                }
                IpAddr::V6(addr) => {
                    let prefix_len = Self::netmask_to_prefix_len(config.netmask);
                    builder.ipv6(addr, prefix_len, None);
                }
            }

            builder.mtu(config.mtu);

            if config.up {
                builder.up(true);
            }

            let device = builder.build_sync()?;

            let name = device.name().to_string();

            tracing::info!("Created TUN interface: {} (mtu: {})", name, config.mtu);

            Ok(Self { device, name })
        }

        pub async fn create_async(config: TunConfig) -> Result<Self, io::Error> {
            let mut builder = DeviceBuilder::new();

            builder.name(&config.name);

            match config.address {
                IpAddr::V4(addr) => {
                    let prefix_len = Self::netmask_to_prefix_len(config.netmask);
                    builder.ipv4(addr, prefix_len, None);
                }
                IpAddr::V6(addr) => {
                    let prefix_len = Self::netmask_to_prefix_len(config.netmask);
                    builder.ipv6(addr, prefix_len, None);
                }
            }

            builder.mtu(config.mtu);

            if config.up {
                builder.up(true);
            }

            let device = builder.build_async().await?;

            let name = device.name().to_string();

            tracing::info!(
                "Created async TUN interface: {} (mtu: {})",
                name,
                config.mtu
            );

            Ok(Self { device, name })
        }

        fn netmask_to_prefix_len(netmask: IpAddr) -> u8 {
            match netmask {
                IpAddr::V4(ipv4) => {
                    let bits = ipv4.octets();
                    bits.iter()
                        .fold(0u8, |acc, &octet| acc + octet.count_ones() as u8)
                }
                IpAddr::V6(ipv6) => {
                    let bits = ipv6.segments();
                    bits.iter()
                        .fold(0u8, |acc, &seg| acc + seg.count_ones() as u8)
                }
            }
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn reader(&self) -> TunReader {
            self.device.reader()
        }

        pub fn writer(&self) -> TunWriter {
            self.device.writer()
        }
    }

    impl AsyncRead for AsyncTunDevice {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.project();
            this.device.poll_read_packet(cx, buf)
        }
    }

    impl AsyncWrite for AsyncTunDevice {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.project();
            this.device.poll_write_packet(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.project();
            this.device.poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.project();
            this.device.poll_shutdown(cx)
        }
    }

    impl Drop for AsyncTunDevice {
        fn drop(&mut self) {
            tracing::debug!("TUN interface {} being dropped", self.name);
        }
    }

    pub struct TunInterface {
        name: String,
        config: TunConfig,
        shutdown_tx: broadcast::Sender<()>,
    }

    impl TunInterface {
        pub fn create(config: TunConfig) -> Result<(Self, AsyncTunDevice), io::Error> {
            let (shutdown_tx, _) = broadcast::channel(1);

            let device = AsyncTunDevice::create(config.clone())?;
            let name = device.name().to_string();

            let interface = Self {
                name: name.clone(),
                config,
                shutdown_tx,
            };

            tracing::info!("Created TUN interface: {}", name);

            Ok((interface, device))
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn config(&self) -> &TunConfig {
            &self.config
        }

        pub fn add_route(&self, destination: &str) -> io::Result<()> {
            #[cfg(target_os = "linux")]
            {
                let output = std::process::Command::new("ip")
                    .args(["route", "add", destination])
                    .output()?;

                if !output.status.success() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "ip route add failed: {}",
                            String::from_utf8_lossy(&output.stderr)
                        ),
                    ));
                }
                Ok(())
            }

            #[cfg(target_os = "macos")]
            {
                let output = std::process::Command::new("route")
                    .args(["-n", "add", "-net", destination, "-interface", &self.name])
                    .output()?;

                if !output.status.success() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "route add failed: {}",
                            String::from_utf8_lossy(&output.stderr)
                        ),
                    ));
                }
                Ok(())
            }

            #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
            {
                let output = std::process::Command::new("route")
                    .args(["add", "-net", destination, "-interface", &self.name])
                    .output()?;

                if !output.status.success() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "route add failed: {}",
                            String::from_utf8_lossy(&output.stderr)
                        ),
                    ));
                }
                Ok(())
            }

            #[cfg(target_os = "windows")]
            {
                let _ = destination;
                tracing::warn!("Route addition not implemented for Windows");
                Ok(())
            }
        }

        pub fn delete_route(&self, destination: &str) -> io::Result<()> {
            #[cfg(target_os = "linux")]
            {
                let output = std::process::Command::new("ip")
                    .args(["route", "del", destination])
                    .output()?;

                if !output.status.success() {
                    tracing::warn!(
                        "ip route del failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Ok(())
            }

            #[cfg(not(target_os = "linux"))]
            {
                let _ = (self, destination);
                Ok(())
            }
        }

        pub fn shutdown(&self) {
            let _ = self.shutdown_tx.send(());
        }

        pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
            self.shutdown_tx.subscribe()
        }
    }

    impl Drop for TunInterface {
        fn drop(&mut self) {
            tracing::debug!("TUN interface {} being destroyed", self.name);
        }
    }

    pub struct TunReader {
        device: Arc<AsyncTunDevice>,
        shutdown_rx: broadcast::Receiver<()>,
    }

    impl TunReader {
        pub fn new(device: Arc<AsyncTunDevice>, shutdown_rx: broadcast::Receiver<()>) -> Self {
            Self {
                device,
                shutdown_rx,
            }
        }

        pub async fn read_packet(&mut self) -> io::Result<Option<TunPacket>> {
            let mut buf = vec![0u8; TUN_MTU];

            tokio::select! {
                result = self.device.reader().read_packet(&mut buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            buf.truncate(n);
                            Ok(Some(TunPacket::new(buf)))
                        }
                        Ok(_) => Ok(None),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
                        Err(e) => Err(e),
                    }
                }
                _ = self.shutdown_rx.recv() => {
                    Ok(None)
                }
            }
        }
    }

    pub struct TunWriter {
        device: Arc<AsyncTunDevice>,
        shutdown_rx: broadcast::Receiver<()>,
    }

    impl TunWriter {
        pub fn new(device: Arc<AsyncTunDevice>, shutdown_rx: broadcast::Receiver<()>) -> Self {
            Self {
                device,
                shutdown_rx,
            }
        }

        pub async fn write_packet(&mut self, packet: &TunPacket) -> io::Result<()> {
            tokio::select! {
                result = self.device.writer().write_packet(packet.data()) => {
                    result.map(|_| ())
                }
                _ = self.shutdown_rx.recv() => {
                    Ok(())
                }
            }
        }
    }

    pub fn is_tun_available() -> bool {
        #[cfg(target_os = "linux")]
        {
            std::path::Path::new("/dev/net/tun").exists()
                || std::path::Path::new("/dev/tun").exists()
        }

        #[cfg(target_os = "macos")]
        {
            true
        }

        #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
        {
            std::path::Path::new("/dev/tun").exists()
        }

        #[cfg(target_os = "windows")]
        {
            true
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "windows"
        )))]
        {
            false
        }
    }
}

#[cfg(not(feature = "tun-rs"))]
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
                "TUN support requires the 'tun-rs' feature",
            ))
        }

        pub async fn create_async(_config: TunConfig) -> Result<Self, io::Error> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN support requires the 'tun-rs' feature",
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
                "TUN support requires the 'tun-rs' feature",
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
                "TUN support requires the 'tun-rs' feature",
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
                "TUN support requires the 'tun-rs' feature",
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
                "TUN support requires the 'tun-rs' feature",
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
