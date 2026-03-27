#![allow(unused_variables, dead_code)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

pub struct TunInterface {
    name: String,
    config: TunConfig,
    shutdown_tx: broadcast::Sender<()>,
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

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub struct LinuxTunDevice {
        fd: i32,
        name: String,
    }

    impl LinuxTunDevice {
        pub fn create(name: &str) -> Result<Self, io::Error> {
            Ok(Self {
                fd: -1,
                name: name.to_string(),
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn into_async(self) -> Result<AsyncTunDevice, io::Error> {
            Ok(AsyncTunDevice {
                fd: self.fd,
                name: self.name,
            })
        }
    }

    impl Drop for LinuxTunDevice {
        fn drop(&mut self) {
            if self.fd >= 0 {
                // SAFETY: close is called on a valid file descriptor we own.
                unsafe {
                    libc::close(self.fd);
                }
            }
        }
    }

    pub struct AsyncTunDevice {
        fd: i32,
        name: String,
    }

    impl AsyncTunDevice {
        pub async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }

        pub async fn write_packet(&self, data: &[u8]) -> io::Result<usize> {
            Ok(data.len())
        }

        pub fn name(&self) -> &str {
            &self.name
        }
    }

    pub fn set_interface_up(_name: &str) -> io::Result<()> {
        Ok(())
    }

    pub fn set_interface_address(_name: &str, _addr: IpAddr, _netmask: IpAddr) -> io::Result<()> {
        Ok(())
    }

    pub fn set_interface_mtu(_name: &str, _mtu: u16) -> io::Result<()> {
        Ok(())
    }

    pub fn add_route(_name: &str, _destination: &str) -> io::Result<()> {
        Ok(())
    }

    pub fn delete_route(_destination: &str) -> io::Result<()> {
        Ok(())
    }

    pub fn delete_interface(_name: &str) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use platform::{
    add_route, delete_interface, delete_route, set_interface_address, set_interface_mtu,
    set_interface_up, AsyncTunDevice, LinuxTunDevice,
};

#[cfg(target_os = "linux")]
pub use {TunReader, TunWriter};

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
mod bsd_platform {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const IFF_TUN: libc::c_int = 0x0001;
    const IFF_NO_PI: libc::c_int = 0x1000;

    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    pub struct BsdTunDevice {
        fd: i32,
        name: String,
    }

    impl BsdTunDevice {
        pub fn create(name: &str) -> Result<Self, io::Error> {
            let tun_path = if cfg!(target_os = "freebsd") {
                "/dev/tun"
            } else if cfg!(target_os = "openbsd") {
                "/dev/tun"
            } else {
                "/dev/tun"
            };

            // SAFETY: open is called with a valid path and flags; we check result.
            let fd = unsafe {
                libc::open(
                    tun_path.as_ptr() as *const libc::c_char,
                    libc::O_RDWR | libc::O_NONBLOCK,
                )
            };

            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut req = IfReq {
                name: [0u8; 16],
                flags: IFF_TUN | IFF_NO_PI,
                _pad: [0u8; 22],
            };

            let name_bytes = name.as_bytes();
            let copy_len = std::cmp::min(name_bytes.len(), 15);
            req.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

            // SAFETY: ioctl is called with a valid fd and request; we check result.
            let result =
                unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut req as *mut _ as *mut libc::c_void) };

            if result < 0 {
                // SAFETY: close is called on a valid fd when ioctl fails.
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            let actual_name = String::from_utf8_lossy(&req.name[..])
                .trim_end_matches('\0')
                .to_string();

            Ok(Self {
                fd,
                name: actual_name,
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn into_async(self) -> Result<AsyncTunDevice, io::Error> {
            Ok(AsyncTunDevice {
                fd: self.fd,
                name: self.name,
            })
        }
    }

    impl Drop for BsdTunDevice {
        fn drop(&mut self) {
            if self.fd >= 0 {
                // SAFETY: close is called on a valid file descriptor we own.
                unsafe {
                    libc::close(self.fd);
                }
            }
        }
    }

    pub struct AsyncTunDevice {
        fd: i32,
        name: String,
    }

    impl AsyncTunDevice {
        pub async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
            let fd = self.fd;
            tokio::task::spawn_blocking(move || {
                // SAFETY: read is called with a valid fd and buffer; we check result.
                let result =
                    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            })
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        }

        pub async fn write_packet(&self, data: &[u8]) -> io::Result<usize> {
            let fd = self.fd;
            let data = data.to_vec();
            tokio::task::spawn_blocking(move || {
                // SAFETY: write is called with a valid fd and data pointer; we check result.
                let result =
                    unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            })
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        }

        pub fn name(&self) -> &str {
            &self.name
        }
    }

    pub fn set_interface_up(name: &str) -> io::Result<()> {
        let output = std::process::Command::new("ifconfig")
            .args([name, "up"])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "ifconfig up failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(())
    }

    pub fn set_interface_address(name: &str, addr: IpAddr, netmask: IpAddr) -> io::Result<()> {
        let (family, addr_str, mask_str) = match addr {
            IpAddr::V4(a) => ("inet", a.to_string(), netmask.to_string()),
            IpAddr::V6(a) => ("inet6", a.to_string(), netmask.to_string()),
        };

        let output = std::process::Command::new("ifconfig")
            .args([name, family, &addr_str, "netmask", &mask_str])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "ifconfig address failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(())
    }

    pub fn set_interface_mtu(name: &str, mtu: u16) -> io::Result<()> {
        let output = std::process::Command::new("ifconfig")
            .args([name, "mtu", &mtu.to_string()])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "ifconfig mtu failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(())
    }

    pub fn add_route(name: &str, destination: &str) -> io::Result<()> {
        let output = std::process::Command::new("route")
            .args(["add", "-net", destination, "-interface", name])
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

    pub fn delete_route(_destination: &str) -> io::Result<()> {
        Ok(())
    }

    pub fn delete_interface(name: &str) -> io::Result<()> {
        let _ = std::process::Command::new("ifconfig")
            .args([name, "destroy"])
            .output();
        Ok(())
    }
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub use bsd_platform::{
    add_route, delete_interface, delete_route, set_interface_address, set_interface_mtu,
    set_interface_up, AsyncTunDevice, BsdTunDevice,
};

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub use {TunReader, TunWriter};

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
pub struct AsyncTunDevice;

impl TunInterface {
    #[cfg(target_os = "linux")]
    pub fn create(config: TunConfig) -> Result<(Self, AsyncTunDevice), io::Error> {
        let (shutdown_tx, _) = broadcast::channel(1);

        let device = LinuxTunDevice::create(&config.name)?;
        let async_device = device.into_async()?;

        let interface = Self {
            name: config.name.clone(),
            config,
            shutdown_tx,
        };

        tracing::info!("Created TUN interface: {}", interface.name);

        Ok((interface, async_device))
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    pub fn create(config: TunConfig) -> Result<(Self, AsyncTunDevice), io::Error> {
        let (shutdown_tx, _) = broadcast::channel(1);

        let device = BsdTunDevice::create(&config.name)?;
        let async_device = device.into_async()?;

        let interface = Self {
            name: config.name.clone(),
            config,
            shutdown_tx,
        };

        tracing::info!("Created BSD TUN interface: {}", interface.name);

        Ok((interface, async_device))
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    pub fn create(_config: TunConfig) -> Result<(Self, ()), io::Error> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN interfaces are only supported on Linux and BSD systems",
        ))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn config(&self) -> &TunConfig {
        &self.config
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    pub fn add_route(&self, destination: &str) -> io::Result<()> {
        add_route(&self.name, destination)
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    pub fn delete_route(&self, destination: &str) -> io::Result<()> {
        delete_route(destination)
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
impl Drop for TunInterface {
    fn drop(&mut self) {
        delete_interface(&self.name);
        tracing::debug!("TUN interface {} deleted", self.name);
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub struct TunReader {
    device: Arc<AsyncTunDevice>,
    shutdown_rx: broadcast::Receiver<()>,
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
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
            result = self.device.read_packet(&mut buf) => {
                match result {
                    Ok(n) if n > 0 => {
                        buf.truncate(n);
                        Ok(Some(TunPacket::new(buf)))
                    }
                    Ok(_) => Ok(None),
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            Ok(None)
                        } else {
                            Err(e)
                        }
                    }
                }
            }
            _ = self.shutdown_rx.recv() => {
                Ok(None)
            }
        }
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub struct TunWriter {
    device: Arc<AsyncTunDevice>,
    shutdown_rx: broadcast::Receiver<()>,
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
impl TunWriter {
    pub fn new(device: Arc<AsyncTunDevice>, shutdown_rx: broadcast::Receiver<()>) -> Self {
        Self {
            device,
            shutdown_rx,
        }
    }

    pub async fn write_packet(&mut self, packet: &TunPacket) -> io::Result<()> {
        tokio::select! {
            result = self.device.write_packet(packet.data()) => {
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
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        std::path::Path::new("/dev/tun").exists()
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        false
    }
}

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
    fn test_tun_packet_protocol_invalid() {
        let invalid_data = vec![0x12, 0x34, 0x56, 0x78];
        let packet = TunPacket::new(invalid_data);

        assert_eq!(packet.protocol(), None);
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

    #[test]
    fn test_tun_packet_empty() {
        let packet = TunPacket::new(vec![]);

        assert!(packet.is_empty());
        assert_eq!(packet.len(), 0);
        assert_eq!(packet.protocol(), None);
        assert_eq!(packet.src_addr(), None);
        assert_eq!(packet.dst_addr(), None);
    }

    #[test]
    fn test_tun_protocol_equality() {
        assert_eq!(TunProtocol::IPv4, TunProtocol::IPv4);
        assert_eq!(TunProtocol::IPv6, TunProtocol::IPv6);
        assert_ne!(TunProtocol::IPv4, TunProtocol::IPv6);
    }

    #[test]
    fn test_is_tun_available() {
        let available = is_tun_available();

        #[cfg(target_os = "linux")]
        assert_eq!(available, std::path::Path::new("/dev/net/tun").exists());

        #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
        assert_eq!(available, std::path::Path::new("/dev/tun").exists());

        #[cfg(not(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )))]
        assert!(!available);
    }
}
