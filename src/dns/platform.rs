use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub trait AnycastSocketPlatform: Send + Sync {
    fn enable_pktinfo(&self, socket: &UdpSocket) -> Result<(), String>;
    fn get_destination_ip(&self, cmsg_data: &[u8]) -> Option<IpAddr>;
    fn supports_pktinfo(&self) -> bool;
    fn platform_name(&self) -> &'static str;

    fn enable_tcp_pktinfo(&self, socket: std::os::fd::RawFd) -> Result<(), String>;
    fn supports_tcp_pktinfo(&self) -> bool;
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::fd::AsRawFd;

    pub struct LinuxAnycastSocket;

    impl LinuxAnycastSocket {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for LinuxAnycastSocket {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AnycastSocketPlatform for LinuxAnycastSocket {
        fn enable_pktinfo(&self, socket: &UdpSocket) -> Result<(), String> {
            let fd = socket.as_raw_fd();

            let enable: libc::c_int = 1;

            unsafe {
                let ret = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    &enable as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );

                if ret != 0 {
                    return Err(format!("IP_PKTINFO: {}", std::io::Error::last_os_error()));
                }

                let ret_v6 = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_PKTINFO,
                    &enable as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );

                if ret_v6 != 0 {
                    tracing::warn!("IPV6_PKTINFO not available (may not be IPv6 socket)");
                }
            }

            tracing::debug!("Enabled IP_PKTINFO on socket");
            Ok(())
        }

        fn get_destination_ip(&self, cmsg_data: &[u8]) -> Option<IpAddr> {
            if cmsg_data.len() < std::mem::size_of::<libc::in_pktinfo>() {
                return None;
            }

            unsafe {
                let pktinfo = &*(cmsg_data.as_ptr() as *const libc::in_pktinfo);

                let addr = std::net::IpAddr::from(std::net::Ipv4Addr::from(
                    pktinfo.ipi_addr.s_addr.to_ne_bytes(),
                ));

                Some(addr)
            }
        }

        fn supports_pktinfo(&self) -> bool {
            true
        }

        fn platform_name(&self) -> &'static str {
            "linux"
        }

        fn enable_tcp_pktinfo(&self, fd: std::os::fd::RawFd) -> Result<(), String> {
            let enable: libc::c_int = 1;

            unsafe {
                let ret = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    &enable as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );

                if ret != 0 {
                    return Err(format!(
                        "IP_PKTINFO for TCP: {}",
                        std::io::Error::last_os_error()
                    ));
                }

                let ret_v6 = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_PKTINFO,
                    &enable as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );

                if ret_v6 != 0 {
                    tracing::warn!("IPV6_PKTINFO not available for TCP");
                }
            }

            tracing::debug!("Enabled IP_PKTINFO on TCP socket");
            Ok(())
        }

        fn supports_tcp_pktinfo(&self) -> bool {
            true
        }
    }

    pub fn create_platform() -> Arc<dyn AnycastSocketPlatform> {
        Arc::new(LinuxAnycastSocket::new())
    }
}

#[cfg(not(target_os = "linux"))]
mod fallback {
    use super::*;

    pub struct FallbackAnycastSocket;

    impl FallbackAnycastSocket {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for FallbackAnycastSocket {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AnycastSocketPlatform for FallbackAnycastSocket {
        fn enable_pktinfo(&self, _: &UdpSocket) -> Result<(), String> {
            Err(
                "IP_PKTINFO not supported on this platform. Anycast will use source-based routing."
                    .into(),
            )
        }

        fn get_destination_ip(&self, _: &[u8]) -> Option<IpAddr> {
            None
        }

        fn supports_pktinfo(&self) -> bool {
            false
        }

        fn platform_name(&self) -> &'static str {
            "fallback"
        }

        fn enable_tcp_pktinfo(&self, _: std::os::fd::RawFd) -> Result<(), String> {
            Err("IP_PKTINFO not supported on this platform for TCP.".into())
        }

        fn supports_tcp_pktinfo(&self) -> bool {
            false
        }
    }

    pub fn create_platform() -> Arc<dyn AnycastSocketPlatform> {
        Arc::new(FallbackAnycastSocket::new())
    }
}

#[cfg(target_os = "linux")]
pub use linux::create_platform;

#[cfg(not(target_os = "linux"))]
pub use fallback::create_platform;

pub fn create_platform_optional() -> Arc<dyn AnycastSocketPlatform> {
    create_platform()
}
