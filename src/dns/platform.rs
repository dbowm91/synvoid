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
    use nix::sys::socket::{setsockopt, sockopt};

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
            setsockopt(socket, sockopt::Ipv4PacketInfo, &true)
                .map_err(|e| format!("IP_PKTINFO: {}", e))?;

            tracing::debug!("Enabled IP_PKTINFO on socket");
            Ok(())
        }

        fn get_destination_ip(&self, cmsg_data: &[u8]) -> Option<IpAddr> {
            use std::mem::size_of;

            if cmsg_data.len() < size_of::<nix::libc::in_pktinfo>() {
                return None;
            }

            let pktinfo_bytes = &cmsg_data[..size_of::<nix::libc::in_pktinfo>()];
            let pktinfo: nix::libc::in_pktinfo =
                unsafe { (pktinfo_bytes.as_ptr() as *const nix::libc::in_pktinfo).read() };

            let addr = std::net::IpAddr::from(std::net::Ipv4Addr::from(
                pktinfo.ipi_addr.s_addr.to_ne_bytes(),
            ));

            Some(addr)
        }

        fn supports_pktinfo(&self) -> bool {
            true
        }

        fn platform_name(&self) -> &'static str {
            "linux"
        }

        fn enable_tcp_pktinfo(&self, fd: std::os::fd::RawFd) -> Result<(), String> {
            unsafe {
                let ret = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    &1 as *const i32 as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                if ret != 0 {
                    return Err(format!(
                        "IP_PKTINFO for TCP: {}",
                        std::io::Error::last_os_error()
                    ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        #[test]
        fn test_linux_platform_name() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();
            assert_eq!(platform.platform_name(), "linux");
        }

        #[test]
        fn test_linux_supports_pktinfo() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();
            assert!(platform.supports_pktinfo());
        }

        #[test]
        fn test_linux_supports_tcp_pktinfo() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();
            assert!(platform.supports_tcp_pktinfo());
        }

        #[test]
        fn test_get_destination_ip_valid_ipv4_loopback() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let mut pktinfo_bytes = vec![0u8; std::mem::size_of::<nix::libc::in_pktinfo>()];
            // Write s_addr directly at byte offset 8 (ipi_addr.s_addr within in_pktinfo on 64-bit)
            pktinfo_bytes[8..12].copy_from_slice(&[127u8, 0, 0, 1]);

            let result = platform.get_destination_ip(&pktinfo_bytes);
            assert!(result.is_some());
            assert_eq!(result.unwrap(), IpAddr::from([127, 0, 0, 1]));
        }

        #[test]
        fn test_get_destination_ip_valid_ipv4_private_10() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let mut pktinfo_bytes = vec![0u8; std::mem::size_of::<nix::libc::in_pktinfo>()];
            pktinfo_bytes[8..12].copy_from_slice(&[10u8, 0, 0, 1]);

            let result = platform.get_destination_ip(&pktinfo_bytes);
            assert!(result.is_some());
            assert_eq!(result.unwrap(), IpAddr::from([10, 0, 0, 1]));
        }

        #[test]
        fn test_get_destination_ip_valid_ipv4_private_172() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let mut pktinfo_bytes = vec![0u8; std::mem::size_of::<nix::libc::in_pktinfo>()];
            pktinfo_bytes[8..12].copy_from_slice(&[172u8, 16, 0, 1]);

            let result = platform.get_destination_ip(&pktinfo_bytes);
            assert!(result.is_some());
            assert_eq!(result.unwrap(), IpAddr::from([172, 16, 0, 1]));
        }

        #[test]
        fn test_get_destination_ip_valid_ipv4_private_192() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let mut pktinfo_bytes = vec![0u8; std::mem::size_of::<nix::libc::in_pktinfo>()];
            pktinfo_bytes[8..12].copy_from_slice(&[192u8, 168, 0, 1]);

            let result = platform.get_destination_ip(&pktinfo_bytes);
            assert!(result.is_some());
            assert_eq!(result.unwrap(), IpAddr::from([192, 168, 0, 1]));
        }

        #[test]
        fn test_get_destination_ip_valid_ipv4_broadcast() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let mut pktinfo_bytes = vec![0u8; std::mem::size_of::<nix::libc::in_pktinfo>()];
            pktinfo_bytes[8..12].copy_from_slice(&[255u8, 255, 255, 255]);

            let result = platform.get_destination_ip(&pktinfo_bytes);
            assert!(result.is_some());
            assert_eq!(result.unwrap(), IpAddr::from([255, 255, 255, 255]));
        }

        #[test]
        fn test_get_destination_ip_valid_ipv4_all_zeros() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let mut pktinfo_bytes = vec![0u8; std::mem::size_of::<nix::libc::in_pktinfo>()];
            pktinfo_bytes[8..12].copy_from_slice(&[0u8, 0, 0, 0]);

            let result = platform.get_destination_ip(&pktinfo_bytes);
            assert!(result.is_some());
            assert_eq!(result.unwrap(), IpAddr::from([0, 0, 0, 0]));
        }

        #[test]
        fn test_get_destination_ip_invalid_too_small() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let small_data = vec![0u8; 4];
            let result = platform.get_destination_ip(&small_data);
            assert!(result.is_none());
        }

        #[test]
        fn test_get_destination_ip_empty() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let empty_data: Vec<u8> = vec![];
            let result = platform.get_destination_ip(&empty_data);
            assert!(result.is_none());
        }

        #[test]
        fn test_get_destination_ip_exact_size() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let pktinfo_bytes = vec![0u8; std::mem::size_of::<nix::libc::in_pktinfo>()];
            let result = platform.get_destination_ip(&pktinfo_bytes);
            assert!(result.is_some());
        }

        #[test]
        fn test_get_destination_ip_one_byte_short() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let size = std::mem::size_of::<nix::libc::in_pktinfo>();
            let pktinfo_bytes = vec![0u8; size - 1];
            let result = platform.get_destination_ip(&pktinfo_bytes);
            assert!(result.is_none());
        }

        #[test]
        fn test_get_destination_ip_one_byte_over() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let size = std::mem::size_of::<nix::libc::in_pktinfo>();
            let mut pktinfo_bytes = vec![0u8; size + 1];
            pktinfo_bytes[8..12].copy_from_slice(&[192u8, 168, 0, 1]);

            let result = platform.get_destination_ip(&pktinfo_bytes);
            assert!(result.is_some());
            assert_eq!(result.unwrap(), IpAddr::from([192, 168, 0, 1]));
        }

        #[test]
        fn test_get_destination_ip_zeroed_data() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let pktinfo_bytes = vec![0u8; std::mem::size_of::<nix::libc::in_pktinfo>()];
            let result = platform.get_destination_ip(&pktinfo_bytes);
            assert!(result.is_some());
            assert_eq!(result.unwrap(), IpAddr::from([0, 0, 0, 0]));
        }

        #[test]
        fn test_get_destination_ip_max_values() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::new();

            let mut pktinfo_bytes = vec![0u8; std::mem::size_of::<nix::libc::in_pktinfo>()];
            pktinfo_bytes[8..12].copy_from_slice(&[255u8, 255, 255, 255]);

            let result = platform.get_destination_ip(&pktinfo_bytes);
            assert!(result.is_some());
            assert_eq!(result.unwrap(), IpAddr::from([255, 255, 255, 255]));
        }

        #[test]
        fn test_default_linux_platform() {
            let platform = crate::dns::platform::linux::LinuxAnycastSocket::default();
            assert_eq!(platform.platform_name(), "linux");
            assert!(platform.supports_pktinfo());
        }

        #[test]
        fn test_linux_platform_size() {
            let size = std::mem::size_of::<nix::libc::in_pktinfo>();
            assert_eq!(size, 12);
        }
    }

    #[cfg(not(target_os = "linux"))]
    mod fallback_tests {
        use super::*;

        #[test]
        fn test_fallback_platform_name() {
            let platform = super::fallback::FallbackAnycastSocket::new();
            assert_eq!(platform.platform_name(), "fallback");
        }

        #[test]
        fn test_fallback_does_not_support_pktinfo() {
            let platform = super::fallback::FallbackAnycastSocket::new();
            assert!(!platform.supports_pktinfo());
        }

        #[test]
        fn test_fallback_does_not_support_tcp_pktinfo() {
            let platform = super::fallback::FallbackAnycastSocket::new();
            assert!(!platform.supports_tcp_pktinfo());
        }

        #[test]
        fn test_fallback_get_destination_ip_returns_none() {
            let platform = super::fallback::FallbackAnycastSocket::new();
            let result = platform.get_destination_ip(&[0u8; 32]);
            assert!(result.is_none());
        }

        #[test]
        fn test_fallback_get_destination_ip_with_various_sizes() {
            let platform = super::fallback::FallbackAnycastSocket::new();

            assert!(platform.get_destination_ip(&[]).is_none());
            assert!(platform.get_destination_ip(&[0u8; 1]).is_none());
            assert!(platform.get_destination_ip(&[0u8; 8]).is_none());
            assert!(platform.get_destination_ip(&[0u8; 12]).is_none());
            assert!(platform.get_destination_ip(&[0u8; 16]).is_none());
            assert!(platform.get_destination_ip(&[0u8; 32]).is_none());
            assert!(platform.get_destination_ip(&[0u8; 64]).is_none());
        }

        #[test]
        fn test_fallback_enable_pktinfo_returns_error() {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let platform = super::fallback::FallbackAnycastSocket::new();
                    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
                    let result = platform.enable_pktinfo(&socket);
                    assert!(result.is_err());
                });
        }

        #[test]
        fn test_fallback_enable_tcp_pktinfo_returns_error() {
            let platform = super::fallback::FallbackAnycastSocket::new();
            let result = platform.enable_tcp_pktinfo(0);
            assert!(result.is_err());
        }

        #[test]
        fn test_fallback_error_message_mentions_pktinfo() {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let platform = super::fallback::FallbackAnycastSocket::new();
                    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
                    let result = platform.enable_pktinfo(&socket);
                    assert!(result.unwrap_err().contains("IP_PKTINFO"));
                });
        }

        #[test]
        fn test_fallback_error_message_mentions_tcp() {
            let platform = super::fallback::FallbackAnycastSocket::new();
            let result = platform.enable_tcp_pktinfo(0);
            assert!(result.unwrap_err().contains("IP_PKTINFO"));
        }

        #[test]
        fn test_default_fallback_platform() {
            let platform = super::fallback::FallbackAnycastSocket::default();
            assert_eq!(platform.platform_name(), "fallback");
            assert!(!platform.supports_pktinfo());
        }
    }

    #[test]
    fn test_trait_object_creation() {
        let _platform: Arc<dyn AnycastSocketPlatform> = create_platform();
    }

    #[test]
    fn test_create_platform_optional() {
        let platform = create_platform_optional();
        let _ = platform.platform_name();
        let _ = platform.supports_pktinfo();
    }

    #[test]
    fn test_trait_has_all_methods() {
        let platform = create_platform_optional();

        let _ = platform.platform_name();
        let _ = platform.supports_pktinfo();
        let _ = platform.supports_tcp_pktinfo();
        let _ = platform.get_destination_ip(&[]);
    }

    #[test]
    fn test_trait_object_clone() {
        let platform = create_platform_optional();
        let name = platform.platform_name();

        let platform2 = create_platform_optional();
        let name2 = platform2.platform_name();

        assert_eq!(name, name2);
    }

    #[test]
    fn test_platform_is_send_sync() {
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<Arc<dyn AnycastSocketPlatform>>();
    }
}
