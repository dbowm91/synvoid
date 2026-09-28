use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

fn reuse_port_supported() -> bool {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "illumos",
        target_os = "solaris"
    ))]
    {
        true
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "illumos",
        target_os = "solaris"
    )))]
    {
        false
    }
}

pub fn is_reuse_port_available() -> bool {
    reuse_port_supported()
}

/// Bind a TCP listener with SO_REUSEADDR (+SO_REUSEPORT where available).
///
/// The returned socket is **nonblocking**: every production caller feeds it
/// straight into `tokio::net::TcpListener::from_std`, which panics on
/// blocking sockets ("Registering a blocking socket with the tokio runtime
/// is unsupported"). Returning a blocking socket here silently broke all
/// listener paths built on this helper (found via the eggbench minimal
/// qualification runtime).
pub fn bind_tcp_reuse(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    if is_reuse_port_available() {
        socket.set_reuse_port(true)?;
    }

    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    socket.set_nonblocking(true)?;

    Ok(socket.into())
}

/// Bind a UDP socket with SO_REUSEADDR (+SO_REUSEPORT where available).
///
/// Nonblocking for the same reason as [`bind_tcp_reuse`]: callers convert
/// with `tokio::net::UdpSocket::from_std`, which rejects blocking sockets.
pub fn bind_udp_reuse(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    if is_reuse_port_available() {
        socket.set_reuse_port(true)?;
    }

    socket.bind(&addr.into())?;

    socket.set_nonblocking(true)?;

    Ok(socket.into())
}
