use std::io;
use std::net::IpAddr;
use std::time::Duration;

/// Application-neutral contract for IP mitigation providers.
pub trait MitigationProvider: Send + Sync {
    fn block_ip(&self, ip: IpAddr, reason: &str, duration: Duration) -> io::Result<()>;
    fn unblock_ip(&self, ip: IpAddr) -> io::Result<()>;
    fn name(&self) -> &'static str;
}
