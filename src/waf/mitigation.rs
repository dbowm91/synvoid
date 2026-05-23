use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Trait for platform-specific IP mitigation (blocking/unblocking).
///
/// This provides an abstraction over kernel-level blocking (eBPF on Linux)
/// and userspace fallback implementations.
pub trait MitigationProvider: Send + Sync {
    /// Block an IP address for the specified duration.
    fn block_ip(&self, ip: IpAddr, reason: &str, duration: Duration) -> io::Result<()>;

    /// Unblock an IP address.
    fn unblock_ip(&self, ip: IpAddr) -> io::Result<()>;

    /// Returns the name of the provider (e.g., "aya-ebpf", "userspace-fallback").
    fn name(&self) -> &'static str;
}

/// A mitigation provider that does nothing, used as a default or for testing.
pub struct NoOpMitigationProvider;

impl MitigationProvider for NoOpMitigationProvider {
    fn block_ip(&self, _ip: IpAddr, _reason: &str, _duration: Duration) -> io::Result<()> {
        Ok(())
    }

    fn unblock_ip(&self, _ip: IpAddr) -> io::Result<()> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "no-op"
    }
}

/// A mitigation provider that logs the blocking actions but doesn't enforce them in the kernel.
pub struct LoggingMitigationProvider;

impl MitigationProvider for LoggingMitigationProvider {
    fn block_ip(&self, ip: IpAddr, reason: &str, duration: Duration) -> io::Result<()> {
        tracing::info!(%ip, %reason, ?duration, "Mitigation (Logging): Blocked IP");
        Ok(())
    }

    fn unblock_ip(&self, ip: IpAddr) -> io::Result<()> {
        tracing::info!(%ip, "Mitigation (Logging): Unblocked IP");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "logging"
    }
}

/// Global registry for the active mitigation provider.
pub struct SizedMitigationProvider(pub Arc<dyn MitigationProvider>);

#[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
pub struct EbpfMitigationProvider {
    ebpf: Arc<parking_lot::Mutex<crate::waf::flood::ebpf_flood::EbpfSynFloodProtector>>,
}

#[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
impl MitigationProvider for EbpfMitigationProvider {
    fn block_ip(&self, ip: IpAddr, _reason: &str, _duration: Duration) -> io::Result<()> {
        let ebpf = self.ebpf.lock();
        ebpf.block_ip(ip)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn unblock_ip(&self, ip: IpAddr) -> io::Result<()> {
        let ebpf = self.ebpf.lock();
        ebpf.unblock_ip(ip)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn name(&self) -> &'static str {
        "aya-ebpf"
    }
}

#[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
impl EbpfMitigationProvider {
    pub fn new(
        ebpf: Arc<parking_lot::Mutex<crate::waf::flood::ebpf_flood::EbpfSynFloodProtector>>,
    ) -> Self {
        Self { ebpf }
    }
}

static MITIGATION_PROVIDER: arc_swap::ArcSwapOption<SizedMitigationProvider> =
    arc_swap::ArcSwapOption::const_empty();

pub fn set_mitigation_provider(provider: Arc<dyn MitigationProvider>) {
    MITIGATION_PROVIDER.store(Some(Arc::new(SizedMitigationProvider(provider))));
}

pub fn get_mitigation_provider() -> Option<Arc<dyn MitigationProvider>> {
    MITIGATION_PROVIDER.load_full().map(|p| p.0.clone())
}
