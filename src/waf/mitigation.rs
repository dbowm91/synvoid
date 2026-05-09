use std::io;
use std::net::IpAddr;
use std::time::Duration;
use std::sync::Arc;

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

static MITIGATION_PROVIDER: arc_swap::ArcSwapOption<SizedMitigationProvider> = arc_swap::ArcSwapOption::const_empty();

pub fn set_mitigation_provider(provider: Arc<dyn MitigationProvider>) {
    MITIGATION_PROVIDER.store(Some(Arc::new(SizedMitigationProvider(provider))));
}

pub fn get_mitigation_provider() -> Option<Arc<dyn MitigationProvider>> {
    MITIGATION_PROVIDER.load_full().map(|p| p.0.clone())
}
