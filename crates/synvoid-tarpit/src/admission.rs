use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// RAII guard that holds global and per-IP semaphore permits.
/// Permits are released automatically on drop.
pub struct AdmissionGuard {
    _global: OwnedSemaphorePermit,
    _ip: OwnedSemaphorePermit,
    active_count: Arc<AtomicUsize>,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        self.active_count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Semaphore-based admission control with global and per-IP limits.
pub struct TarpitAdmission {
    global: Arc<Semaphore>,
    ip_map: Arc<Mutex<HashMap<IpAddr, Arc<Semaphore>>>>,
    max_per_ip: usize,
    active_count: Arc<AtomicUsize>,
}

impl TarpitAdmission {
    pub fn new(max_concurrent: usize, max_per_ip: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_concurrent)),
            ip_map: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
            active_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Try to admit a session from the given IP.
    ///
    /// Returns `Some(AdmissionGuard)` if admitted, `None` if the global or per-IP
    /// limit would be exceeded.
    pub fn try_admit(&self, ip: IpAddr) -> Option<AdmissionGuard> {
        let global_permit = Arc::clone(&self.global).try_acquire_owned().ok()?;

        let ip_sema = {
            let mut map = self.ip_map.lock();
            map.entry(ip)
                .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_ip)))
                .clone()
        };

        let ip_permit = match Arc::clone(&ip_sema).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                drop(global_permit);
                return None;
            }
        };

        self.active_count.fetch_add(1, Ordering::Relaxed);

        Some(AdmissionGuard {
            _global: global_permit,
            _ip: ip_permit,
            active_count: Arc::clone(&self.active_count),
        })
    }

    /// Number of currently active sessions (approximate).
    pub fn active_count(&self) -> usize {
        self.active_count.load(Ordering::Relaxed)
    }

    /// Number of sessions currently active for a specific IP.
    pub fn active_count_for_ip(&self, ip: &IpAddr) -> usize {
        let map = self.ip_map.lock();
        if let Some(sema) = map.get(ip) {
            self.max_per_ip - sema.available_permits()
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admit_within_limits() {
        let admission = TarpitAdmission::new(2, 2);
        let guard = admission.try_admit(IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)));
        assert!(guard.is_some());
        assert_eq!(admission.active_count(), 1);
    }

    #[test]
    fn reject_global_limit() {
        let admission = TarpitAdmission::new(1, 2);
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        let _g1 = admission.try_admit(ip);
        let g2 = admission.try_admit(ip);
        assert!(g2.is_none());
    }

    #[test]
    fn reject_per_ip_limit() {
        let admission = TarpitAdmission::new(10, 1);
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(5, 6, 7, 8));
        let _g1 = admission.try_admit(ip);
        let g2 = admission.try_admit(ip);
        assert!(g2.is_none());
        // Different IP should still succeed
        let g3 = admission.try_admit(ip2);
        assert!(g3.is_some());
    }

    #[test]
    fn guard_drop_releases_permit() {
        let admission = TarpitAdmission::new(1, 1);
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        {
            let _g = admission.try_admit(ip);
            assert_eq!(admission.active_count(), 1);
        }
        // Guard dropped, should be able to admit again
        let g = admission.try_admit(ip);
        assert!(g.is_some());
    }

    #[test]
    fn active_count_for_ip() {
        let admission = TarpitAdmission::new(10, 2);
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(admission.active_count_for_ip(&ip), 0);
        let _g = admission.try_admit(ip);
        assert_eq!(admission.active_count_for_ip(&ip), 1);
    }
}
