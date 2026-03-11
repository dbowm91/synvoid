use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use super::FloodDecision;
use crate::utils::ip_to_slot;

const CONNECTION_TRACKER_SLOTS: usize = 65536;

pub struct ConnectionLimiter {
    per_ip_rate: u32,
    global_rate: u32,

    per_ip_second: Box<[AtomicU32; CONNECTION_TRACKER_SLOTS]>,
    per_ip_minute: Box<[AtomicU32; CONNECTION_TRACKER_SLOTS]>,
    global_second: AtomicU64,
    global_minute: AtomicU64,

    current_second: AtomicU64,
    current_minute: AtomicU64,

    active_connections: AtomicU32,
    max_connections: u32,

    start_instant: Instant,
}

impl ConnectionLimiter {
    pub fn new(per_ip_rate: u32, global_rate: u32) -> Self {
        Self {
            per_ip_rate,
            global_rate,
            per_ip_second: Box::new([const { AtomicU32::new(0) }; CONNECTION_TRACKER_SLOTS]),
            per_ip_minute: Box::new([const { AtomicU32::new(0) }; CONNECTION_TRACKER_SLOTS]),
            global_second: AtomicU64::new(0),
            global_minute: AtomicU64::new(0),
            current_second: AtomicU64::new(0),
            current_minute: AtomicU64::new(0),
            active_connections: AtomicU32::new(0),
            max_connections: 10000,
            start_instant: Instant::now(),
        }
    }

    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self
    }

    pub fn try_register_connection(&self, ip: IpAddr) -> FloodDecision {
        let now_secs = self.start_instant.elapsed().as_secs();
        self.rotate_windows(now_secs);

        let active = self.active_connections.fetch_add(1, Ordering::Acquire);
        if active >= self.max_connections {
            self.active_connections.fetch_sub(1, Ordering::Release);
            metrics::counter!("maluwaf.connection_limiter.max_reached").increment(1);
            return FloodDecision::RateLimited;
        }

        let global = self.global_second.load(Ordering::Relaxed);
        if global > self.global_rate as u64 {
            self.active_connections.fetch_sub(1, Ordering::Release);
            metrics::counter!("maluwaf.connection_limiter.global_limited").increment(1);
            return FloodDecision::RateLimited;
        }

        let slot = self.ip_to_slot(ip);
        let ip_count = self.per_ip_second[slot].fetch_add(1, Ordering::Relaxed);
        if ip_count > self.per_ip_rate {
            self.per_ip_second[slot].fetch_sub(1, Ordering::Relaxed);
            self.active_connections.fetch_sub(1, Ordering::Release);
            metrics::counter!("maluwaf.connection_limiter.ip_limited").increment(1);
            return FloodDecision::RateLimited;
        }

        self.global_second.fetch_add(1, Ordering::Relaxed);
        self.global_minute.fetch_add(1, Ordering::Relaxed);
        self.per_ip_minute[slot].fetch_add(1, Ordering::Relaxed);

        let active = self.active_connections.load(Ordering::Relaxed);
        metrics::gauge!("maluwaf.connection_limiter.active").set(active as f64);

        FloodDecision::Allowed
    }

    #[deprecated(
        since = "0.1.0",
        note = "Use try_register_connection instead to avoid race conditions"
    )]
    pub fn check_connection(&self, ip: IpAddr) -> FloodDecision {
        self.try_register_connection(ip)
    }

    #[deprecated(
        since = "0.1.0",
        note = "Use try_register_connection instead to avoid race conditions"
    )]
    pub fn register_connection(&self, ip: IpAddr) {
        let _ = self.try_register_connection(ip);
    }

    pub fn release_connection(&self) {
        let active = self.active_connections.fetch_sub(1, Ordering::Relaxed);
        metrics::gauge!("maluwaf.connection_limiter.active").set(active.saturating_sub(1) as f64);
    }

    fn ip_to_slot(&self, ip: IpAddr) -> usize {
        ip_to_slot(ip, CONNECTION_TRACKER_SLOTS)
    }

    fn rotate_windows(&self, now_secs: u64) {
        let current_sec = self.current_second.load(Ordering::Relaxed);
        let current_min = self.current_minute.load(Ordering::Relaxed);

        if now_secs > current_sec {
            if self
                .current_second
                .compare_exchange(current_sec, now_secs, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                for counter in self.per_ip_second.iter() {
                    counter.store(0, Ordering::Relaxed);
                }
                self.global_second.store(0, Ordering::Relaxed);
            }
        }

        let current_min_val = now_secs / 60;
        if current_min_val > current_min {
            if self
                .current_minute
                .compare_exchange(
                    current_min,
                    current_min_val,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                for counter in self.per_ip_minute.iter() {
                    counter.store(0, Ordering::Relaxed);
                }
                self.global_minute.store(0, Ordering::Relaxed);
            }
        }
    }

    pub fn get_stats(&self) -> ConnectionStats {
        ConnectionStats {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            global_connections_per_second: self.global_second.load(Ordering::Relaxed),
            global_connections_per_minute: self.global_minute.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub active_connections: u32,
    pub global_connections_per_second: u64,
    pub global_connections_per_minute: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_connection_rate_limiting() {
        let limiter = ConnectionLimiter::new(5, 1000).with_max_connections(5);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        for _ in 0..5 {
            assert_eq!(limiter.try_register_connection(ip), FloodDecision::Allowed);
        }

        assert_eq!(
            limiter.try_register_connection(ip),
            FloodDecision::RateLimited
        );
    }

    #[test]
    fn test_connection_release() {
        let limiter = ConnectionLimiter::new(10, 1000);

        assert_eq!(
            limiter.try_register_connection(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            FloodDecision::Allowed
        );
        assert_eq!(limiter.active_connections.load(Ordering::Relaxed), 1);

        limiter.release_connection();
        assert_eq!(limiter.active_connections.load(Ordering::Relaxed), 0);
    }
}
