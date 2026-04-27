#![allow(dead_code)]
// SAFETY_REASON: SYN flood protection - reserved for DDoS mitigation enhancements

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::RwLock;

use super::FloodDecision;
use crate::utils::ip_to_slot;

const SYN_TRACKER_SLOTS: usize = 65536;
const HALF_OPEN_CLEANUP_INTERVAL_SECS: u64 = 60;
const MAX_HALF_OPEN_ENTRIES: usize = 10000;

pub struct SynFloodProtector {
    per_ip_rate: u32,
    global_rate: u32,
    half_open_max: u32,
    half_open_per_ip_max: u32,

    per_ip_counters: Box<[AtomicU32; SYN_TRACKER_SLOTS]>,
    global_counter: AtomicU64,

    half_open_total: AtomicU32,
    half_open_ips: RwLock<HashMap<IpAddr, HalfOpenEntry>>,
    last_cleanup: AtomicU64,

    start_instant: Instant,
    current_window: AtomicU64,
}

#[derive(Clone)]
struct HalfOpenEntry {
    count: u32,
    first_seen: Instant,
    last_seen: Instant,
}

impl SynFloodProtector {
    pub fn new(
        per_ip_rate: u32,
        global_rate: u32,
        half_open_max: u32,
        half_open_per_ip_max: u32,
    ) -> Self {
        Self {
            per_ip_rate,
            global_rate,
            half_open_max,
            half_open_per_ip_max,
            per_ip_counters: Box::new([const { AtomicU32::new(0) }; SYN_TRACKER_SLOTS]),
            global_counter: AtomicU64::new(0),
            half_open_total: AtomicU32::new(0),
            half_open_ips: RwLock::new(HashMap::new()),
            last_cleanup: AtomicU64::new(0),
            start_instant: Instant::now(),
            current_window: AtomicU64::new(0),
        }
    }

    pub fn check_syn(&self, ip: IpAddr) -> FloodDecision {
        let now_secs = self.start_instant.elapsed().as_secs();
        self.rotate_window(now_secs);

        let current = self.global_counter.fetch_add(1, Ordering::Relaxed) + 1;
        if current > self.global_rate as u64 {
            metrics::counter!("maluwaf.syn_flood.global_limited").increment(1);
            return FloodDecision::RateLimited;
        }

        let slot = self.ip_to_slot(ip);
        let ip_count = self.per_ip_counters[slot].fetch_add(1, Ordering::Relaxed) + 1;
        if ip_count > self.per_ip_rate {
            metrics::counter!("maluwaf.syn_flood.ip_limited").increment(1);
            return FloodDecision::RateLimited;
        }

        let half_open = self.half_open_total.load(Ordering::Relaxed);
        if half_open > self.half_open_max {
            metrics::counter!("maluwaf.syn_flood.half_open_exceeded").increment(1);
            return FloodDecision::RateLimited;
        }

        FloodDecision::Allowed
    }

    pub fn register_half_open(&self, ip: IpAddr) {
        {
            let mut map = self.half_open_ips.write();

            if map.len() >= MAX_HALF_OPEN_ENTRIES {
                metrics::counter!("maluwaf.syn_flood.half_open_map_full").increment(1);
                return;
            }

            let now = Instant::now();
            let entry = map.entry(ip).or_insert(HalfOpenEntry {
                count: 0,
                first_seen: now,
                last_seen: now,
            });
            entry.count += 1;
            entry.last_seen = now;

            let half_open = self.half_open_total.fetch_add(1, Ordering::Relaxed) + 1;
            metrics::counter!("maluwaf.syn_flood.half_open").increment(1);
            metrics::gauge!("maluwaf.syn_flood.half_open_count").set(half_open as f64);
        }

        self.maybe_cleanup();
    }

    pub fn register_ack(&self, ip: IpAddr) {
        self.complete_half_open(ip);
    }

    pub fn complete_half_open(&self, ip: IpAddr) {
        let mut should_decrement = false;

        {
            let mut map = self.half_open_ips.write();
            if let Some(entry) = map.get_mut(&ip) {
                if entry.count > 0 {
                    entry.count -= 1;
                    should_decrement = true;
                }
                if entry.count == 0 {
                    map.remove(&ip);
                }
            }
        }

        if should_decrement {
            let _ = self
                .half_open_total
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
            let half_open = self.half_open_total.load(Ordering::Relaxed);
            metrics::gauge!("maluwaf.syn_flood.half_open_count").set(half_open as f64);
        }
    }

    fn ip_to_slot(&self, ip: IpAddr) -> usize {
        ip_to_slot(ip, SYN_TRACKER_SLOTS)
    }

    fn rotate_window(&self, now_secs: u64) {
        let current = self.current_window.load(Ordering::Relaxed);
        if now_secs > current
            && self
                .current_window
                .compare_exchange(current, now_secs, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            for counter in self.per_ip_counters.iter() {
                counter.store(0, Ordering::Relaxed);
            }
            self.global_counter.store(0, Ordering::Relaxed);
        }
    }

    fn maybe_cleanup(&self) {
        let now_secs = self.start_instant.elapsed().as_secs();
        let last = self.last_cleanup.load(Ordering::Relaxed);

        if now_secs.saturating_sub(last) > HALF_OPEN_CLEANUP_INTERVAL_SECS
            && self
                .last_cleanup
                .compare_exchange(last, now_secs, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            self.cleanup_stale_half_opens();
        }
    }

    fn cleanup_stale_half_opens(&self) {
        let mut map = self.half_open_ips.write();
        let now = Instant::now();
        let stale_threshold = std::time::Duration::from_secs(120);

        let mut removed_count = 0u32;
        map.retain(|_ip, entry| {
            if now.duration_since(entry.last_seen) > stale_threshold {
                removed_count += entry.count;
                false
            } else {
                true
            }
        });

        if removed_count > 0 {
            let _ = self
                .half_open_total
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    v.checked_sub(removed_count)
                });
            let half_open = self.half_open_total.load(Ordering::Relaxed);
            metrics::gauge!("maluwaf.syn_flood.half_open_count").set(half_open as f64);
            tracing::debug!("Cleaned up {} stale half-open connections", removed_count);
        }
    }

    pub fn get_stats(&self) -> SynFloodStats {
        let _now_secs = self.start_instant.elapsed().as_secs();
        SynFloodStats {
            global_syn_rate: self.global_counter.load(Ordering::Relaxed),
            half_open_connections: self.half_open_total.load(Ordering::Relaxed),
            unique_half_open_ips: self.half_open_ips.read().len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SynFloodStats {
    pub global_syn_rate: u64,
    pub half_open_connections: u32,
    pub unique_half_open_ips: usize,
}

impl super::SynFloodBackend for SynFloodProtector {
    fn check_syn(&self, ip: IpAddr) -> super::FloodDecision {
        SynFloodProtector::check_syn(self, ip)
    }

    fn register_half_open(&self, ip: IpAddr) {
        SynFloodProtector::register_half_open(self, ip);
    }

    fn register_ack(&self, ip: IpAddr) {
        SynFloodProtector::register_ack(self, ip);
    }

    fn complete_half_open(&self, ip: IpAddr) {
        SynFloodProtector::complete_half_open(self, ip);
    }

    fn get_stats(&self) -> SynFloodStats {
        SynFloodProtector::get_stats(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_syn_rate_limiting() {
        let protector = SynFloodProtector::new(5, 1000, 100, 10);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        for _ in 0..5 {
            assert_eq!(protector.check_syn(ip), FloodDecision::Allowed);
        }

        assert_eq!(protector.check_syn(ip), FloodDecision::RateLimited);
    }

    #[test]
    fn test_half_open_tracking() {
        let protector = SynFloodProtector::new(100, 1000, 3, 10);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        protector.register_half_open(ip);
        protector.register_half_open(ip);
        protector.register_half_open(ip);

        assert_eq!(protector.half_open_total.load(Ordering::Relaxed), 3);

        protector.complete_half_open(ip);
        assert_eq!(protector.half_open_total.load(Ordering::Relaxed), 2);
    }
}
