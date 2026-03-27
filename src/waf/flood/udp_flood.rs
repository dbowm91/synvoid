use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use super::FloodDecision;
use crate::utils::ip_to_slot;

const UDP_TRACKER_SLOTS: usize = 65536;
const MAX_AMPLIFICATION_ENTRIES: usize = 10000;

#[derive(Debug, Clone)]
pub struct UdpProtocolLimits {
    pub dns_limit: u32,
    pub ntp_limit: u32,
    pub snmp_limit: u32,
    pub ssdp_limit: u32,
    pub mdns_limit: u32,
    pub stun_limit: u32,
    pub coap_limit: u32,
    pub quic_limit: u32,
    pub amplification_threshold: f64,
}

impl Default for UdpProtocolLimits {
    fn default() -> Self {
        Self {
            dns_limit: 1000,
            ntp_limit: 100,
            snmp_limit: 50,
            ssdp_limit: 50,
            mdns_limit: 100,
            stun_limit: 200,
            coap_limit: 500,
            quic_limit: 10000,
            amplification_threshold: 5.0,
        }
    }
}

pub struct UdpFloodProtector {
    per_ip_rate: u32,
    global_rate: u32,
    protocol_limits: UdpProtocolLimits,

    per_ip_counters: Box<[AtomicU32; UDP_TRACKER_SLOTS]>,
    per_port_counters: Box<[AtomicU32; 65536]>,

    dns_counters: Box<[AtomicU32; UDP_TRACKER_SLOTS]>,
    ntp_counters: Box<[AtomicU32; UDP_TRACKER_SLOTS]>,
    snmp_counters: Box<[AtomicU32; UDP_TRACKER_SLOTS]>,
    ssdp_counters: Box<[AtomicU32; UDP_TRACKER_SLOTS]>,

    global_counter: AtomicU64,
    current_window: AtomicU64,

    start_instant: Instant,

    amplification_tracker: RwLock<HashMap<IpAddr, AmplificationEntry>>,
    amplification_alert: AtomicBool,
}

#[derive(Clone)]
struct AmplificationEntry {
    request_bytes: u64,
    response_bytes: u64,
    last_seen: Instant,
}

impl UdpFloodProtector {
    pub fn new(per_ip_rate: u32, global_rate: u32) -> Self {
        Self::with_protocol_limits(per_ip_rate, global_rate, UdpProtocolLimits::default())
    }

    pub fn with_protocol_limits(
        per_ip_rate: u32,
        global_rate: u32,
        protocol_limits: UdpProtocolLimits,
    ) -> Self {
        Self {
            per_ip_rate,
            global_rate,
            protocol_limits,
            per_ip_counters: Box::new([const { AtomicU32::new(0) }; UDP_TRACKER_SLOTS]),
            per_port_counters: Box::new([const { AtomicU32::new(0) }; 65536]),
            dns_counters: Box::new([const { AtomicU32::new(0) }; UDP_TRACKER_SLOTS]),
            ntp_counters: Box::new([const { AtomicU32::new(0) }; UDP_TRACKER_SLOTS]),
            snmp_counters: Box::new([const { AtomicU32::new(0) }; UDP_TRACKER_SLOTS]),
            ssdp_counters: Box::new([const { AtomicU32::new(0) }; UDP_TRACKER_SLOTS]),
            global_counter: AtomicU64::new(0),
            current_window: AtomicU64::new(0),
            start_instant: Instant::now(),
            amplification_tracker: RwLock::new(HashMap::new()),
            amplification_alert: AtomicBool::new(false),
        }
    }

    pub fn check_packet(&self, ip: IpAddr) -> FloodDecision {
        self.check_packet_with_port(ip, None)
    }

    pub fn check_packet_with_port(&self, ip: IpAddr, port: Option<u16>) -> FloodDecision {
        let now_secs = self.start_instant.elapsed().as_secs();
        self.rotate_window(now_secs);

        let global = self.global_counter.fetch_add(1, Ordering::Relaxed) + 1;
        if global > self.global_rate as u64 {
            metrics::counter!("maluwaf.udp_flood.global_limited").increment(1);
            return FloodDecision::RateLimited;
        }

        let slot = self.ip_to_slot(ip);
        let ip_count = self.per_ip_counters[slot].fetch_add(1, Ordering::Relaxed) + 1;
        if ip_count > self.per_ip_rate {
            metrics::counter!("maluwaf.udp_flood.ip_limited").increment(1);
            return FloodDecision::RateLimited;
        }

        if let Some(p) = port {
            let port_count = self.per_port_counters[p as usize].fetch_add(1, Ordering::Relaxed) + 1;
            let port_threshold = self.global_rate / 100;
            if port_count > port_threshold {
                metrics::counter!("maluwaf.udp_flood.port_limited").increment(1);
                return FloodDecision::RateLimited;
            }

            if let FloodDecision::RateLimited = self.check_protocol_rate(ip, p, slot) {
                return FloodDecision::RateLimited;
            }
        }

        FloodDecision::Allowed
    }

    fn check_protocol_rate(&self, _ip: IpAddr, port: u16, slot: usize) -> FloodDecision {
        match port {
            53 => {
                let count = self.dns_counters[slot].fetch_add(1, Ordering::Relaxed) + 1;
                if count > self.protocol_limits.dns_limit {
                    metrics::counter!("maluwaf.udp_flood.dns_limited").increment(1);
                    return FloodDecision::RateLimited;
                }
            }
            123 => {
                let count = self.ntp_counters[slot].fetch_add(1, Ordering::Relaxed) + 1;
                if count > self.protocol_limits.ntp_limit {
                    metrics::counter!("maluwaf.udp_flood.ntp_limited").increment(1);
                    return FloodDecision::RateLimited;
                }
            }
            161 | 162 => {
                let count = self.snmp_counters[slot].fetch_add(1, Ordering::Relaxed) + 1;
                if count > self.protocol_limits.snmp_limit {
                    metrics::counter!("maluwaf.udp_flood.snmp_limited").increment(1);
                    return FloodDecision::RateLimited;
                }
            }
            1900 => {
                let count = self.ssdp_counters[slot].fetch_add(1, Ordering::Relaxed) + 1;
                if count > self.protocol_limits.ssdp_limit {
                    metrics::counter!("maluwaf.udp_flood.ssdp_limited").increment(1);
                    return FloodDecision::RateLimited;
                }
            }
            _ => {}
        }
        FloodDecision::Allowed
    }

    pub fn check_amplification(
        &self,
        source_ip: IpAddr,
        request_size: usize,
        response_size: usize,
    ) -> bool {
        if request_size == 0 || response_size == 0 {
            return false;
        }

        let ratio = response_size as f64 / request_size as f64;

        if ratio > self.protocol_limits.amplification_threshold {
            let mut tracker = self.amplification_tracker.write();

            if tracker.len() >= MAX_AMPLIFICATION_ENTRIES {
                metrics::counter!("maluwaf.udp_flood.amplification_tracker_full").increment(1);
                return false;
            }

            let entry = tracker.entry(source_ip).or_insert(AmplificationEntry {
                request_bytes: 0,
                response_bytes: 0,
                last_seen: Instant::now(),
            });

            entry.request_bytes += request_size as u64;
            entry.response_bytes += response_size as u64;
            entry.last_seen = Instant::now();

            let total_ratio = entry.response_bytes as f64 / entry.request_bytes as f64;

            if total_ratio > self.protocol_limits.amplification_threshold {
                self.amplification_alert.store(true, Ordering::Relaxed);
                metrics::counter!("maluwaf.udp_flood.amplification_detected").increment(1);
                return true;
            }
        }

        false
    }

    pub fn is_amplification_alert(&self) -> bool {
        self.amplification_alert.load(Ordering::Relaxed)
    }

    pub fn clear_amplification_alert(&self) {
        self.amplification_alert.store(false, Ordering::Relaxed);
        self.amplification_tracker.write().clear();
    }

    fn ip_to_slot(&self, ip: IpAddr) -> usize {
        ip_to_slot(ip, UDP_TRACKER_SLOTS)
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
            for counter in self.per_port_counters.iter() {
                counter.store(0, Ordering::Relaxed);
            }
            for counter in self.dns_counters.iter() {
                counter.store(0, Ordering::Relaxed);
            }
            for counter in self.ntp_counters.iter() {
                counter.store(0, Ordering::Relaxed);
            }
            for counter in self.snmp_counters.iter() {
                counter.store(0, Ordering::Relaxed);
            }
            for counter in self.ssdp_counters.iter() {
                counter.store(0, Ordering::Relaxed);
            }
            self.global_counter.store(0, Ordering::Relaxed);

            let mut tracker = self.amplification_tracker.write();
            tracker.retain(|_, entry| entry.last_seen.elapsed().as_secs() < 60);
        }
    }

    pub fn get_stats(&self) -> UdpFloodStats {
        UdpFloodStats {
            global_packets_per_second: self.global_counter.load(Ordering::Relaxed),
            amplification_alert: self.amplification_alert.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdpFloodStats {
    pub global_packets_per_second: u64,
    pub amplification_alert: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_udp_rate_limiting() {
        let protector = UdpFloodProtector::new(5, 1000);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        for i in 0..5 {
            assert_eq!(
                protector.check_packet(ip),
                FloodDecision::Allowed,
                "Packet {} should be allowed",
                i
            );
        }

        assert_eq!(protector.check_packet(ip), FloodDecision::RateLimited);
    }

    #[test]
    fn test_udp_global_limiting() {
        let protector = UdpFloodProtector::new(10000, 5);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        for i in 0..5 {
            assert_eq!(
                protector.check_packet(ip1),
                FloodDecision::Allowed,
                "Packet {} should be allowed",
                i
            );
        }

        assert_eq!(protector.check_packet(ip2), FloodDecision::RateLimited);
    }

    #[test]
    fn test_dns_protocol_rate_limiting() {
        let limits = UdpProtocolLimits {
            dns_limit: 10,
            ..Default::default()
        };
        let protector = UdpFloodProtector::with_protocol_limits(1000, 100000, limits);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        for i in 0..10 {
            assert_eq!(
                protector.check_packet_with_port(ip, Some(53)),
                FloodDecision::Allowed,
                "DNS packet {} should be allowed",
                i
            );
        }

        assert_eq!(
            protector.check_packet_with_port(ip, Some(53)),
            FloodDecision::RateLimited
        );
    }

    #[test]
    fn test_amplification_detection() {
        let protector = UdpFloodProtector::new(1000, 100000);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let is_amp = protector.check_amplification(ip, 40, 4000);
        assert!(is_amp);
        assert!(protector.is_amplification_alert());
    }
}
