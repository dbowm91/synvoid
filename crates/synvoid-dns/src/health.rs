use parking_lot::RwLock;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// Overall DNS server health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HealthState {
    /// Server is alive and ready to serve queries.
    Healthy,
    /// Server is alive but operating in degraded mode (e.g., some zones failed to load).
    Degraded,
    /// Server is not ready to serve queries.
    NotReady,
}

/// Liveness vs readiness distinction.
#[derive(Debug, Clone, Serialize)]
pub struct DnsHealthStatus {
    /// Liveness: is the DNS server process running?
    pub liveness: HealthState,
    /// Readiness: can the server accept and answer queries?
    pub readiness: HealthState,
    /// Whether any listener is bound (UDP/TCP).
    pub listener_bound: bool,
    /// Number of authoritative zones currently loaded and active.
    pub zones_loaded: u64,
    /// Number of zones that failed to load.
    pub zones_failed: u64,
    /// Recursive resolver state.
    pub recursive_state: RecursiveHealth,
    /// Cache operational state.
    pub cache_operational: bool,
    /// DNSSEC key state.
    pub dnssec_state: DnssecHealth,
    /// Encrypted transport cert state.
    pub encrypted_transport_state: EncryptedTransportHealth,
    /// Transfer/update policy state.
    pub transfer_update_state: TransferUpdateHealth,
    /// Uptime in seconds since last reset.
    pub uptime_seconds: u64,
    /// Timestamp of last zone load/reload attempt.
    pub last_zone_load_time: Option<u64>,
    /// Last zone load/reload error message (if any).
    pub last_zone_load_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub enum RecursiveHealth {
    Healthy,
    Degraded { circuit_breaker_open: bool },
    Disabled,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnssecHealth {
    pub keys_loaded: u64,
    pub last_key_rotation: Option<u64>,
    pub signing_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EncryptedTransportHealth {
    pub dot_enabled: bool,
    pub doh_enabled: bool,
    pub doq_enabled: bool,
    pub cert_valid: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferUpdateHealth {
    pub axfr_enabled: bool,
    pub ixfr_enabled: bool,
    pub update_enabled: bool,
    pub tsig_required: bool,
}

/// Thread-safe health checker for the DNS server.
pub struct DnsHealthChecker {
    listener_bound: AtomicBool,
    zones_loaded: AtomicU64,
    zones_failed: AtomicU64,
    recursive_healthy: AtomicBool,
    recursive_degraded: AtomicBool,
    recursive_disabled: AtomicBool,
    circuit_breaker_open: AtomicBool,
    cache_operational: AtomicBool,
    dnssec_keys_loaded: AtomicU64,
    dnssec_signing_enabled: AtomicBool,
    last_key_rotation: AtomicU64,
    dot_enabled: AtomicBool,
    doh_enabled: AtomicBool,
    doq_enabled: AtomicBool,
    cert_valid: AtomicBool,
    axfr_enabled: AtomicBool,
    ixfr_enabled: AtomicBool,
    update_enabled: AtomicBool,
    tsig_required: AtomicBool,
    last_zone_load_time: AtomicU64,
    last_zone_load_error: RwLock<Option<String>>,
    start_time: Instant,
}

impl DnsHealthChecker {
    pub fn new() -> Self {
        Self {
            listener_bound: AtomicBool::new(false),
            zones_loaded: AtomicU64::new(0),
            zones_failed: AtomicU64::new(0),
            recursive_healthy: AtomicBool::new(false),
            recursive_degraded: AtomicBool::new(false),
            recursive_disabled: AtomicBool::new(true),
            circuit_breaker_open: AtomicBool::new(false),
            cache_operational: AtomicBool::new(false),
            dnssec_keys_loaded: AtomicU64::new(0),
            dnssec_signing_enabled: AtomicBool::new(false),
            last_key_rotation: AtomicU64::new(0),
            dot_enabled: AtomicBool::new(false),
            doh_enabled: AtomicBool::new(false),
            doq_enabled: AtomicBool::new(false),
            cert_valid: AtomicBool::new(false),
            axfr_enabled: AtomicBool::new(false),
            ixfr_enabled: AtomicBool::new(false),
            update_enabled: AtomicBool::new(false),
            tsig_required: AtomicBool::new(false),
            last_zone_load_time: AtomicU64::new(0),
            last_zone_load_error: RwLock::new(None),
            start_time: Instant::now(),
        }
    }

    // Setter methods
    pub fn set_listener_bound(&self, bound: bool) {
        self.listener_bound.store(bound, Ordering::Relaxed);
    }
    pub fn set_zones_loaded(&self, count: u64) {
        self.zones_loaded.store(count, Ordering::Relaxed);
    }
    pub fn set_zones_failed(&self, count: u64) {
        self.zones_failed.store(count, Ordering::Relaxed);
    }
    pub fn set_recursive_healthy(&self) {
        self.recursive_healthy.store(true, Ordering::Relaxed);
        self.recursive_degraded.store(false, Ordering::Relaxed);
        self.recursive_disabled.store(false, Ordering::Relaxed);
    }
    pub fn set_recursive_degraded(&self) {
        self.recursive_degraded.store(true, Ordering::Relaxed);
        self.recursive_healthy.store(false, Ordering::Relaxed);
        self.recursive_disabled.store(false, Ordering::Relaxed);
    }
    pub fn set_recursive_disabled(&self) {
        self.recursive_disabled.store(true, Ordering::Relaxed);
        self.recursive_healthy.store(false, Ordering::Relaxed);
        self.recursive_degraded.store(false, Ordering::Relaxed);
    }
    pub fn set_circuit_breaker_open(&self, open: bool) {
        self.circuit_breaker_open.store(open, Ordering::Relaxed);
    }
    pub fn set_cache_operational(&self, operational: bool) {
        self.cache_operational.store(operational, Ordering::Relaxed);
    }
    pub fn set_dnssec_keys_loaded(&self, count: u64) {
        self.dnssec_keys_loaded.store(count, Ordering::Relaxed);
    }
    pub fn set_dnssec_signing_enabled(&self, enabled: bool) {
        self.dnssec_signing_enabled
            .store(enabled, Ordering::Relaxed);
    }
    pub fn set_last_key_rotation(&self, ts: u64) {
        self.last_key_rotation.store(ts, Ordering::Relaxed);
    }
    pub fn set_dot_enabled(&self, enabled: bool) {
        self.dot_enabled.store(enabled, Ordering::Relaxed);
    }
    pub fn set_doh_enabled(&self, enabled: bool) {
        self.doh_enabled.store(enabled, Ordering::Relaxed);
    }
    pub fn set_doq_enabled(&self, enabled: bool) {
        self.doq_enabled.store(enabled, Ordering::Relaxed);
    }
    pub fn set_cert_valid(&self, valid: bool) {
        self.cert_valid.store(valid, Ordering::Relaxed);
    }
    pub fn set_axfr_enabled(&self, enabled: bool) {
        self.axfr_enabled.store(enabled, Ordering::Relaxed);
    }
    pub fn set_ixfr_enabled(&self, enabled: bool) {
        self.ixfr_enabled.store(enabled, Ordering::Relaxed);
    }
    pub fn set_update_enabled(&self, enabled: bool) {
        self.update_enabled.store(enabled, Ordering::Relaxed);
    }
    pub fn set_tsig_required(&self, required: bool) {
        self.tsig_required.store(required, Ordering::Relaxed);
    }

    pub fn record_zone_load_attempt(&self, success: bool, error: Option<String>) {
        self.last_zone_load_time.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
        if success {
            self.zones_loaded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.zones_failed.fetch_add(1, Ordering::Relaxed);
            *self.last_zone_load_error.write() = error;
        }
    }

    /// Build the current health status snapshot.
    pub fn status(&self) -> DnsHealthStatus {
        let bound = self.listener_bound.load(Ordering::Relaxed);
        let loaded = self.zones_loaded.load(Ordering::Relaxed);
        let failed = self.zones_failed.load(Ordering::Relaxed);
        let cache_ok = self.cache_operational.load(Ordering::Relaxed);
        let cert_ok = self.cert_valid.load(Ordering::Relaxed);

        let recursive_state = if self.recursive_disabled.load(Ordering::Relaxed) {
            RecursiveHealth::Disabled
        } else if self.recursive_degraded.load(Ordering::Relaxed)
            || self.circuit_breaker_open.load(Ordering::Relaxed)
        {
            RecursiveHealth::Degraded {
                circuit_breaker_open: self.circuit_breaker_open.load(Ordering::Relaxed),
            }
        } else {
            RecursiveHealth::Healthy
        };

        let liveness = if bound {
            HealthState::Healthy
        } else {
            HealthState::NotReady
        };

        let readiness = if !bound {
            HealthState::NotReady
        } else if failed > 0 || !cache_ok {
            HealthState::Degraded
        } else {
            HealthState::Healthy
        };

        DnsHealthStatus {
            liveness,
            readiness,
            listener_bound: bound,
            zones_loaded: loaded,
            zones_failed: failed,
            recursive_state,
            cache_operational: cache_ok,
            dnssec_state: DnssecHealth {
                keys_loaded: self.dnssec_keys_loaded.load(Ordering::Relaxed),
                last_key_rotation: {
                    let ts = self.last_key_rotation.load(Ordering::Relaxed);
                    if ts > 0 {
                        Some(ts)
                    } else {
                        None
                    }
                },
                signing_enabled: self.dnssec_signing_enabled.load(Ordering::Relaxed),
            },
            encrypted_transport_state: EncryptedTransportHealth {
                dot_enabled: self.dot_enabled.load(Ordering::Relaxed),
                doh_enabled: self.doh_enabled.load(Ordering::Relaxed),
                doq_enabled: self.doq_enabled.load(Ordering::Relaxed),
                cert_valid: cert_ok,
            },
            transfer_update_state: TransferUpdateHealth {
                axfr_enabled: self.axfr_enabled.load(Ordering::Relaxed),
                ixfr_enabled: self.ixfr_enabled.load(Ordering::Relaxed),
                update_enabled: self.update_enabled.load(Ordering::Relaxed),
                tsig_required: self.tsig_required.load(Ordering::Relaxed),
            },
            uptime_seconds: self.start_time.elapsed().as_secs(),
            last_zone_load_time: {
                let ts = self.last_zone_load_time.load(Ordering::Relaxed);
                if ts > 0 {
                    Some(ts)
                } else {
                    None
                }
            },
            last_zone_load_error: self.last_zone_load_error.read().clone(),
        }
    }

    /// Serialize health status as JSON.
    pub fn status_json(&self) -> String {
        serde_json::to_string_pretty(&self.status()).unwrap_or_else(|_| "{}".to_string())
    }
}

impl Default for DnsHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}
