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
    /// Realized-vs-requested capability matrix.
    pub capabilities: DnsCapabilities,
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

/// How recursive answers are DNSSEC-validated, as actually realized.
///
/// A forwarder that is only trusted to validate is `delegated`, never
/// `enabled`: reporting local validation for a resolver that performs none is
/// the health-truth failure this field exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnssecValidationHealth {
    /// The recursor validates every answer locally.
    Enabled,
    /// Validation is delegated to the upstream forwarder.
    Delegated,
    /// Recursive validation is not configured (or recursion is off).
    Disabled,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnssecHealth {
    pub keys_loaded: u64,
    pub last_key_rotation: Option<u64>,
    pub signing_enabled: bool,
    /// Realized recursive validation state, not the configured intent.
    pub validation: DnssecValidationHealth,
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

/// The DNS capabilities `/health` reports one by one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCapability {
    Axfr,
    Ixfr,
    Update,
    Notify,
    DnssecSigning,
    Recursive,
    Dot,
    Doh,
    Doq,
}

impl DnsCapability {
    /// Number of capabilities, kept in one place so the cells array and the
    /// serialized struct cannot drift.
    pub const COUNT: usize = 9;

    fn index(self) -> usize {
        match self {
            Self::Axfr => 0,
            Self::Ixfr => 1,
            Self::Update => 2,
            Self::Notify => 3,
            Self::DnssecSigning => 4,
            Self::Recursive => 5,
            Self::Dot => 6,
            Self::Doh => 7,
            Self::Doq => 8,
        }
    }
}

/// A capability's realized state against what configuration asked for.
///
/// The pair exists so a mismatch is visible rather than inferred: `realized`
/// is set only by the code that built the handler, bound the listener, or
/// loaded the key, while `config_requested` is the config value the runtime
/// received. Neither is derived from the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CapabilityRealization {
    pub realized: bool,
    pub config_requested: bool,
}

/// The `dns.capabilities` block of `/health`.
#[derive(Debug, Clone, Serialize)]
pub struct DnsCapabilities {
    pub axfr: CapabilityRealization,
    pub ixfr: CapabilityRealization,
    pub update: CapabilityRealization,
    pub notify: CapabilityRealization,
    pub dnssec_signing: CapabilityRealization,
    pub recursive: CapabilityRealization,
    pub dot: CapabilityRealization,
    pub doh: CapabilityRealization,
    pub doq: CapabilityRealization,
}

struct CapabilityCells {
    realized: [AtomicBool; DnsCapability::COUNT],
    config_requested: [AtomicBool; DnsCapability::COUNT],
}

impl CapabilityCells {
    fn new() -> Self {
        Self {
            realized: std::array::from_fn(|_| AtomicBool::new(false)),
            config_requested: std::array::from_fn(|_| AtomicBool::new(false)),
        }
    }

    fn set_realized(&self, capability: DnsCapability, realized: bool) {
        self.realized[capability.index()].store(realized, Ordering::Relaxed);
    }

    fn set_config_requested(&self, capability: DnsCapability, requested: bool) {
        self.config_requested[capability.index()].store(requested, Ordering::Relaxed);
    }

    fn get(&self, capability: DnsCapability) -> CapabilityRealization {
        CapabilityRealization {
            realized: self.realized[capability.index()].load(Ordering::Relaxed),
            config_requested: self.config_requested[capability.index()].load(Ordering::Relaxed),
        }
    }
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
    dnssec_validation: RwLock<DnssecValidationHealth>,
    last_key_rotation: AtomicU64,
    cert_valid: AtomicBool,
    tsig_required: AtomicBool,
    /// Single source of truth for every capability flag. The legacy named
    /// getters read the same cells, so `transfer_update_state` and
    /// `capabilities` cannot disagree.
    capabilities: CapabilityCells,
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
            dnssec_validation: RwLock::new(DnssecValidationHealth::Disabled),
            last_key_rotation: AtomicU64::new(0),
            cert_valid: AtomicBool::new(false),
            tsig_required: AtomicBool::new(false),
            capabilities: CapabilityCells::new(),
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
        self.capabilities
            .set_realized(DnsCapability::Recursive, true);
    }
    pub fn set_recursive_degraded(&self) {
        self.recursive_degraded.store(true, Ordering::Relaxed);
        self.recursive_healthy.store(false, Ordering::Relaxed);
        self.recursive_disabled.store(false, Ordering::Relaxed);
        self.capabilities
            .set_realized(DnsCapability::Recursive, false);
    }
    pub fn set_recursive_disabled(&self) {
        self.recursive_disabled.store(true, Ordering::Relaxed);
        self.recursive_healthy.store(false, Ordering::Relaxed);
        self.recursive_degraded.store(false, Ordering::Relaxed);
        self.capabilities
            .set_realized(DnsCapability::Recursive, false);
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
    /// Record whether DNSSEC signing is **realized**: at least one loaded zone
    /// holds a ZSK handle. Config enabling DNSSEC is not evidence of this.
    pub fn set_dnssec_signing_enabled(&self, enabled: bool) {
        self.capabilities
            .set_realized(DnsCapability::DnssecSigning, enabled);
    }
    /// Record the realized recursive validation state.
    pub fn set_dnssec_validation(&self, validation: DnssecValidationHealth) {
        *self.dnssec_validation.write() = validation;
    }
    pub fn set_last_key_rotation(&self, ts: u64) {
        self.last_key_rotation.store(ts, Ordering::Relaxed);
    }
    /// Record that the DoT listener is actually bound.
    pub fn set_dot_enabled(&self, enabled: bool) {
        self.capabilities.set_realized(DnsCapability::Dot, enabled);
    }
    /// Record that the DoH listener is actually bound.
    pub fn set_doh_enabled(&self, enabled: bool) {
        self.capabilities.set_realized(DnsCapability::Doh, enabled);
    }
    /// Record that the DoQ listener is actually bound.
    pub fn set_doq_enabled(&self, enabled: bool) {
        self.capabilities.set_realized(DnsCapability::Doq, enabled);
    }
    pub fn set_cert_valid(&self, valid: bool) {
        self.cert_valid.store(valid, Ordering::Relaxed);
    }
    /// Record that an AXFR-capable handler is attached.
    pub fn set_axfr_enabled(&self, enabled: bool) {
        self.capabilities.set_realized(DnsCapability::Axfr, enabled);
    }
    /// Record that an IXFR-capable handler is attached.
    pub fn set_ixfr_enabled(&self, enabled: bool) {
        self.capabilities.set_realized(DnsCapability::Ixfr, enabled);
    }
    /// Record that an UPDATE handler is attached.
    pub fn set_update_enabled(&self, enabled: bool) {
        self.capabilities
            .set_realized(DnsCapability::Update, enabled);
    }
    /// Record that a NOTIFY handler is attached.
    pub fn set_notify_enabled(&self, enabled: bool) {
        self.capabilities
            .set_realized(DnsCapability::Notify, enabled);
    }
    /// Record whether configuration asked for a capability.
    ///
    /// Called once from the constructor, where the runtime config is known.
    /// It never sets `realized`: only the code that built the thing can.
    pub fn set_capability_config_requested(&self, capability: DnsCapability, requested: bool) {
        self.capabilities
            .set_config_requested(capability, requested);
    }
    /// One capability's realized-vs-requested pair.
    pub fn capability(&self, capability: DnsCapability) -> CapabilityRealization {
        self.capabilities.get(capability)
    }
    /// The whole capability matrix.
    pub fn capabilities(&self) -> DnsCapabilities {
        DnsCapabilities {
            axfr: self.capability(DnsCapability::Axfr),
            ixfr: self.capability(DnsCapability::Ixfr),
            update: self.capability(DnsCapability::Update),
            notify: self.capability(DnsCapability::Notify),
            dnssec_signing: self.capability(DnsCapability::DnssecSigning),
            recursive: self.capability(DnsCapability::Recursive),
            dot: self.capability(DnsCapability::Dot),
            doh: self.capability(DnsCapability::Doh),
            doq: self.capability(DnsCapability::Doq),
        }
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
                signing_enabled: self.capability(DnsCapability::DnssecSigning).realized,
                validation: *self.dnssec_validation.read(),
            },
            encrypted_transport_state: EncryptedTransportHealth {
                dot_enabled: self.capability(DnsCapability::Dot).realized,
                doh_enabled: self.capability(DnsCapability::Doh).realized,
                doq_enabled: self.capability(DnsCapability::Doq).realized,
                cert_valid: cert_ok,
            },
            transfer_update_state: TransferUpdateHealth {
                axfr_enabled: self.capability(DnsCapability::Axfr).realized,
                ixfr_enabled: self.capability(DnsCapability::Ixfr).realized,
                update_enabled: self.capability(DnsCapability::Update).realized,
                tsig_required: self.tsig_required.load(Ordering::Relaxed),
            },
            capabilities: self.capabilities(),
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
