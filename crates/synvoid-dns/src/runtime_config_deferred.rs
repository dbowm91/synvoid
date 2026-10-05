//! Temporary persistence passthrough for Phases 127/128 (NOT runtime DTO).
//!
//! **This module is deliberately separate from `runtime_config`.** The
//! DNS-owned runtime vocabulary must never reference the persistence schema
//! (enforced by
//! `tools/synvoid-repo-guards/tests/dns_runtime_config_ownership.rs`), so the
//! sections that Phases 127/128 have not converted yet live here instead,
//! where that edge is unmissable.
//!
//! Each field below is deleted as its owning phase lands:
//!
//! | Field | Owning phase |
//! |---|---|
//! | `recursive` | Phase 127 — recursive runtime cutover |
//! | `dnssec` (incl. HSM + TSIG) | Phase 128 — DNSSEC/TSIG/HSM conversion |
//! | `zones` | Phase 128 — zone conversion |
//!
//! **Phase 128 deletes this module together with the `synvoid-config`
//! dependency edge.** Nothing in the authoritative request path reads these
//! values; the only readers are recursive startup and zone/DNSSEC startup.

/// Persisted DNS sections whose runtime conversion belongs to later phases of
/// the campaign.
#[derive(Debug, Clone)]
pub struct DeferredDnsConfig {
    /// Recursive resolver subtree — converted in Phase 127.
    pub recursive: synvoid_config::dns::RecursiveDnsConfig,
    /// Global DNSSEC policy, HSM settings, and zone data — converted in
    /// Phase 128.
    pub dnssec: synvoid_config::dns::DnsSecConfig,
    /// Zone data — converted in Phase 128.
    pub zones: synvoid_config::dns::DnsZonesConfig,
}

impl DeferredDnsConfig {
    /// Whether the recursive subsystem is requested.
    pub fn recursive_enabled(&self) -> bool {
        self.recursive.enabled
    }

    /// Whether DNSSEC signing is requested.
    pub fn dnssec_enabled(&self) -> bool {
        self.dnssec.enabled
    }
}
