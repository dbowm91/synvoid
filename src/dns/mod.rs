//! DNS Server module for MaluWAF
//!
//! This module provides an authoritative DNS server,
//! with support for:
//! - Standalone operation (manual zone configuration)
//! - Mesh mode (dynamic registration from edge nodes)
//! - DNSSEC signing
//! - Geo-steering based on client location and node health
//! - DNS-over-TLS (DoT)
//! - DNS-over-HTTPS (DoH)
//! - DNS-over-Quic (DoQ)
//! - Dynamic Updates (RFC 2136)

pub mod anycast;
pub mod anycast_sync;
pub mod cache;
pub mod compression;
pub mod config;
pub mod cookie;
pub mod crypto_rng;
pub mod dns64;
pub mod dnssec;
pub mod doh;
pub mod doq;
pub mod dot;
pub mod edns;
pub mod firewall;
pub mod hsm;
pub mod limits;
pub mod mesh_dnssec;
pub mod mesh_sync;
pub mod messages;
pub mod metrics;
pub mod notify;
pub mod platform;
pub mod qname;
pub mod query_coalesce;
pub mod query_validator;
pub mod recursive;
pub mod recursive_cache;
pub mod resolver;
pub mod rpz;
pub mod secure_server;
pub mod server;
pub mod store;
pub mod transfer;
pub mod trust_anchor;
pub mod tsig;
pub mod update;
pub mod wire;
pub mod zone_file;
pub mod zone_trie;

pub use wire::{
    build_error_response, build_question, build_response_header, get_message_flags, get_message_id,
    parse_dns_message, parse_query_name, MessageFlags, OPCODE_IQUERY, OPCODE_NOTIFY, OPCODE_QUERY,
    OPCODE_STATUS, OPCODE_UPDATE, RCODE_FORMERR, RCODE_NOERROR, RCODE_NOTIMP, RCODE_NXDOMAIN,
    RCODE_REFUSED, RCODE_SERVFAIL, UPDATE_RCODE_FORMERR, UPDATE_RCODE_NOERROR,
    UPDATE_RCODE_NOTAUTH, UPDATE_RCODE_NOTIMP, UPDATE_RCODE_NOTZONE, UPDATE_RCODE_NXDOMAIN,
    UPDATE_RCODE_NXRRSET, UPDATE_RCODE_REFUSED, UPDATE_RCODE_SERVFAIL, UPDATE_RCODE_YXDOMAIN,
    UPDATE_RCODE_YXRRSET,
};

pub use crate::config::dns::{
    RecursiveCacheConfig, RecursiveDnsConfig, RecursiveUpstreamProvider, RecursiveUpstreamServer,
};
pub use anycast::{AnycastHealthUpdate, AnycastPacketInfo, AnycastSocketManager};
pub use anycast_sync::{
    AnycastZoneSync, SerialComparison, SerializedRecord, SerializedZoneData, ZoneSyncDecision,
    ZoneSyncMetadata, ZoneSyncReason,
};
pub use cache::{
    CacheKey, CachePoisoningError, CacheStats, CachedResponse, DnsCache, SecureDnsCache,
};
pub use config::DnsSettings;
pub use cookie::{build_cookie_option, DnsCookieServer};
pub use dns64::{Dns64Config, Dns64Translator};
pub use dnssec::{
    Algorithm, DnsSecKeyManager, DnsSecKeyStatus, KeyInfo, KeyRotationConfig, KeyRotationResult,
    KeyType, ZoneSigningKey,
};
pub use doh::DohServer;
pub use doq::DoqServer;
pub use dot::DotServer;
pub use firewall::{
    DnsFirewall, DnsFirewallAction, DnsFirewallDecision, DnsFirewallRule, DnsFirewallRuleType,
    DnsFirewallStats,
};
pub use hsm::{HsmBackend, HsmError, HsmManager, HsmSigner, Pkcs11Hsm, SoftHsm};
pub use limits::{ConnectionLimitError, ConnectionLimits, ConnectionStats};
pub use mesh_sync::{
    MeshDnsRegistry, MeshDnsRegistryConfig, MeshNodeCertificate, RegisteredAnycastNode,
    RegisteredEdgeNode, RegisteredOriginNode, VerificationMetricsSummary,
};
pub use messages::{
    DnsAnycastHealthUpdate, DnsAnycastNodeRegistration, DnsEdgeHealthReport, DnsHealthUpdate,
    DnsNodeRole, DnsNodeShutdown, DnsRegistration, DnsRegistrationRequest,
    DnsRegistrationWithVerificationRequest, DnsRegistrationWithVerificationResponse, DnsZoneSync,
    DomainVerificationRequest, DomainVerificationResponse, DomainVerificationStatus,
    DomainVerificationStatusUpdate, DomainVerificationType,
};
pub use metrics::{
    DnsMetrics, DnsMetricsSummary, DnsSecurityEvent, DnsSecurityEventSeverity,
    DnsSecurityEventType, DnsSecurityLogger,
};
pub use notify::{build_notify_response, NotifyConfig, NotifyHandler};
pub use platform::{create_platform, AnycastSocketPlatform};
pub use qname::{QnameMinimizer, RebindingChecker};
pub use query_coalesce::{CoalesceResult, QueryCoalescer, QueryKey};
pub use query_validator::{DnsQueryClass, DnsQueryType, DnsQueryValidator};
pub use recursive::{RecursiveDnsError, RecursiveDnsResult, RecursiveDnsServer};
pub use recursive_cache::{
    CacheEntry, CachedRecord, NegativeCacheEntry, PositiveCacheEntry, RecursiveCacheKey,
    RecursiveCacheStats, RecursiveDnsCache, RecursiveRecordType,
};
pub use resolver::{
    CdsRecord, DnsKeyRecord, DnsResolver, HickoryRecursor, HickoryResolver, NoopResolver, NsRecord,
    ResolverError, ResolverResult, Rfc5011CheckResult, TxtRecord,
};
pub use rpz::{RpzAction, RpzManager, RpzPolicy, RpzZone};
pub use secure_server::{
    DnsServerConfig, SecureDnsServerBase, MAX_QUERY_SIZE, TLS_HANDSHAKE_TIMEOUT_SECS,
};
pub use server::{DnsRateLimiter, DnsServer, DnsZoneRecord, DsRecordExport, RecordType, Zone};
pub use store::ZoneStore;
pub use transfer::{ZoneTransfer, AXFR_QUERY_TYPE, IXFR_QUERY_TYPE};
pub use trust_anchor::{
    Rfc5011Event, TrustAnchorConfig, TrustAnchorManager, TrustAnchorState, TrustAnchorStatus,
};
pub use tsig::{parse_tsig_from_query, TsigError, TsigKey, TsigParseResult, TsigVerifier};
pub use update::{DynamicUpdate, DynamicUpdateHandler};
pub use zone_file::{
    parse_zone_content, parse_zone_file, ParsedRecord, ZoneFileParser, ZoneParseError,
};
