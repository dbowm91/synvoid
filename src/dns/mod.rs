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
pub mod crypto_rng;
pub mod cookie;
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
pub mod platform;
pub mod qname;
pub mod query_validator;
pub mod resolver;
pub mod rpz;
pub mod server;
pub mod store;
pub mod transfer;
pub mod tsig;
pub mod update;
pub mod notify;
pub mod wire;
pub mod zone_file;
pub mod query_coalesce;
pub mod zone_trie;

pub use wire::{
    build_error_response, build_question, build_response_header,
    get_message_id, get_message_flags, parse_dns_message, parse_query_name,
    MessageFlags, RCODE_NOERROR, RCODE_FORMERR, RCODE_SERVFAIL, RCODE_NXDOMAIN, RCODE_NOTIMP, RCODE_REFUSED,
    OPCODE_QUERY, OPCODE_IQUERY, OPCODE_STATUS, OPCODE_NOTIFY, OPCODE_UPDATE,
    UPDATE_RCODE_NOERROR, UPDATE_RCODE_FORMERR, UPDATE_RCODE_SERVFAIL,
    UPDATE_RCODE_NXDOMAIN, UPDATE_RCODE_NOTIMP, UPDATE_RCODE_REFUSED,
    UPDATE_RCODE_YXDOMAIN, UPDATE_RCODE_YXRRSET, UPDATE_RCODE_NXRRSET,
    UPDATE_RCODE_NOTAUTH, UPDATE_RCODE_NOTZONE,
};

pub use dns64::{Dns64Config, Dns64Translator};
pub use dnssec::{DnsSecKeyManager, KeyRotationConfig, KeyRotationResult, KeyInfo, DnsSecKeyStatus, Algorithm, KeyType, ZoneSigningKey};
pub use cache::{CacheKey, CacheStats, CachedResponse, DnsCache, SecureDnsCache, CachePoisoningError};
pub use cookie::{DnsCookieServer, build_cookie_option};
pub use config::DnsSettings;
pub use firewall::{DnsFirewall, DnsFirewallDecision, DnsFirewallRule, DnsFirewallRuleType, DnsFirewallStats, DnsFirewallAction};
pub use limits::{ConnectionLimitError, ConnectionLimits, ConnectionStats};
pub use hsm::{HsmManager, HsmSigner, HsmError, HsmBackend, Pkcs11Hsm, SoftHsm};
pub use mesh_sync::{MeshDnsRegistry, MeshDnsRegistryConfig, MeshNodeCertificate, RegisteredEdgeNode, RegisteredOriginNode, RegisteredAnycastNode, VerificationMetricsSummary};
pub use messages::{DnsHealthUpdate, DnsRegistration, DnsRegistrationRequest, DnsZoneSync, DnsNodeRole, DnsNodeShutdown, DnsEdgeHealthReport, DomainVerificationRequest, DomainVerificationResponse, DomainVerificationType, DomainVerificationStatus, DnsRegistrationWithVerificationRequest, DnsRegistrationWithVerificationResponse, DomainVerificationStatusUpdate, DnsAnycastHealthUpdate, DnsAnycastNodeRegistration};
pub use metrics::{DnsMetrics, DnsMetricsSummary, DnsSecurityEvent, DnsSecurityEventSeverity, DnsSecurityEventType, DnsSecurityLogger};
pub use qname::{QnameMinimizer, RebindingChecker};
pub use query_validator::{DnsQueryClass, DnsQueryType, DnsQueryValidator};
pub use resolver::{DnsResolver, HickoryResolver, NoopResolver, TxtRecord, NsRecord, ResolverError, ResolverResult};
pub use rpz::{RpzAction, RpzManager, RpzPolicy, RpzZone};
pub use server::{DnsRateLimiter, DnsServer, DnsZoneRecord, DsRecordExport, RecordType, Zone};
pub use store::ZoneStore;
pub use transfer::{AXFR_QUERY_TYPE, IXFR_QUERY_TYPE, ZoneTransfer};
pub use tsig::{TsigVerifier, TsigKey, TsigError, TsigParseResult, parse_tsig_from_query};
pub use update::{DynamicUpdateHandler, DynamicUpdate};
pub use notify::{NotifyHandler, NotifyConfig, build_notify_response};
pub use doh::DohServer;
pub use dot::DotServer;
pub use doq::DoqServer;
pub use zone_file::{ZoneFileParser, parse_zone_file, parse_zone_content, ZoneParseError, ParsedRecord};
pub use query_coalesce::{QueryCoalescer, QueryKey, CoalesceResult};
pub use anycast::{AnycastSocketManager, AnycastPacketInfo, AnycastHealthUpdate};
pub use anycast_sync::{AnycastZoneSync, ZoneSyncMetadata, SerializedZoneData, SerializedRecord, ZoneSyncReason};
pub use platform::{AnycastSocketPlatform, create_platform};
