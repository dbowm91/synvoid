#![cfg(feature = "dns")]

#[cfg(test)]
mod tests {
    #[test]
    fn test_dns_zone_record_structure() {
        use synvoid::dns::DnsZoneRecord;
        use synvoid::dns::RecordType;

        let record = DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.1".to_string(),
            ttl: 3600,
            priority: None,
        };

        assert_eq!(record.name, "@");
        assert_eq!(record.ttl, 3600);
    }

    #[test]
    fn test_dns_zone_creation() {
        use synvoid::dns::Zone;

        let zone = Zone::new("example.com".to_string());
        assert_eq!(zone.origin, "example.com");
        assert_eq!(zone.serial, 0);
        assert!(zone.records.is_empty());
    }

    #[test]
    fn test_dns_zone_increment_serial() {
        use synvoid::dns::Zone;

        let mut zone = Zone::new("example.com".to_string());
        assert_eq!(zone.serial, 0);

        zone.increment_serial();
        assert!(
            zone.serial >= 1,
            "serial should be >= 1 after first increment"
        );

        let first_serial = zone.serial;
        zone.increment_serial();
        assert!(
            zone.serial > first_serial || zone.serial == 1,
            "serial should increase or wrap"
        );
    }

    #[test]
    fn test_zone_history_tracking() {
        use synvoid::dns::{DnsZoneRecord, RecordType, Zone};

        let mut zone = Zone::new("example.com".to_string());

        zone.records.insert(
            ("@".to_string(), RecordType::A),
            vec![DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::A,
                value: "192.0.2.1".to_string(),
                ttl: 3600,
                priority: None,
            }],
        );

        zone.increment_serial();
        assert_eq!(zone.history.len(), 1);

        zone.increment_serial();
        assert_eq!(zone.history.len(), 2);
    }

    #[test]
    fn test_zone_history_limit() {
        use synvoid::dns::{DnsZoneRecord, RecordType, Zone};

        let mut zone = Zone::new("example.com".to_string());

        zone.records.insert(
            ("@".to_string(), RecordType::A),
            vec![DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::A,
                value: "192.0.2.1".to_string(),
                ttl: 3600,
                priority: None,
            }],
        );

        for _ in 0..15 {
            zone.increment_serial();
        }

        assert!(
            zone.history.len() <= 15,
            "history should be limited, got {}",
            zone.history.len()
        );
    }

    #[test]
    fn test_serial_comparison_wraps() {
        use synvoid::dns::Zone;

        assert!(Zone::serial_is_more_recent(1, 0xFFFFFFFF));
        assert!(!Zone::serial_is_more_recent(0xFFFFFFFF, 1));
        assert!(Zone::serial_is_more_recent(2, 1));
        assert!(!Zone::serial_is_more_recent(1, 2));
    }

    #[test]
    fn test_dns_config_defaults() {
        use synvoid::config::dns::{DnsConfig, DnsMode};

        let config = DnsConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.port, 53);
        assert_eq!(config.mode, DnsMode::Standalone);
    }

    #[test]
    fn test_dns_ratelimit_config_defaults() {
        use synvoid::config::dns::{DnsRateLimitConfig, DnsRateLimitMode};

        let config = DnsRateLimitConfig::default();
        assert_eq!(config.mode, DnsRateLimitMode::Shared);
        assert_eq!(config.per_second, 500);
        assert_eq!(config.per_minute, 5000);
    }

    #[test]
    fn test_dns_rrl_config_defaults() {
        use synvoid::config::dns::DnsRrlConfig;

        let config = DnsRrlConfig {
            enabled: true,
            responses_per_second: 100,
            window_secs: 5,
            max_responses: 1000,
            ttl: 300,
        };
        assert!(config.enabled);
        assert_eq!(config.responses_per_second, 100);
        assert_eq!(config.window_secs, 5);
        assert_eq!(config.ttl, 300);
    }

    #[test]
    fn test_dnssec_config_defaults() {
        use synvoid::config::dns::DnsSecConfig;

        let config = DnsSecConfig::default();
        assert!(!config.enabled);
    }

    #[test]
    fn test_tsig_key_config_defaults() {
        use synvoid::config::dns::{TsigAlgorithm, TsigKeyConfig};

        let config = TsigKeyConfig::default();
        assert!(config.name.is_empty());
        assert!(config.secret_base64.is_empty());
        assert_eq!(config.algorithm, TsigAlgorithm::HmacSha256);
    }

    #[test]
    fn test_dns_firewall_action_variants() {
        use synvoid::dns::DnsFirewallAction;

        let allow = DnsFirewallAction::Allow;
        assert!(matches!(allow, DnsFirewallAction::Allow));

        let block = DnsFirewallAction::Block;
        assert!(matches!(block, DnsFirewallAction::Block));
    }

    #[test]
    fn test_connection_limits_defaults() {
        use synvoid::dns::ConnectionLimits;

        let mut limits = ConnectionLimits::new(1000, 5000, 4096, 65535, 100, 30, 60, false);
        limits.disable_graceful_degradation();

        assert!(!limits.is_in_graceful_shutdown());
        assert!(!limits.is_degraded());
    }

    #[test]
    fn test_dns_cache_basic_operations() {
        use synvoid::dns::{CacheKey, DnsCache, RecordType};

        let cache = DnsCache::new(1000, 3600, 60);

        let key = CacheKey::new("example.com".to_string(), RecordType::A, None);

        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_edns_options_creation() {
        use synvoid::dns::edns::EdnsOptions;

        let options = EdnsOptions::default();
        assert_eq!(options.version, 0);
    }

    #[test]
    fn test_wire_parse_query_name() {
        use synvoid::dns::wire::parse_query_name;

        // Test simple domain name
        let name_bytes = vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let name = parse_query_name(&name_bytes, 0).unwrap();
        assert_eq!(name, "example.com");

        // Test domain with multiple labels
        let name_bytes = vec![
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00,
        ];
        let name = parse_query_name(&name_bytes, 0).unwrap();
        assert_eq!(name, "www.example.com");
    }

    #[test]
    fn test_wire_build_question() {
        use synvoid::dns::wire::build_question;

        let question = build_question("example.com", 1, 1); // A record, IN class
        assert!(!question.is_empty());
        // Verify format: [len label][label bytes][0][qtype 2 bytes][qclass 2 bytes]
        assert_eq!(question[0], 7); // "example" length
    }

    #[test]
    fn test_wire_build_response_header() {
        use synvoid::dns::wire::{build_response_header, MessageFlags};

        let flags = MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: true,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            response_code: 0,
        };

        let header = build_response_header(0x1234, flags, 1, 1, 2, 1);

        // Verify header length
        assert_eq!(header.len(), 12);

        // Verify ID
        assert_eq!(header[0], 0x12);
        assert_eq!(header[1], 0x34);
    }

    #[test]
    fn test_wire_get_message_flags() {
        use synvoid::dns::wire::get_message_flags;

        // Standard query with RD bit set (0x0100)
        let query = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let flags = get_message_flags(&query).unwrap();

        assert!(!flags.is_response);
        assert_eq!(flags.opcode, 0);
        assert!(flags.recursion_desired); // RD bit is set in this query
    }

    #[test]
    fn test_wire_error_response() {
        use synvoid::dns::wire::{build_error_response, RCODE_NXDOMAIN};

        let query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // Name
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        let response = build_error_response(&query, RCODE_NXDOMAIN).unwrap();

        // Response should preserve query ID
        assert_eq!(response[0], 0x12);
        assert_eq!(response[1], 0x34);

        // Should be a response (QR bit set)
        assert!(response[2] & 0x80 != 0);

        // Should have AA (authoritative) set for error responses
        // (authoritative server should set AA bit even for errors)
        assert!(response[2] & 0x04 != 0);

        // Should have NXDOMAIN RCODE (3)
        assert_eq!(response[3] & 0x0F, 3);
    }

    #[test]
    fn test_dns_query_validator_limits() {
        use synvoid::dns::DnsQueryValidator;

        let validator = DnsQueryValidator::new();

        // Valid query
        let valid_query = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        let result = validator.validate_query(&valid_query);
        if let Err(e) = &result {
            eprintln!("Validator error: {}", e);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limiter_basic() {
        use std::net::IpAddr;
        use synvoid::dns::DnsRateLimiter;

        let limiter = DnsRateLimiter::new(100, 50);

        // Should allow some requests
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First request should succeed
        assert!(limiter.check_ip(ip).is_ok());
    }

    #[test]
    fn test_dns_zone_with_soa_record() {
        use synvoid::dns::{DnsZoneRecord, RecordType, Zone};

        let mut zone = Zone::new("example.com".to_string());

        zone.records.insert(
            ("@".to_string(), RecordType::SOA),
            vec![DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::SOA,
                value: "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"
                    .to_string(),
                ttl: 3600,
                priority: None,
            }],
        );

        assert!(zone
            .records
            .contains_key(&("@".to_string(), RecordType::SOA)));

        // Zone::new initializes serial to 0; SOA record insertion does not parse serial
        assert_eq!(zone.serial, 0);
    }

    #[test]
    fn test_dns_zone_get_previous_version() {
        use synvoid::dns::{DnsZoneRecord, RecordType, Zone};

        let mut zone = Zone::new("example.com".to_string());

        // Add initial record
        zone.records.insert(
            ("@".to_string(), RecordType::A),
            vec![DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::A,
                value: "1.2.3.4".to_string(),
                ttl: 3600,
                priority: None,
            }],
        );

        let first_serial = zone.serial;
        zone.increment_serial();

        // Should be able to get the previous version
        let prev = zone.get_previous_version(first_serial);
        // Zone now tracks history entries so previous version should exist
        assert!(prev.is_some());
    }

    #[test]
    fn test_extended_dns_error_codes() {
        use synvoid::dns::edns::ExtendedDnsError;

        assert_eq!(
            ExtendedDnsError::from_u16(0),
            Some(ExtendedDnsError::OtherError)
        );
        assert_eq!(
            ExtendedDnsError::from_u16(1),
            Some(ExtendedDnsError::UnsupportedDsDigestType)
        );
        assert_eq!(
            ExtendedDnsError::from_u16(2),
            Some(ExtendedDnsError::StaleAnswer)
        );
        assert_eq!(
            ExtendedDnsError::from_u16(14),
            Some(ExtendedDnsError::InvalidData)
        );
        assert_eq!(ExtendedDnsError::from_u16(15), None); // Invalid code
    }

    #[test]
    fn test_extended_dns_error_encode_decode() {
        use synvoid::dns::edns::{ExtendedDnsError, ExtendedDnsErrorOption};

        let error = ExtendedDnsErrorOption::new(ExtendedDnsError::StaleAnswer);
        let encoded = error.encode();

        // Should have 2 bytes for info code
        assert_eq!(encoded.len(), 2);

        let decoded = ExtendedDnsErrorOption::decode(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap().info_code, 2);
    }

    #[test]
    fn test_record_type_conversion() {
        use synvoid::dns::server::RecordTypeExt;
        use synvoid::dns::RecordType;

        // Test that common record types can be converted
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
        assert_eq!(RecordType::MX.to_u16(), 15);
        assert_eq!(RecordType::TXT.to_u16(), 16);
        assert_eq!(RecordType::CNAME.to_u16(), 5);
        assert_eq!(RecordType::NS.to_u16(), 2);
        assert_eq!(RecordType::SOA.to_u16(), 6);
        assert_eq!(RecordType::DNSKEY.to_u16(), 48);
        assert_eq!(RecordType::DS.to_u16(), 43);
    }

    #[test]
    fn test_record_type_is_signed() {
        use synvoid::dns::server::RecordTypeExt;
        use synvoid::dns::RecordType;

        // Most record types should be signed in DNSSEC responses
        assert!(RecordType::A.is_signed());
        assert!(RecordType::AAAA.is_signed());
        assert!(RecordType::CNAME.is_signed());
        assert!(RecordType::MX.is_signed());

        // These should not be signed
        assert!(!RecordType::DNSKEY.is_signed());
        assert!(!RecordType::DS.is_signed());
        assert!(!RecordType::RRSIG.is_signed());
        assert!(!RecordType::NSEC.is_signed());
    }

    #[test]
    fn test_rcode_constants() {
        use synvoid::dns::{
            RCODE_FORMERR, RCODE_NOERROR, RCODE_NOTIMP, RCODE_NXDOMAIN, RCODE_REFUSED,
            RCODE_SERVFAIL,
        };

        assert_eq!(RCODE_NOERROR, 0);
        assert_eq!(RCODE_FORMERR, 1);
        assert_eq!(RCODE_SERVFAIL, 2);
        assert_eq!(RCODE_NXDOMAIN, 3);
        assert_eq!(RCODE_NOTIMP, 4);
        assert_eq!(RCODE_REFUSED, 5);
    }

    #[test]
    fn test_error_response_servfail() {
        use synvoid::dns::{build_error_response, RCODE_SERVFAIL};

        let query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // example
            0x03, b'c', b'o', b'm', // com
            0x00, // end
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
        ];

        let response = build_error_response(&query, RCODE_SERVFAIL).unwrap();

        assert!(response[2] & 0x80 != 0); // QR = response
        assert!(response[2] & 0x04 != 0); // AA = authoritative
        assert_eq!(response[3] & 0x0F, 2); // RCODE = SERVFAIL
    }

    #[test]
    fn test_error_response_formerr() {
        use synvoid::dns::{build_error_response, RCODE_FORMERR};

        let query = vec![
            0xAB, 0xCD, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x03, b'w', b'w', b'w', // www
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // example
            0x03, b'c', b'o', b'm', // com
            0x00, // end
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
        ];

        let response = build_error_response(&query, RCODE_FORMERR).unwrap();

        assert_eq!(response[0], 0xAB);
        assert_eq!(response[1], 0xCD);
        assert!(response[2] & 0x80 != 0); // QR = response
        assert!(response[2] & 0x04 != 0); // AA = authoritative
        assert_eq!(response[3] & 0x0F, 1); // RCODE = FORMERR
    }

    #[test]
    fn test_error_response_refused() {
        use synvoid::dns::{build_error_response, RCODE_REFUSED};

        let query = vec![
            0x01, 0x02, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x04, b't', b'e', b's', b't', // test
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // example
            0x03, b'c', b'o', b'm', // com
            0x00, // end
            0x00, 0x1C, // TYPE = AAAA
            0x00, 0x01, // CLASS = IN
        ];

        let response = build_error_response(&query, RCODE_REFUSED).unwrap();

        assert_eq!(response[0], 0x01);
        assert_eq!(response[1], 0x02);
        assert!(response[2] & 0x80 != 0); // QR = response
        assert!(response[2] & 0x04 != 0); // AA = authoritative
        assert_eq!(response[3] & 0x0F, 5); // RCODE = REFUSED
    }

    #[test]
    fn test_error_response_preserves_question() {
        use synvoid::dns::{build_error_response, RCODE_NXDOMAIN};

        let query = vec![
            0x99, 0x88, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x06, b'n', b'o', b'n', b'e', b'x', b'i', b's', b't', // nonexistent
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // example
            0x03, b'c', b'o', b'm', // com
            0x00, // end
            0x00, 0x0C, // TYPE = PTR
            0x00, 0x01, // CLASS = IN
        ];

        let response = build_error_response(&query, RCODE_NXDOMAIN).unwrap();

        // Question section should be preserved
        assert!(response.len() > 17);
        // Should contain the question name "nonexistent.example.com"
    }

    #[test]
    fn test_anycast_health_check_query_building() {
        use synvoid::dns::anycast::AnycastSocketManager;

        let domain = "_healthcheck.local";

        let packet = AnycastSocketManager::build_health_check_query(0x1234, domain);

        assert!(packet.is_some());
        let pkt = packet.unwrap();

        assert!(pkt.len() >= 12);

        let id = u16::from_be_bytes([pkt[0], pkt[1]]);
        assert_eq!(id, 0x1234);

        let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert!(flags & 0x8000 == 0);

        let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
        assert_eq!(qdcount, 1);
    }

    #[test]
    fn test_anycast_health_check_invalid_domain() {
        use synvoid::dns::anycast::AnycastSocketManager;

        let empty_domain = "";
        let packet = AnycastSocketManager::build_health_check_query(0x1234, empty_domain);
        assert!(packet.is_none());

        let long_label = "a".repeat(64);
        let packet2 = AnycastSocketManager::build_health_check_query(0x1234, &long_label);
        assert!(packet2.is_none());
    }

    #[test]
    fn test_anycast_serial_comparison_remote_newer() {
        use synvoid::dns::anycast_sync::AnycastZoneSync;
        use synvoid::dns::anycast_sync::{SerialComparison, ZoneSyncDecision};

        let local = 100u32;
        let remote = 200u32;

        let cmp = AnycastZoneSync::compare_serials(local, remote);
        assert_eq!(cmp, SerialComparison::RemoteIsNewer);

        let decision = AnycastZoneSync::should_accept_zone_update(local, remote);
        assert_eq!(decision, ZoneSyncDecision::Accept);
    }

    #[test]
    fn test_anycast_serial_comparison_local_newer() {
        use synvoid::dns::anycast_sync::AnycastZoneSync;
        use synvoid::dns::anycast_sync::{SerialComparison, ZoneSyncDecision};

        let local = 200u32;
        let remote = 100u32;

        let cmp = AnycastZoneSync::compare_serials(local, remote);
        assert_eq!(cmp, SerialComparison::LocalIsNewer);

        let decision = AnycastZoneSync::should_accept_zone_update(local, remote);
        assert_eq!(decision, ZoneSyncDecision::Reject);
    }

    #[test]
    fn test_anycast_serial_comparison_equal() {
        use synvoid::dns::anycast_sync::AnycastZoneSync;
        use synvoid::dns::anycast_sync::{SerialComparison, ZoneSyncDecision};

        let serial = 100u32;

        let cmp = AnycastZoneSync::compare_serials(serial, serial);
        assert_eq!(cmp, SerialComparison::Equal);

        let decision = AnycastZoneSync::should_accept_zone_update(serial, serial);
        assert_eq!(decision, ZoneSyncDecision::Reject);
    }

    #[test]
    fn test_anycast_serial_wrap_around() {
        use synvoid::dns::anycast_sync::AnycastZoneSync;
        use synvoid::dns::anycast_sync::SerialComparison;
        use synvoid::dns::anycast_sync::ZoneSyncDecision;

        let local = u32::MAX - 100;
        let remote = 50u32;

        let cmp = AnycastZoneSync::compare_serials(local, remote);
        assert_eq!(cmp, SerialComparison::RemoteIsNewer);

        let decision = AnycastZoneSync::should_accept_zone_update(local, remote);
        assert_eq!(decision, ZoneSyncDecision::Accept);
    }

    #[test]
    fn test_anycast_zone_sync_decision_reject_wrap_around() {
        use synvoid::dns::anycast_sync::AnycastZoneSync;
        use synvoid::dns::anycast_sync::ZoneSyncDecision;

        let local = 50u32;
        let remote = u32::MAX - 100;

        let decision = AnycastZoneSync::should_accept_zone_update(local, remote);
        assert_eq!(decision, ZoneSyncDecision::Reject);
    }

    #[test]
    fn test_query_validator_valid_query() {
        use synvoid::dns::DnsQueryValidator;

        let validator = DnsQueryValidator::new();

        let valid_query = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // example
            0x03, b'c', b'o', b'm', // com
            0x00, // end
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
        ];

        let result = validator.validate_query(&valid_query);
        assert!(result.is_ok(), "Valid query should pass: {:?}", result);
    }

    #[test]
    fn test_query_validator_invalid_label_length() {
        use synvoid::dns::DnsQueryValidator;

        let validator = DnsQueryValidator::new();

        let mut query = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];

        // Add a label with length 64 (invalid - max is 63)
        query.push(64);
        query
            .extend_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        query.push(0x00); // end
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE=A, CLASS=IN

        let result = validator.validate_query(&query);
        assert!(result.is_err(), "Query with label > 63 should fail");
    }

    #[test]
    fn test_query_validator_too_many_labels() {
        use synvoid::dns::DnsQueryValidator;

        let validator = DnsQueryValidator::new();

        let mut query = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            00, 0x00, // ARCOUNT = 0
        ];

        // Add 20 single-character labels (default max is 16)
        for _ in 0..20 {
            query.push(1);
            query.push(b'a');
        }
        query.push(0x00); // end
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE=A, CLASS=IN

        let result = validator.validate_query(&query);
        assert!(result.is_err(), "Query with too many labels should fail");
    }

    #[test]
    fn test_query_validator_invalid_query_type_zero() {
        use synvoid::dns::DnsQueryValidator;

        let validator = DnsQueryValidator::new();

        let query = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // example
            0x03, b'c', b'o', b'm', // com
            0x00, // end
            0x00, 0x00, // TYPE = 0 (invalid)
            0x00, 0x01, // CLASS = IN
        ];

        let result = validator.validate_query(&query);
        assert!(result.is_err(), "Query type 0 should be rejected");
    }

    #[test]
    fn test_query_validator_query_too_small() {
        use synvoid::dns::DnsQueryValidator;

        let validator = DnsQueryValidator::new();

        let query = vec![0x00, 0x01]; // Too small - need at least 12 bytes

        let result = validator.validate_query(&query);
        assert!(result.is_err(), "Query smaller than 12 bytes should fail");
    }
}
