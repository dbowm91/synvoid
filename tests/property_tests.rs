#![cfg(feature = "dns")]

use proptest::prelude::*;

proptest! {
    /// DNS encode_name → parse_query_name roundtrip identity
    #[test]
    fn dns_encode_parse_roundtrip(name in "[a-z]{1,10}(\\.[a-z]{1,10}){0,3}") {
        let encoded = synvoid::dns::wire::encode_name(&name);
        let parsed = synvoid::dns::wire::parse_query_name(&encoded, 0);
        // parse_query_name lowercases the result
        prop_assert_eq!(parsed, Some(name.to_lowercase()));
    }

    /// DNS get_message_id on build_response_header preserves ID
    #[test]
    fn dns_message_id_preserved(id in 0u16..=65535u16) {
        use synvoid::dns::wire::MessageFlags;
        let flags = MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            response_code: 0,
        };
        let response = synvoid::dns::wire::build_response_header(id, flags, 1, 0, 0, 0);
        let parsed_id = synvoid::dns::wire::get_message_id(&response);
        prop_assert_eq!(parsed_id, Some(id));
    }

    /// DNS build_question produces valid wire format
    #[test]
    fn dns_build_question_valid(
        name in "[a-z]{1,8}(\\.[a-z]{1,8}){1,2}",
        qtype in 1u16..=65535u16,
    ) {
        let question = synvoid::dns::wire::build_question(&name, qtype, 1);
        // Question should be at least: name bytes + 0 terminator + 2 type + 2 class
        prop_assert!(question.len() >= name.len() + 5);
        // Last 4 bytes should be qtype + qclass
        let parsed_qtype = u16::from_be_bytes([question[question.len()-4], question[question.len()-3]]);
        prop_assert_eq!(parsed_qtype, qtype);
    }

    /// DNS build_error_response preserves query ID
    #[test]
    fn dns_error_response_preserves_id(id in 0u16..=65535u16) {
        let mut query = Vec::new();
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&[0x01, 0x00]); // standard query flags
        query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
        // minimal question: \x03www\x07example\x03com\x00 + type + class
        query.extend_from_slice(b"\x03www\x07example\x03com\x00");
        query.extend_from_slice(&[0x00, 0x01]); // A record
        query.extend_from_slice(&[0x00, 0x01]); // IN class

        if let Some(response) = synvoid::dns::wire::build_error_response(&query, 3) {
            let parsed_id = synvoid::dns::wire::get_message_id(&response);
            prop_assert_eq!(parsed_id, Some(id));
        }
    }

    /// DNS wire encode_name produces null-terminated output
    #[test]
    fn dns_encode_name_terminates(name in "[a-z]{1,5}(\\.[a-z]{1,5}){0,2}") {
        let encoded = synvoid::dns::wire::encode_name(&name);
        prop_assert!(!encoded.is_empty());
        prop_assert_eq!(*encoded.last().unwrap(), 0u8);
    }

    /// MessageFlags is_nxdomain for rcode 3
    #[test]
    fn dns_flags_nxdomain(rcode in 0u8..=15u8) {
        use synvoid::dns::wire::MessageFlags;
        let flags = MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            response_code: rcode,
        };
        prop_assert_eq!(flags.is_nxdomain(), rcode == 3);
    }

    /// MessageFlags is_standard_query
    #[test]
    fn dns_flags_standard_query(opcode in 0u8..=15u8) {
        use synvoid::dns::wire::MessageFlags;
        let flags = MessageFlags {
            is_response: false,
            opcode,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: false,
            authentic_data: false,
            response_code: 0,
        };
        prop_assert_eq!(flags.is_standard_query(), opcode == 0);
    }
}
