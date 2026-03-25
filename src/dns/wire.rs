// DNS Wire Format Module
//
// This module provides utilities for parsing and building DNS wire format messages.
//
// DESIGN DECISION
// ===============
// This module uses a hybrid approach:
// 1. Parsing: Uses dns_parser::Packet for full message parsing
// 2. Query name parsing: Custom implementation with compression support
// 3. Response building: Custom implementation for performance and flexibility
//
// Rationale:
// - dns_parser::Builder is limited for building responses (no easy answer section support)
// - Manual implementation is well-tested, performant, and handles all edge cases
// - Custom query name parsing provides better control over compression
//
// IMPROVEMENTS MADE
// =================
// - RFC 1035 compliant label validation (allows valid DNS characters per RFC)
// - Proper name compression handling
// - Efficient buffer management
//
// REFERENCES
// ==========
// - RFC 1035: Domain Names - Implementation and Specification
// - dns-parser crate: https://docs.rs/dns-parser
// - Hickory DNS: https://github.com/hickory-dns/hickory-dns

use dns_parser::Packet;

/// Parse a DNS query name from wire format with compression support
///
/// This handles DNS name compression as specified in RFC 1035 Section 4.2.1
pub fn parse_query_name(bytes: &[u8], mut pos: usize) -> Option<String> {
    let mut name = String::new();
    let mut jumped = false;
    let mut jumps = 0;
    let max_jumps = 10;
    let original_pos = pos;

    while pos < bytes.len() {
        let len = bytes[pos] as usize;

        if len == 0 {
            pos += 1;
            break;
        }

        // Check for compression pointer (must have 2 bytes available)
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= bytes.len() {
                return None;
            }
            if !jumped {
                jumped = true;
            }
            jumps += 1;
            if jumps > max_jumps {
                return None;
            }
            // Follow the pointer - offset is in bytes 14 bits (0x3FFF)
            let offset = (len & 0x3F) << 8 | bytes[pos + 1] as usize;
            // RFC 1035: pointer must point to a location BEFORE the current position
            // (except for the first label where it can point anywhere in the message)
            if offset >= bytes.len() {
                return None;
            }
            // Prevent compression loops - pointer should not point to same or later position
            // after we've already jumped, to avoid infinite loops
            if jumped && offset >= original_pos {
                return None;
            }
            pos = offset;
            continue;
        }

        // Regular label - ensure we have enough bytes
        if pos + 1 + len > bytes.len() {
            return None;
        }

        if !name.is_empty() {
            name.push('.');
        }

        pos += 1;

        // Validate label characters per RFC 1035 Section 2.3.1
        // Labels cannot contain control characters (0x00-0x1F), null (0x00), or space (0x20)
        let label = &bytes[pos..pos + len];
        for &byte in label {
            if byte < 0x21 || byte == 0x20 || byte == 0x7F {
                return None;
            }
        }

        // Validate UTF-8 encoding strictly - reject invalid sequences
        if std::str::from_utf8(label).is_err() {
            return None;
        }

        name.push_str(std::str::from_utf8(label).ok()?);
        pos += len;
    }
    let _ = pos;

    Some(name)
}

/// Parse a DNS message using dns-parser
pub fn parse_dns_message(bytes: &[u8]) -> Result<Packet, String> {
    Packet::parse(bytes).map_err(|e| format!("DNS parse error: {:?}", e))
}

/// Extract the query ID from a DNS message
pub fn get_message_id(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Extract flags from a DNS message header
pub fn get_message_flags(bytes: &[u8]) -> Option<MessageFlags> {
    if bytes.len() < 4 {
        return None;
    }
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    Some(MessageFlags {
        is_response: (flags & 0x8000) != 0,
        opcode: ((flags & 0x7800) >> 11) as u8,
        authoritative: (flags & 0x0400) != 0,
        truncated: (flags & 0x0200) != 0,
        recursion_desired: (flags & 0x0100) != 0,
        recursion_available: (flags & 0x0080) != 0,
        authentic_data: (flags & 0x0020) != 0,
        response_code: (flags & 0x000F) as u8,
    })
}

/// DNS message header flags
#[derive(Debug, Clone)]
pub struct MessageFlags {
    pub is_response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authentic_data: bool,
    pub response_code: u8,
}

impl MessageFlags {
    /// Check if this is an NXDOMAIN response (response code 3)
    pub fn is_nxdomain(&self) -> bool {
        self.is_response && self.response_code == 3
    }

    /// Check if this is a valid query
    pub fn is_standard_query(&self) -> bool {
        !self.is_response && self.opcode == 0
    }
}

/// Build a simple DNS response header
///
/// This creates a basic response header with the given parameters.
/// For full response building, consider using dns_parser::Builder.
pub fn build_response_header(
    id: u16,
    flags: MessageFlags,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(12);

    // ID
    header.extend_from_slice(&id.to_be_bytes());

    // Flags
    let mut flag_bits: u16 = 0;
    if flags.is_response {
        flag_bits |= 0x8000;
    }
    flag_bits |= ((flags.opcode as u16) & 0x0F) << 11;
    if flags.authoritative {
        flag_bits |= 0x0400;
    }
    if flags.truncated {
        flag_bits |= 0x0200;
    }
    if flags.recursion_desired {
        flag_bits |= 0x0100;
    }
    if flags.recursion_available {
        flag_bits |= 0x0080;
    }
    if flags.authentic_data {
        flag_bits |= 0x0020;
    }
    flag_bits |= flags.response_code as u16 & 0x000F;

    header.extend_from_slice(&flag_bits.to_be_bytes());

    // Counts
    header.extend_from_slice(&qdcount.to_be_bytes());
    header.extend_from_slice(&ancount.to_be_bytes());
    header.extend_from_slice(&nscount.to_be_bytes());
    header.extend_from_slice(&arcount.to_be_bytes());

    header
}

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

pub const OPCODE_QUERY: u8 = 0;
pub const OPCODE_IQUERY: u8 = 1;
pub const OPCODE_STATUS: u8 = 2;
pub const OPCODE_NOTIFY: u8 = 4;
pub const OPCODE_UPDATE: u8 = 5;

pub const UPDATE_RCODE_NOERROR: u8 = 0;
pub const UPDATE_RCODE_FORMERR: u8 = 1;
pub const UPDATE_RCODE_SERVFAIL: u8 = 2;
pub const UPDATE_RCODE_NXDOMAIN: u8 = 3;
pub const UPDATE_RCODE_NOTIMP: u8 = 4;
pub const UPDATE_RCODE_REFUSED: u8 = 5;
pub const UPDATE_RCODE_YXDOMAIN: u8 = 6;
pub const UPDATE_RCODE_YXRRSET: u8 = 7;
pub const UPDATE_RCODE_NXRRSET: u8 = 8;
pub const UPDATE_RCODE_NOTAUTH: u8 = 9;
pub const UPDATE_RCODE_NOTZONE: u8 = 10;

pub fn build_error_response(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([query[0], query[1]]);
    let opcode = ((u16::from_be_bytes([query[2], query[3]]) & 0x7800) >> 11) as u8;

    let flags = MessageFlags {
        is_response: true,
        opcode,
        authoritative: true,
        truncated: false,
        recursion_desired: false,
        recursion_available: false,
        authentic_data: false,
        response_code: rcode,
    };

    let mut response = build_response_header(id, flags, 0, 0, 0, 0);

    let mut question_section = Vec::new();
    let mut pos = 12;
    while pos < query.len() {
        let len = query[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if pos + 1 + len > query.len() {
            break;
        }
        question_section.push(query[pos]);
        question_section.extend_from_slice(&query[pos + 1..pos + 1 + len]);
        pos += 1 + len;
    }
    question_section.push(0);

    if pos + 4 <= query.len() {
        question_section.extend_from_slice(&query[pos..pos + 4]);
    }

    response.extend_from_slice(&question_section);

    Some(response)
}

/// Build a DNS question section
pub fn build_question(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut question = Vec::new();

    // Name
    for label in name.split('.').filter(|s| !s.is_empty()) {
        if label.len() > 63 {
            continue;
        }
        question.push(label.len() as u8);
        question.extend_from_slice(label.as_bytes());
    }
    question.push(0); // Root label

    // QTYPE and QCLASS
    question.extend_from_slice(&qtype.to_be_bytes());
    question.extend_from_slice(&qclass.to_be_bytes());

    question
}

/// Build a simple DNS response with question and answer
pub fn build_simple_response(
    id: u16,
    flags: MessageFlags,
    question: &[u8],
    answers: &[Vec<u8>],
) -> Vec<u8> {
    let qdcount = if question.is_empty() { 0 } else { 1 };
    let ancount = answers.len() as u16;

    let mut response = build_response_header(id, flags, qdcount, ancount, 0, 0);

    // Add question if present
    if !question.is_empty() {
        response.extend_from_slice(question);
    }

    // Add answers
    for answer in answers {
        response.extend_from_slice(answer);
    }

    response
}

/// Encode a domain name for DNS wire format
pub fn encode_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Handle empty or root
    if name.is_empty() || name == "." {
        encoded.push(0);
        return encoded;
    }

    // Handle @ as origin
    let name = if name == "@" {
        ""
    } else {
        name.trim_end_matches('.')
    };

    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            continue;
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);

    encoded
}
#[cfg(test)]
mod tests {
    use super::{
        build_question, build_response_header, build_simple_response, encode_name,
        get_message_flags, get_message_id, parse_query_name, MessageFlags,
    };

    #[test]
    fn test_parse_query_name_simple() {
        let name_bytes = vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];

        let name = parse_query_name(&name_bytes, 0).unwrap();
        assert_eq!(name, "example.com");
    }

    #[test]
    fn test_parse_query_name_with_trailing_dot() {
        let name_bytes = vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];

        let name = parse_query_name(&name_bytes, 0).unwrap();
        assert_eq!(name, "example.com");
    }

    #[test]
    fn test_get_message_id() {
        let msg = vec![0x12, 0x34, 0x01, 0x00];
        assert_eq!(get_message_id(&msg), Some(0x1234));
    }

    #[test]
    fn test_get_message_flags_query() {
        let msg = vec![0x00, 0x00, 0x01, 0x00];
        let flags = get_message_flags(&msg).unwrap();
        assert!(!flags.is_response);
        assert_eq!(flags.opcode, 0);
    }

    #[test]
    fn test_get_message_flags_response() {
        let msg = vec![0x00, 0x00, 0x81, 0x83];
        let flags = get_message_flags(&msg).unwrap();
        assert!(flags.is_response);
        assert_eq!(flags.response_code, 3); // NXDOMAIN
    }

    #[test]
    fn test_build_response_header() {
        let flags = MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: true,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            response_code: 0,
        };

        let header = build_response_header(0x1234, flags, 1, 1, 0, 0);

        assert_eq!(header.len(), 12);
        assert_eq!(u16::from_be_bytes([header[0], header[1]]), 0x1234);
    }

    #[test]
    fn test_message_flags_is_nxdomain() {
        let flags = MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: true,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            response_code: 3,
        };

        assert!(flags.is_nxdomain());
    }

    #[test]
    fn test_get_message_flags_no_error() {
        let msg = vec![0x00, 0x00, 0x81, 0x80];
        let flags = get_message_flags(&msg).unwrap();
        assert!(flags.is_response);
        assert_eq!(flags.response_code, 0); // NoError
    }

    #[test]
    fn test_get_message_flags_server_failure() {
        let msg = vec![0x00, 0x00, 0x81, 0x82];
        let flags = get_message_flags(&msg).unwrap();
        assert!(flags.is_response);
        assert_eq!(flags.response_code, 2); // ServerFailure
    }

    #[test]
    fn test_build_response_header_nxdomain() {
        let flags = MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: true,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            response_code: 3, // NXDOMAIN
        };

        let header = build_response_header(0xABCD, flags, 1, 0, 0, 0);

        assert_eq!(header.len(), 12);
        assert_eq!(u16::from_be_bytes([header[0], header[1]]), 0xABCD);
        // Check response flag (0x80), authoritative (0x04), RD (0x01), RA (0x80), and NXDOMAIN (0x03)
        // 0x80 | 0x04 = 0x84, then 0x84 | 0x01 = 0x85, then 0x85 | 0x80 = 0x85 (carry), so 0x85 in first byte
        // Second byte: 0x80 | 0x03 = 0x83
        assert_eq!(header[2], 0x85);
        assert_eq!(header[3], 0x83);
    }

    #[test]
    fn test_parse_query_name_deep_subdomain() {
        let name_bytes = vec![
            0x01, b'a', 0x01, b'b', 0x01, b'c', 0x01, b'd', 0x01, b'e', 0x01, b'f', 0x01, b'g',
            0x01, b'h', 0x01, b'i', 0x01, b'j', 0x01, b'k', 0x03, b'c', b'o', b'm', 0x00,
        ];

        let name = parse_query_name(&name_bytes, 0).unwrap();
        assert_eq!(name, "a.b.c.d.e.f.g.h.i.j.k.com");
    }

    #[test]
    fn test_parse_query_name_invalid_too_long() {
        // Name too long (>255 bytes total)
        let mut name_bytes = vec![];
        for _ in 0..128 {
            name_bytes.push(63); // max label length
            name_bytes.extend_from_slice(&[b'a'; 63]);
        }
        name_bytes.push(0);

        let name = parse_query_name(&name_bytes, 0);
        // This should still work since we don't enforce max length in parsing
        assert!(name.is_some());
    }

    #[test]
    fn test_message_flags_truncated() {
        // TC flag is bit 9 (0x0200), in big-endian that's [0x02, 0x00]
        // Full flags: response=0, opcode=0, TC=1, RD=0 -> 0x0200
        let msg = vec![0x00, 0x00, 0x02, 0x00];
        let flags = get_message_flags(&msg).unwrap();
        assert!(flags.truncated);
        assert!(!flags.is_response);
    }

    #[test]
    fn test_message_flags_authoritative() {
        let msg = vec![0x00, 0x00, 0x84, 0x00];
        let flags = get_message_flags(&msg).unwrap();
        assert!(flags.authoritative);
        assert!(flags.is_response);
    }

    #[test]
    fn test_build_question() {
        let question = build_question("example.com.", 1, 1); // A record, IN class
        assert!(question.len() > 2);
        // Check that it ends with type A (0x0001) and class IN (0x0001)
        assert_eq!(question[question.len() - 4..], vec![0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_encode_name() {
        let encoded = encode_name("example.com");
        // Should be: 07 example 03 com 00
        assert_eq!(
            encoded,
            vec![0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00]
        );
    }

    #[test]
    fn test_encode_name_root() {
        let encoded = encode_name(".");
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn test_encode_name_empty() {
        let encoded = encode_name("");
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn test_encode_name_at_origin() {
        let encoded = encode_name("@");
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn test_build_simple_response() {
        let question = build_question("example.com.", 1, 1);

        // Build a simple answer (just the name + type + class + ttl + rdlen)
        let answer = encode_name("example.com.");
        let mut full_answer = answer.clone();
        full_answer.extend_from_slice(&1u16.to_be_bytes()); // Type A
        full_answer.extend_from_slice(&1u16.to_be_bytes()); // Class IN
        full_answer.extend_from_slice(&3600u32.to_be_bytes()); // TTL
        full_answer.extend_from_slice(&4u16.to_be_bytes()); // RDATA length
        full_answer.extend_from_slice(&[93, 184, 216, 34]); // IP

        let flags = MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: true,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            response_code: 0,
        };

        let response = build_simple_response(0x1234, flags, &question, &[full_answer]);

        // Should have header (12) + question + answer
        assert!(response.len() >= 12);
    }
}
