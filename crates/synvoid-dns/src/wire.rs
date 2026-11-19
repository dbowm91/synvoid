// DNS Wire Format Module
//
// This module provides utilities for parsing and building DNS wire format messages.
//
// DESIGN DECISION
// ===============
// This module uses a hybrid approach:
// 1. Parsing: Uses hickory_proto::op::Message for full message parsing
// 2. Query name parsing: Custom implementation with compression support
// 3. Response building: Custom implementation for performance and flexibility
//
// Rationale:
// - Manual response building is well-tested, performant, and handles all edge cases
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
// - Hickory DNS: https://github.com/hickory-dns/hickory-dns

use hickory_proto::op::Message;

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

        // RFC 1035 limits each uncompressed label to 63 octets.
        if len > 63 {
            return None;
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

    // A DNS name is limited to 255 octets on the wire, including the
    // terminating root label. The textual form therefore cannot exceed 253
    // octets (the parser does not append a trailing dot).
    if name.len() > 253 {
        return None;
    }

    Some(name)
}

/// Parse a DNS message using hickory-proto
pub fn parse_dns_message(bytes: &[u8]) -> Result<Message, String> {
    Message::from_vec(bytes).map_err(|e| format!("DNS parse error: {:?}", e))
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
        checking_disabled: (flags & 0x0010) != 0,
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
    pub checking_disabled: bool,
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
/// For full response building, use hickory_proto or custom wire format.
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
    if flags.checking_disabled {
        flag_bits |= 0x0010;
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

/// Copy the single question section of `query` verbatim.
///
/// Returns `None` when the header does not declare exactly one question, the
/// name is truncated or contains a compression pointer, a label exceeds 63
/// octets, or QTYPE/QCLASS are missing. Callers use this to decide QDCOUNT:
/// it is never safe to write question bytes without also counting them.
pub fn question_section(query: &[u8]) -> Option<&[u8]> {
    if query.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }

    let mut pos = 12;
    loop {
        let len = *query.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // The question name is never compressed (RFC 1035 §4.1.2).
        if (len & 0xC0) == 0xC0 || len > 63 {
            return None;
        }
        let next = pos.checked_add(1 + len)?;
        if next > query.len() {
            return None;
        }
        pos = next;
    }

    let end = pos.checked_add(4)?; // QTYPE + QCLASS
    if end > query.len() {
        return None;
    }
    Some(&query[12..end])
}

/// Build an error response, optionally carrying an already-encoded OPT RR.
///
/// `QDCOUNT` is `1` exactly when the question section was copied, so a client
/// never sees a count that disagrees with the bytes. A truncated or malformed
/// question produces a header-only response (`QDCOUNT = 0`) instead of a
/// partial question or a panic.
pub fn build_error_response_with_opt(
    query: &[u8],
    rcode: u8,
    opt: Option<&[u8]>,
) -> Option<Vec<u8>> {
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
        checking_disabled: false,
        response_code: rcode,
    };

    let question = question_section(query);
    let qdcount = u16::from(question.is_some());
    let arcount = u16::from(opt.is_some());

    let mut response = build_response_header(id, flags, qdcount, 0, 0, arcount);
    if let Some(question) = question {
        response.extend_from_slice(question);
    }
    if let Some(opt) = opt {
        response.extend_from_slice(opt);
    }

    Some(response)
}

/// Build an error response that echoes the query's question section.
///
/// Thin wrapper over [`build_error_response_with_opt`] for responses that
/// carry no EDNS OPT record.
pub fn build_error_response(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    build_error_response_with_opt(query, rcode, None)
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

/// Errors produced while encoding a domain name to wire format.
///
/// `encode_owner` is total: instead of silently dropping or shortening a
/// malformed name (which produced an unparseable or wrong owner on the wire),
/// it reports the exact RFC 1035 violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// A name contained an empty label (`a..b`, or a leading/trailing dot that
    /// was not the root designator).
    EmptyLabel,
    /// A relative name was handed to a function that requires a fully
    /// qualified name. A relative name has no canonical form without its
    /// origin (RFC 4034 §6.2), so it is rejected rather than guessed at.
    RelativeName { name: String },
    /// A single label exceeded the 63-octet limit (RFC 1035 §2.3.4).
    LabelTooLong { len: usize },
    /// The encoded name exceeded the 255-octet limit (RFC 1035 §2.3.4).
    NameTooLong { len: usize },
}

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyLabel => write!(f, "domain name contains an empty label"),
            Self::RelativeName { name } => write!(
                f,
                "relative domain name '{name}' has no canonical form without its origin"
            ),
            Self::LabelTooLong { len } => {
                write!(f, "domain label of {len} octets exceeds the 63-octet limit")
            }
            Self::NameTooLong { len } => write!(
                f,
                "encoded domain name of {len} octets exceeds the 255-octet limit"
            ),
        }
    }
}

impl std::error::Error for NameError {}

/// An owner name expressed the way zones store it: a relative spelling plus
/// the origin it belongs to.
///
/// This is the only place that knows the difference between `www` (relative)
/// and `www.example.com` (absolute). DNSSEC signs the **fully qualified**
/// owner (RFC 4034 §3.1.2) and counts its labels (RFC 4034 §3.1.3), so a
/// signer that takes a bare storage key signs the wrong name. Both the wire
/// owner and the RRSIG `Labels` field therefore come from this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerName<'a> {
    relative: &'a str,
    origin: &'a str,
}

impl<'a> OwnerName<'a> {
    pub const fn new(relative: &'a str, origin: &'a str) -> Self {
        Self { relative, origin }
    }

    /// The fully qualified name as presentation text, always absolute:
    /// `www.example.com.`, or `.` for the root.
    pub fn fqdn(&self) -> String {
        let absolute = self.absolute();
        if absolute.is_empty() {
            ".".to_string()
        } else {
            format!("{absolute}.")
        }
    }

    /// Uncompressed wire form of the fully qualified owner.
    ///
    /// Labels are length-checked (1..=63), the total is checked (<= 255
    /// octets), and empty interior labels are rejected rather than skipped.
    pub fn wire(&self) -> Result<Vec<u8>, NameError> {
        encode_absolute(&self.absolute())
    }

    /// The RRSIG `Labels` field (RFC 4034 §3.1.3).
    ///
    /// The root label is not counted, and neither is a leading wildcard label:
    /// `*.example.com` reports `2`, `www.example.com` reports `3`, and the
    /// root reports `0`.
    pub fn labels(&self) -> u8 {
        let absolute = self.absolute();
        if absolute.is_empty() {
            return 0;
        }
        let labels: Vec<&str> = absolute
            .split('.')
            .filter(|label| !label.is_empty())
            .collect();
        let count = labels.len() - usize::from(labels.first() == Some(&"*"));
        // A valid wire name holds at most 127 labels; saturate rather than
        // truncate so an over-long name cannot claim a small label count.
        u8::try_from(count).unwrap_or(u8::MAX)
    }

    /// The absolute spelling without the trailing root dot (empty for the
    /// root), applying the zone-file owner rules documented on
    /// [`encode_owner`].
    fn absolute(&self) -> String {
        let relative = self.relative.trim();
        let origin = normalize_origin(self.origin);

        // 1. An explicit trailing dot marks an absolute name.
        if relative.len() > 1 && relative.ends_with('.') {
            return relative.trim_end_matches('.').to_string();
        }

        // 2. The apex spellings resolve to the origin.
        if relative.is_empty() || relative == "@" || relative == "." {
            return origin;
        }

        // 3. No origin: the name is already absolute (root zone).
        if origin.is_empty() {
            return relative.to_string();
        }

        // 4. Already the origin.
        if relative.eq_ignore_ascii_case(&origin) {
            return origin;
        }

        // 5. Already a fully qualified name inside the origin.
        if ends_with_origin(relative, &origin) {
            return relative.to_string();
        }

        // 6. Relative to the origin.
        format!("{relative}.{origin}")
    }
}

/// Encode an owner name given its zone-relative spelling and the zone origin.
///
/// Every owner written to the wire goes through this function, so a stored
/// record name (`"@"`, `"www"`, `"a.b"`) can never reach the wire as a
/// partial name. Rules, in order:
///
/// 1. a name with its own trailing dot is already absolute and is encoded as
///    given;
/// 2. `"@"`, `"."` or the empty string mean the origin;
/// 3. an empty origin means the relative name is itself absolute (root zone);
/// 4. a name already equal to the origin is the origin;
/// 5. a name already inside the origin (`hash.example.com` with origin
///    `example.com`) is absolute and is encoded as given — DNSSEC NSEC/NSEC3
///    owners are generated in that form;
/// 6. anything else is joined as `{relative}.{origin}`.
///
/// Labels are length-checked (1..=63), the total is checked (<= 255 octets),
/// and empty interior labels are rejected rather than skipped.
pub fn encode_owner(relative: &str, origin: &str) -> Result<Vec<u8>, NameError> {
    OwnerName::new(relative, origin).wire()
}

/// Encode an absolute (fully qualified) domain name for DNS wire format.
///
/// Thin wrapper around [`encode_owner`] for the question section and RDATA
/// name targets, which are never zone-relative.
pub fn encode_name(name: &str) -> Result<Vec<u8>, NameError> {
    encode_owner(name, "")
}

/// Strip a trailing root dot and map the root spellings to the empty origin.
fn normalize_origin(origin: &str) -> String {
    let origin = origin.trim().trim_end_matches('.');
    if origin == "@" {
        String::new()
    } else {
        origin.to_string()
    }
}

/// True when `name` already ends with `.origin` (ASCII case-insensitive) and
/// has at least one label of its own.
fn ends_with_origin(name: &str, origin: &str) -> bool {
    let name = name.as_bytes();
    let origin = origin.as_bytes();
    if name.len() <= origin.len() + 1 {
        return false;
    }
    if name[name.len() - origin.len() - 1] != b'.' {
        return false;
    }
    name[name.len() - origin.len()..].eq_ignore_ascii_case(origin)
}

/// Encode a name that is already absolute, rejecting every malformed label.
fn encode_absolute(name: &str) -> Result<Vec<u8>, NameError> {
    let mut encoded = Vec::with_capacity(name.len() + 2);

    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            if label.len() > 63 {
                return Err(NameError::LabelTooLong { len: label.len() });
            }
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
    }
    encoded.push(0);

    if encoded.len() > 255 {
        return Err(NameError::NameTooLong { len: encoded.len() });
    }

    Ok(encoded)
}
#[cfg(test)]
mod tests {
    use super::{
        build_question, build_response_header, build_simple_response, encode_name, encode_owner,
        get_message_flags, get_message_id, parse_query_name, MessageFlags, NameError, OwnerName,
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
            checking_disabled: false,
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
            checking_disabled: false,
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
            checking_disabled: false,
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
        assert!(name.is_none());
    }

    #[test]
    fn test_parse_query_name_invalid_label_too_long() {
        let mut name_bytes = vec![64];
        name_bytes.extend_from_slice(&[b'a'; 64]);
        name_bytes.push(0);

        assert!(parse_query_name(&name_bytes, 0).is_none());
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
        let encoded = encode_name("example.com").unwrap();
        // Should be: 07 example 03 com 00
        assert_eq!(
            encoded,
            vec![0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00]
        );
    }

    #[test]
    fn test_encode_name_root() {
        let encoded = encode_name(".").unwrap();
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn test_encode_name_empty() {
        let encoded = encode_name("").unwrap();
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn test_encode_name_at_origin() {
        let encoded = encode_name("@").unwrap();
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn test_encode_owner_joins_relative_name_and_origin() {
        let encoded = encode_owner("www", "example.com").unwrap();
        assert_eq!(
            encoded,
            vec![
                0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
                b'o', b'm', 0x00
            ]
        );
    }

    #[test]
    fn test_encode_owner_apex_spellings_resolve_to_origin() {
        let origin = encode_owner("example.com", "example.com").unwrap();
        for apex in ["@", "", ".", "example.com", "EXAMPLE.COM"] {
            assert_eq!(
                encode_owner(apex, "example.com").unwrap(),
                origin,
                "apex spelling {apex:?} must encode as the origin"
            );
        }
        // An explicitly absolute spelling keeps the caller's case; DNS names
        // compare case-insensitively, so this is still the origin.
        let explicit = encode_owner("EXAMPLE.COM.", "example.com").unwrap();
        assert_eq!(
            parse_query_name(&explicit, 0).as_deref(),
            Some("EXAMPLE.COM")
        );
    }

    #[test]
    fn test_encode_owner_absolute_name_inside_origin_is_not_joined_again() {
        // NSEC3 owners are generated as "<hash>.example.com"; joining them with
        // the origin again would move the record out of the zone.
        let encoded = encode_owner("abc.example.com", "example.com").unwrap();
        assert_eq!(encoded, encode_name("abc.example.com").unwrap());
    }

    #[test]
    fn test_encode_owner_empty_origin_is_root_zone() {
        assert_eq!(
            encode_owner("example.com", "").unwrap(),
            encode_name("example.com").unwrap()
        );
        assert_eq!(encode_owner("@", "").unwrap(), vec![0u8]);
    }

    #[test]
    fn test_encode_owner_rejects_empty_label() {
        assert_eq!(
            encode_owner("a..b", "example.com"),
            Err(NameError::EmptyLabel)
        );
    }

    #[test]
    fn test_encode_owner_rejects_oversized_label() {
        assert_eq!(
            encode_owner(&"a".repeat(64), "example.com"),
            Err(NameError::LabelTooLong { len: 64 })
        );
    }

    #[test]
    fn test_encode_owner_rejects_oversized_name() {
        // 4 * 63 + 1 + 4 labels = 260 octets encoded, over the 255 limit.
        let name = (0..4).map(|_| "a".repeat(63)).collect::<Vec<_>>().join(".");
        assert!(matches!(
            encode_owner(&name, ""),
            Err(NameError::NameTooLong { .. })
        ));
    }

    #[test]
    fn test_owner_name_fqdn_joins_the_origin() {
        assert_eq!(
            OwnerName::new("www", "example.com").fqdn(),
            "www.example.com."
        );
        assert_eq!(OwnerName::new("@", "example.com").fqdn(), "example.com.");
        assert_eq!(OwnerName::new("", "example.com.").fqdn(), "example.com.");
        // An absolute spelling is not joined again.
        assert_eq!(
            OwnerName::new("a.b.example.com", "example.com").fqdn(),
            "a.b.example.com."
        );
        // The root zone.
        assert_eq!(OwnerName::new("@", "").fqdn(), ".");
    }

    #[test]
    fn test_owner_name_wire_matches_encode_owner() {
        for (relative, origin) in [
            ("www", "example.com"),
            ("@", "example.com"),
            ("a.b", "example.com"),
            ("abc.example.com", "example.com"),
            ("WWW", "EXAMPLE.COM"),
            ("@", ""),
        ] {
            assert_eq!(
                OwnerName::new(relative, origin).wire().unwrap(),
                encode_owner(relative, origin).unwrap(),
                "OwnerName::wire must be the one owner encoder for ({relative:?}, {origin:?})"
            );
        }
    }

    #[test]
    fn test_owner_name_labels_follow_rfc4034() {
        // RFC 4034 §3.1.3: the root label is not counted.
        assert_eq!(OwnerName::new("@", "example.com").labels(), 2);
        assert_eq!(OwnerName::new("www", "example.com").labels(), 3);
        assert_eq!(OwnerName::new("a.b", "example.com").labels(), 4);
        // A leading wildcard label is not counted either.
        assert_eq!(OwnerName::new("*", "example.com").labels(), 2);
        assert_eq!(OwnerName::new("*.sub", "example.com").labels(), 3);
        // Only the leftmost label can be a wildcard.
        assert_eq!(OwnerName::new("a.*", "example.com").labels(), 4);
        // The root has no labels.
        assert_eq!(OwnerName::new("@", "").labels(), 0);
    }

    #[test]
    fn test_build_simple_response() {
        let question = build_question("example.com.", 1, 1);

        // Build a simple answer (just the name + type + class + ttl + rdlen)
        let answer = encode_name("example.com.").unwrap();
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
            checking_disabled: false,
            response_code: 0,
        };

        let response = build_simple_response(0x1234, flags, &question, &[full_answer]);

        // Should have header (12) + question + answer
        assert!(response.len() >= 12);
    }
}
