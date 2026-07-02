#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryParseError {
    TooShort,
    NotAQuery { is_response: bool, opcode: u8 },
    BadQuestionCount(u16),
    LabelTooLong,
    TotalNameTooLong,
    TruncatedQuestion,
    MalformedEdns,
}

impl std::fmt::Display for QueryParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "query shorter than DNS header"),
            Self::NotAQuery {
                is_response,
                opcode,
            } => write!(
                f,
                "not a query (response={}, opcode={})",
                is_response, opcode
            ),
            Self::BadQuestionCount(n) => write!(f, "unexpected QDCOUNT {}", n),
            Self::LabelTooLong => write!(f, "label exceeds 63 bytes"),
            Self::TotalNameTooLong => write!(f, "QNAME exceeds 255 bytes"),
            Self::TruncatedQuestion => write!(f, "question section truncated"),
            Self::MalformedEdns => write!(f, "malformed EDNS OPT record"),
        }
    }
}

impl std::error::Error for QueryParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryFlags {
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

impl QueryFlags {
    pub fn from_u16(flags: u16) -> Self {
        Self {
            is_response: (flags & 0x8000) != 0,
            opcode: ((flags & 0x7800) >> 11) as u8,
            authoritative: (flags & 0x0400) != 0,
            truncated: (flags & 0x0200) != 0,
            recursion_desired: (flags & 0x0100) != 0,
            recursion_available: (flags & 0x0080) != 0,
            authentic_data: (flags & 0x0020) != 0,
            checking_disabled: (flags & 0x0010) != 0,
            response_code: (flags & 0x000F) as u8,
        }
    }

    pub fn to_u16(self) -> u16 {
        let mut flags: u16 = 0;
        if self.is_response {
            flags |= 0x8000;
        }
        flags |= ((self.opcode as u16) & 0x0F) << 11;
        if self.authoritative {
            flags |= 0x0400;
        }
        if self.truncated {
            flags |= 0x0200;
        }
        if self.recursion_desired {
            flags |= 0x0100;
        }
        if self.recursion_available {
            flags |= 0x0080;
        }
        if self.authentic_data {
            flags |= 0x0020;
        }
        if self.checking_disabled {
            flags |= 0x0010;
        }
        flags |= self.response_code as u16 & 0x000F;
        flags
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDnsQuery<'a> {
    pub id: u16,
    pub flags: QueryFlags,
    pub qdcount: u16,
    pub qname: String,
    pub qname_end: usize,
    pub qtype: u16,
    pub qclass: u16,
    pub question_end: usize,
    pub has_edns: bool,
    pub dnssec_ok: bool,
    pub raw: &'a [u8],
}

impl<'a> ParsedDnsQuery<'a> {
    pub fn parse(query: &'a [u8]) -> Result<Self, QueryParseError> {
        if query.len() < 12 {
            return Err(QueryParseError::TooShort);
        }

        let id = u16::from_be_bytes([query[0], query[1]]);
        let raw_flags = u16::from_be_bytes([query[2], query[3]]);
        let flags = QueryFlags::from_u16(raw_flags);

        let qdcount = u16::from_be_bytes([query[4], query[5]]);

        if flags.is_response {
            return Err(QueryParseError::NotAQuery {
                is_response: true,
                opcode: flags.opcode,
            });
        }
        if qdcount == 0 {
            return Err(QueryParseError::BadQuestionCount(0));
        }

        // Parse QNAME — build dotted string from wire labels
        let mut pos = 12;
        let mut total_name_len: u32 = 0;
        let mut qname = String::new();

        loop {
            if pos >= query.len() {
                return Err(QueryParseError::TruncatedQuestion);
            }
            let len = query[pos] as usize;

            if len == 0 {
                pos += 1;
                break;
            }

            // Reject compression pointers in question section
            if (len & 0xC0) == 0xC0 {
                return Err(QueryParseError::TruncatedQuestion);
            }

            if len > 63 {
                return Err(QueryParseError::LabelTooLong);
            }

            if pos + 1 + len > query.len() {
                return Err(QueryParseError::TruncatedQuestion);
            }

            // Reject control characters in label bytes
            let label_bytes = &query[pos + 1..pos + 1 + len];
            for &byte in label_bytes {
                if byte < 0x21 || byte == 0x7F {
                    return Err(QueryParseError::LabelTooLong);
                }
            }

            // Validate UTF-8
            let label_str =
                std::str::from_utf8(label_bytes).map_err(|_| QueryParseError::LabelTooLong)?;

            if !qname.is_empty() {
                qname.push('.');
            }
            qname.push_str(label_str);

            total_name_len += len as u32 + 1;
            if total_name_len > 255 {
                return Err(QueryParseError::TotalNameTooLong);
            }

            pos += 1 + len;
        }

        let qname_end = pos;

        if qname_end + 4 > query.len() {
            return Err(QueryParseError::TruncatedQuestion);
        }

        let qtype = u16::from_be_bytes([query[qname_end], query[qname_end + 1]]);
        let qclass = u16::from_be_bytes([query[qname_end + 2], query[qname_end + 3]]);
        let question_end = qname_end + 4;

        // Detect EDNS by checking if ARCOUNT > 0 and the first additional record is OPT (type 41)
        let arcount = u16::from_be_bytes([query[10], query[11]]);
        let mut has_edns = false;
        let mut dnssec_ok = false;

        if arcount > 0 {
            // OPT record in EDNS: root(1) + type(2) + class/UDP_size(2) + rdata(4+)
            // Type field is at question_end + 1 (after root label byte)
            if question_end + 3 < query.len() {
                let rr_type =
                    u16::from_be_bytes([query[question_end + 1], query[question_end + 2]]);
                if rr_type == 41 {
                    has_edns = true;
                    // OPT RDATA layout (after root label):
                    //   type(2) + class/UDP_size(2) + ext_rcode(1) + version(1) + flags(2)
                    // Flags start at question_end + 1 + 2 + 2 + 1 + 1 = question_end + 7
                    let flags_offset = question_end + 7;
                    if flags_offset + 2 <= query.len() {
                        let edns_flags =
                            u16::from_be_bytes([query[flags_offset], query[flags_offset + 1]]);
                        dnssec_ok = (edns_flags & 0x8000) != 0;
                    }
                }
            }
        }

        Ok(Self {
            id,
            flags,
            qdcount,
            qname,
            qname_end,
            qtype,
            qclass,
            question_end,
            has_edns,
            dnssec_ok,
            raw: query,
        })
    }

    pub fn is_notify(&self) -> bool {
        self.flags.opcode == crate::wire::OPCODE_NOTIFY
    }

    pub fn is_update(&self) -> bool {
        self.flags.opcode == crate::wire::OPCODE_UPDATE
    }

    pub fn is_axfr(&self) -> bool {
        self.qtype == crate::transfer::AXFR_QUERY_TYPE
    }

    pub fn is_ixfr(&self) -> bool {
        self.qtype == crate::transfer::IXFR_QUERY_TYPE
    }

    /// Skip past a wire-format name in raw query bytes, starting at `pos`.
    /// Returns the byte position after the terminating zero byte, or `None`
    /// if the data is truncated or contains a compression pointer.
    pub fn skip_wire_name(raw: &[u8], start: usize) -> Option<usize> {
        let mut pos = start;
        while pos < raw.len() {
            let len = raw[pos] as usize;
            if len == 0 {
                return Some(pos + 1);
            }
            // Reject compression pointers
            if (len & 0xC0) == 0xC0 {
                return None;
            }
            pos += 1 + len;
        }
        None
    }
}

/// Build a response flags u16 from policy parameters.
///
/// For authoritative servers, `recursion_available` should be false
/// (authoritative-only mode) or true only when recursion is actually
/// offered to the client. `authentic_data` should only be set for
/// validated recursive data, not merely signed authoritative data.
/// `checking_disabled` echoes the client's CD bit for recursive validation policy.
pub fn build_response_flags(
    authoritative: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    authentic_data: bool,
    rcode: u8,
) -> u16 {
    build_response_flags_full(
        authoritative,
        truncated,
        recursion_desired,
        recursion_available,
        authentic_data,
        false,
        rcode,
    )
}

/// Build a response flags u16 with full control over all flag bits.
///
/// This is the canonical response flag constructor. All other flag construction
/// methods must delegate here.
pub fn build_response_flags_full(
    authoritative: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    authentic_data: bool,
    checking_disabled: bool,
    rcode: u8,
) -> u16 {
    let mut flags: u16 = 0x8000; // QR bit
    if authoritative {
        flags |= 0x0400;
    }
    if truncated {
        flags |= 0x0200;
    }
    if recursion_desired {
        flags |= 0x0100;
    }
    if recursion_available {
        flags |= 0x0080;
    }
    if authentic_data {
        flags |= 0x0020;
    }
    if checking_disabled {
        flags |= 0x0010;
    }
    flags |= rcode as u16 & 0x000F;
    flags
}

/// Build response flags from a parsed query and response parameters.
///
/// Policy:
/// - Always set QR=1.
/// - Set AA for authoritative answers.
/// - Echo RD if the query set it (per RFC 1035 §4.1.1).
/// - Set RA only if recursion is available to this client.
/// - Set AD only for validated recursive data, not signed authoritative data.
/// - Echo CD from the query when validation policy allows it.
/// - Set RCODE from explicit response outcome.
/// - Preserve opcode for NOTIFY/UPDATE responses.
pub fn build_response_flags_from_query(
    parsed: &ParsedDnsQuery,
    authoritative: bool,
    truncated: bool,
    recursion_available: bool,
    authentic_data: bool,
    rcode: u8,
) -> u16 {
    let mut flags: u16 = 0x8000; // QR bit
    if authoritative {
        flags |= 0x0400;
    }
    if truncated {
        flags |= 0x0200;
    }
    if parsed.flags.recursion_desired {
        flags |= 0x0100;
    }
    if recursion_available {
        flags |= 0x0080;
    }
    if authentic_data {
        flags |= 0x0020;
    }
    // Echo CD bit from query when validation policy allows it
    if parsed.flags.checking_disabled {
        flags |= 0x0010;
    }
    // Preserve opcode for non-query responses (NOTIFY, UPDATE, etc.)
    flags |= ((parsed.flags.opcode as u16) & 0x0F) << 11;
    flags |= rcode as u16 & 0x000F;
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(id: u16, flags: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut q = Vec::with_capacity(12 + 256 + 4);
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&flags.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Encode name
        if name.is_empty() || name == "." {
            q.push(0);
        } else {
            for label in name.split('.').filter(|s| !s.is_empty()) {
                q.push(label.len() as u8);
                q.extend_from_slice(label.as_bytes());
            }
            q.push(0);
        }

        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&qclass.to_be_bytes());
        q
    }

    #[test]
    fn parse_valid_a_query() {
        let q = build_query(0x1234, 0x0100, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert!(!parsed.flags.is_response);
        assert_eq!(parsed.flags.opcode, 0);
        assert!(parsed.flags.recursion_desired);
        assert_eq!(parsed.qname, "example.com");
        assert_eq!(parsed.qtype, 1);
        assert_eq!(parsed.qclass, 1);
        assert_eq!(parsed.qdcount, 1);
    }

    #[test]
    fn parse_valid_aaaa_query() {
        let q = build_query(0xABCD, 0x0100, "www.example.com", 28, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert_eq!(parsed.id, 0xABCD);
        assert_eq!(parsed.qname, "www.example.com");
        assert_eq!(parsed.qtype, 28);
    }

    #[test]
    fn parse_root_query() {
        let q = build_query(0x0001, 0x0100, ".", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert_eq!(parsed.qname, "");
        assert_eq!(parsed.qtype, 1);
    }

    #[test]
    fn parse_mixed_case_qname() {
        let q = build_query(0x0001, 0x0100, "ExAmPlE.CoM", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert_eq!(parsed.qname, "ExAmPlE.CoM");
    }

    #[test]
    fn parse_query_too_short() {
        let q = [0u8; 5];
        assert_eq!(
            ParsedDnsQuery::parse(&q).unwrap_err(),
            QueryParseError::TooShort
        );
    }

    #[test]
    fn parse_response_rejected() {
        let q = build_query(0x0001, 0x8180, "example.com", 1, 1);
        match ParsedDnsQuery::parse(&q) {
            Err(QueryParseError::NotAQuery {
                is_response: true, ..
            }) => {}
            other => panic!("expected NotAQuery, got {:?}", other),
        }
    }

    #[test]
    fn parse_qdcount_zero() {
        let mut q = build_query(0x0001, 0x0100, "example.com", 1, 1);
        // Zero out QDCOUNT
        q[4] = 0;
        q[5] = 0;
        assert_eq!(
            ParsedDnsQuery::parse(&q).unwrap_err(),
            QueryParseError::BadQuestionCount(0)
        );
    }

    #[test]
    fn parse_axfr_qtype() {
        let q = build_query(0x0001, 0x0100, "example.com", 252, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert!(parsed.is_axfr());
        assert!(!parsed.is_ixfr());
    }

    #[test]
    fn parse_ixfr_qtype() {
        let q = build_query(0x0001, 0x0100, "example.com", 251, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert!(parsed.is_ixfr());
        assert!(!parsed.is_axfr());
    }

    #[test]
    fn parse_notify_opcode() {
        let flags = 0x0100 | (4u16 << 11); // RD + OPCODE_NOTIFY
        let q = build_query(0x0001, flags, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert!(parsed.is_notify());
        assert!(!parsed.is_update());
    }

    #[test]
    fn parse_update_opcode() {
        let flags = 0x0100 | (5u16 << 11); // RD + OPCODE_UPDATE
        let q = build_query(0x0001, flags, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert!(parsed.is_update());
        assert!(!parsed.is_notify());
    }

    #[test]
    fn parse_edns_opt_record() {
        let mut q = build_query(0x0001, 0x0100, "example.com", 1, 1);
        // Add OPT record (ARCOUNT already 0, need to set it to 1)
        q[10] = 0;
        q[11] = 1;
        // Root label for OPT
        q.push(0);
        // Type OPT = 41
        q.extend_from_slice(&41u16.to_be_bytes());
        // Class = UDP payload size (4096)
        q.extend_from_slice(&4096u16.to_be_bytes());
        // TTL field: extended_rcode(1) + version(1) + flags(2)
        q.push(0); // extended rcode
        q.push(0); // version
                   // DO bit in flags (bit 15 of the 16-bit flags field)
        q.extend_from_slice(&0x8000u16.to_be_bytes());
        // RDLENGTH
        q.extend_from_slice(&0u16.to_be_bytes());

        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert!(parsed.has_edns);
        assert!(parsed.dnssec_ok);
    }

    #[test]
    fn parse_edns_no_do_bit() {
        let mut q = build_query(0x0001, 0x0100, "example.com", 1, 1);
        q[10] = 0;
        q[11] = 1;
        q.push(0);
        q.extend_from_slice(&41u16.to_be_bytes());
        q.extend_from_slice(&4096u16.to_be_bytes());
        q.push(0);
        q.push(0);
        q.extend_from_slice(&0u16.to_be_bytes()); // no DO bit
        q.extend_from_slice(&0u16.to_be_bytes());

        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert!(parsed.has_edns);
        assert!(!parsed.dnssec_ok);
    }

    #[test]
    fn parse_no_edns() {
        let q = build_query(0x0001, 0x0100, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert!(!parsed.has_edns);
        assert!(!parsed.dnssec_ok);
    }

    #[test]
    fn parse_truncated_mid_label() {
        // Create a minimal query that claims a label of 5 bytes but buffer ends before that
        let mut q = Vec::with_capacity(16);
        q.extend_from_slice(&0x0001u16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        // Label claiming 5 bytes
        q.push(5);
        q.push(b'a');
        q.push(b'b');
        // Only 2 of 5 bytes present, then buffer ends
        assert_eq!(
            ParsedDnsQuery::parse(&q).unwrap_err(),
            QueryParseError::TruncatedQuestion
        );
    }

    #[test]
    fn parse_truncated_after_name() {
        let mut q = build_query(0x0001, 0x0100, "", 1, 1);
        // Remove the last 2 bytes (QTYPE)
        q.truncate(q.len() - 2);
        assert_eq!(
            ParsedDnsQuery::parse(&q).unwrap_err(),
            QueryParseError::TruncatedQuestion
        );
    }

    #[test]
    fn parse_large_label_rejected() {
        let mut q = Vec::with_capacity(12 + 70 + 4);
        q.extend_from_slice(&0x0001u16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        // Label of 64 bytes (over 63 limit)
        q.push(64);
        q.extend_from_slice(&[b'a'; 64]);
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            ParsedDnsQuery::parse(&q).unwrap_err(),
            QueryParseError::LabelTooLong
        );
    }

    #[test]
    fn parse_long_name_rejected() {
        let mut q = Vec::with_capacity(260);
        q.extend_from_slice(&0x0001u16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        // Build a name with total length > 255
        for _ in 0..10 {
            q.push(25); // 25-byte labels
            q.extend_from_slice(&[b'a'; 25]);
        }
        q.push(26); // 26-byte label to push over 255
        q.extend_from_slice(&[b'b'; 26]);
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            ParsedDnsQuery::parse(&q).unwrap_err(),
            QueryParseError::TotalNameTooLong
        );
    }

    #[test]
    fn response_flags_basic() {
        let flags = build_response_flags(true, false, true, true, false, 0);
        assert_eq!(flags & 0x8000, 0x8000); // QR
        assert_eq!(flags & 0x0400, 0x0400); // AA
        assert_eq!(flags & 0x0200, 0); // TC
        assert_eq!(flags & 0x0100, 0x0100); // RD echoed
        assert_eq!(flags & 0x0080, 0x0080); // RA
        assert_eq!(flags & 0x0020, 0); // AD
        assert_eq!(flags & 0x000F, 0); // RCODE
    }

    #[test]
    fn response_flags_nxdomain() {
        let flags = build_response_flags(true, false, false, true, false, 3);
        assert_eq!(flags & 0x8000, 0x8000); // QR
        assert_eq!(flags & 0x0400, 0x0400); // AA
        assert_eq!(flags & 0x000F, 3); // NXDOMAIN
    }

    #[test]
    fn response_flags_truncated() {
        let flags = build_response_flags(true, true, true, true, false, 0);
        assert_ne!(flags & 0x0200, 0); // TC set
    }

    #[test]
    fn response_flags_no_ra_for_authoritative_only() {
        let flags = build_response_flags(true, false, true, false, false, 0);
        assert_eq!(flags & 0x0080, 0); // RA not set
    }

    #[test]
    fn response_flags_ad_set_for_validated() {
        let flags = build_response_flags(false, false, true, true, true, 0);
        assert_ne!(flags & 0x0020, 0); // AD set
    }

    #[test]
    fn response_flags_from_query_preserves_opcode() {
        let q = build_query(0x0001, 0x0100 | (4u16 << 11), "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        let flags = build_response_flags_from_query(&parsed, true, false, false, false, 0);
        assert_eq!(((flags & 0x7800) >> 11) as u8, 4); // NOTIFY opcode preserved
    }

    #[test]
    fn response_flags_from_query_echoes_rd() {
        let q = build_query(0x0001, 0x0100, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        let flags = build_response_flags_from_query(&parsed, true, false, false, false, 0);
        assert_ne!(flags & 0x0100, 0); // RD echoed
    }

    #[test]
    fn response_flags_from_query_no_rd_when_unset() {
        let q = build_query(0x0001, 0x0000, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        let flags = build_response_flags_from_query(&parsed, true, false, false, false, 0);
        assert_eq!(flags & 0x0100, 0); // RD not set
    }

    #[test]
    fn parse_authoritative_query() {
        let q = build_query(0x0001, 0x0100 | 0x0400, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert!(parsed.flags.authoritative);
    }

    #[test]
    fn parse_checking_disabled() {
        let q = build_query(0x0001, 0x0100 | 0x0010, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert!(parsed.flags.checking_disabled);
    }

    #[test]
    fn roundtrip_flags() {
        let original = QueryFlags {
            is_response: false,
            opcode: 4,
            authoritative: true,
            truncated: false,
            recursion_desired: true,
            recursion_available: false,
            authentic_data: true,
            checking_disabled: false,
            response_code: 0,
        };
        let as_u16 = original.to_u16();
        let restored = QueryFlags::from_u16(as_u16);
        assert_eq!(original, restored);
    }

    #[test]
    fn question_end_offset_correct() {
        // "a.b.c" = 1+'a' + 1+'b' + 1+'c' + 1(null) = 7 bytes after header
        // Header(12) + name(7) + qtype(2) + qclass(2) = 23
        let q = build_query(0x0001, 0x0100, "a.b.c", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert_eq!(parsed.question_end, 23);
        assert_eq!(parsed.raw.len(), 23);
    }

    #[test]
    fn trailing_dot_produces_same_result() {
        let q1 = build_query(0x0001, 0x0100, "example.com", 1, 1);
        let q2 = build_query(0x0001, 0x0100, "example.com.", 1, 1);
        let p1 = ParsedDnsQuery::parse(&q1).unwrap();
        let p2 = ParsedDnsQuery::parse(&q2).unwrap();
        assert_eq!(p1.qname, p2.qname);
        assert_eq!(p1.qtype, p2.qtype);
        assert_eq!(p1.question_end, p2.question_end);
    }

    #[test]
    fn non_standard_qclass_is_parsed() {
        let q = build_query(0x0001, 0x0100, "example.com", 1, 3); // CLASS 3 = CH (Chaosnet)
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert_eq!(parsed.qclass, 3);
        let q = build_query(0x0001, 0x0100, "example.com", 1, 4); // CLASS 4 = HS (Hesiod)
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert_eq!(parsed.qclass, 4);
    }

    #[test]
    fn high_opcode_is_parsed() {
        let flags = 0x0100 | (7u16 << 11); // RD + OPCODE 7 (reserved/unknown)
        let q = build_query(0x0001, flags, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        assert_eq!(parsed.flags.opcode, 7);
        assert!(!parsed.is_notify());
        assert!(!parsed.is_update());
    }

    #[test]
    fn response_flags_formerr() {
        let flags = build_response_flags(true, false, false, false, false, 1); // FORMERR
        assert_eq!(flags & 0x8000, 0x8000); // QR
        assert_eq!(flags & 0x000F, 1); // FORMERR
    }

    #[test]
    fn response_flags_notimp() {
        let flags = build_response_flags(true, false, false, false, false, 4); // NOTIMP
        assert_eq!(flags & 0x8000, 0x8000); // QR
        assert_eq!(flags & 0x000F, 4); // NOTIMP
    }

    #[test]
    fn response_flags_from_query_rd_unset() {
        let q = build_query(0x0001, 0x0000, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        let flags = build_response_flags_from_query(&parsed, true, false, false, false, 0);
        assert_eq!(flags & 0x0100, 0); // RD must NOT be echoed when unset
        assert_eq!(flags & 0x8000, 0x8000); // QR must be set
    }

    #[test]
    fn raw_question_section_accessible() {
        let q = build_query(0x0001, 0x0100, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&q).unwrap();
        // The question section spans raw[12..question_end]
        assert_eq!(parsed.raw.len(), parsed.question_end);
        assert_eq!(parsed.raw.len(), q.len());
    }
}
