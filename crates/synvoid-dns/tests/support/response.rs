//! DNS response wire-format parsing helpers for integration tests.
//!
//! These functions read fields from raw DNS response buffers without
//! allocating.  All indices are bounds-checked against `resp.len()`.
#![allow(dead_code)]

/// Extract the flags word (bytes 2–3) from a DNS response.
pub fn response_flags(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[2], resp[3]])
}

/// Extract the RCODE (low 4 bits of the flags) from a DNS response.
pub fn response_rcode(resp: &[u8]) -> u8 {
    (response_flags(resp) & 0x000F) as u8
}

/// Extract the ANCOUNT (answer count) from a DNS response header.
pub fn response_ancount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[6], resp[7]])
}

/// Extract the NSCOUNT (authority count) from a DNS response header.
pub fn response_nscount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[8], resp[9]])
}

/// Extract the ARCOUNT (additional count) from a DNS response header.
pub fn response_arcount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[10], resp[11]])
}

/// Returns `true` if the AA (Authoritative Answer) bit is set.
pub fn is_authoritative(resp: &[u8]) -> bool {
    response_flags(resp) & 0x0400 != 0
}

/// Returns `true` if the RA (Recursion Available) bit is set.
pub fn is_recursion_available(resp: &[u8]) -> bool {
    response_flags(resp) & 0x0080 != 0
}

/// Returns `true` if the QR (Query/Response) bit is set (i.e. this is a response).
pub fn is_response(resp: &[u8]) -> bool {
    response_flags(resp) & 0x8000 != 0
}

/// Skip past a DNS wire-format name, handling compression pointers.
///
/// Starting at `start`, advances past the label sequence until the
/// terminating zero byte or a compression pointer (`0xC0..`).
/// Returns the byte position immediately after the name.
pub fn skip_wire_name(resp: &[u8], start: usize) -> usize {
    let mut pos = start;
    while pos < resp.len() {
        let len = resp[pos] as usize;
        if len == 0 {
            return pos + 1;
        }
        if (len & 0xC0) == 0xC0 {
            return pos + 2;
        }
        pos += 1 + len;
    }
    pos
}

/// Skip past a DNS wire-format name in a mutable buffer position.
///
/// Same as [`skip_wire_name`] but mutates `pos` in place, which is
/// convenient when iterating through multiple records in a buffer.
pub fn skip_name(buf: &[u8], pos: &mut usize) {
    while *pos < buf.len() {
        let b = buf[*pos];
        if b == 0 {
            *pos += 1;
            return;
        }
        if b & 0xC0 == 0xC0 {
            *pos += 2;
            return;
        }
        *pos += 1 + b as usize;
    }
}

/// Decode a DNS wire-format name at `start`, following compression pointers.
///
/// Returns the dotted presentation form without a trailing dot (the empty
/// string for the root).  Returns `None` when the name is truncated, a label
/// exceeds 63 octets, or the pointer chain loops.
pub fn read_wire_name(resp: &[u8], start: usize) -> Option<String> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut pos = start;
    let mut jumps = 0;

    loop {
        let len = *resp.get(pos)? as usize;
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            let offset = ((len & 0x3F) << 8) | *resp.get(pos + 1)? as usize;
            jumps += 1;
            if jumps > 16 || offset >= resp.len() {
                return None;
            }
            pos = offset;
            continue;
        }
        if len > 63 {
            return None;
        }
        labels.push(resp.get(pos + 1..pos + 1 + len)?);
        pos += 1 + len;
    }

    Some(
        labels
            .iter()
            .map(|label| String::from_utf8_lossy(label))
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Decode the name in the response's question section (QDCOUNT must be 1).
///
/// This is how a client sees its own question echoed back: mixed case and
/// every label must survive byte-for-byte.
pub fn question_name(resp: &[u8]) -> String {
    read_wire_name(resp, 12).expect("question name must decode as a wire name")
}

/// Decode the owner name of answer record `index` (0-based), following
/// compression pointers.
pub fn answer_owner(resp: &[u8], index: usize) -> String {
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    assert!(
        index < ancount,
        "answer index {index} out of range (ANCOUNT={ancount})"
    );

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_wire_name(resp, pos) + 4; // QNAME + QTYPE + QCLASS
    }

    for i in 0..=index {
        let owner_at = pos;
        pos = skip_wire_name(resp, pos);
        if i == index {
            return read_wire_name(resp, owner_at)
                .unwrap_or_else(|| panic!("answer {index} owner must decode"));
        }
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10 + rdlength; // TYPE + CLASS + TTL + RDLENGTH + RDATA
    }

    unreachable!("index bounds checked above")
}

/// Parse the answer section of a DNS response and return the record types.
///
/// Skips the question section and iterates over ANCOUNT answers,
/// extracting each answer's TYPE field.  Useful for verifying that
/// a response contains the expected record types.
pub fn parse_answer_types(resp: &[u8]) -> Vec<u16> {
    let mut types = Vec::new();
    if resp.len() < 12 {
        return types;
    }
    let qd = u16::from_be_bytes([resp[4], resp[5]]);
    let an = u16::from_be_bytes([resp[6], resp[7]]);
    let mut pos = 12;
    // Skip question section
    for _ in 0..qd {
        pos = skip_wire_name(resp, pos);
        pos += 4; // QTYPE + QCLASS
    }
    // Parse answer section
    for _ in 0..an {
        pos = skip_wire_name(resp, pos);
        if pos + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        pos += 8; // TYPE(2) + CLASS(2) + TTL(4)
        let rdlen = u16::from_be_bytes([resp[pos], resp[pos + 1]]) as usize;
        pos += 2 + rdlen;
        types.push(rtype);
    }
    types
}

/// Extract the QDCOUNT (question count) from a DNS response header.
pub fn response_qdcount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[4], resp[5]])
}

/// The fields of an OPT pseudo-RR (RFC 6891 §6.1.2) in a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptRecord {
    /// CLASS: the sender's advertised maximum UDP payload size.
    pub payload: u16,
    /// Upper 8 bits of the 12-bit extended RCODE (TTL bits 24-31).
    pub ext_rcode: u8,
    /// EDNS version (TTL bits 16-23).
    pub version: u8,
    /// EDNS flags (TTL bits 0-15); DO is 0x8000.
    pub flags: u16,
    /// RDLENGTH: bytes of option data that follow the fixed header.
    pub rdlen: u16,
}

impl OptRecord {
    /// The DO (DNSSEC OK) bit.
    pub fn dnssec_ok(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// The full 12-bit extended RCODE, given the response header's low nibble.
    pub fn extended_rcode(&self, header_rcode: u8) -> u16 {
        (u16::from(self.ext_rcode) << 4) | u16::from(header_rcode & 0x0F)
    }
}

/// Skip one complete RR starting at `pos`, returning the next position.
fn skip_rr(resp: &[u8], pos: usize) -> Option<usize> {
    let name_end = skip_wire_name(resp, pos);
    if name_end + 10 > resp.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([resp[name_end + 8], resp[name_end + 9]]) as usize;
    let next = name_end + 10 + rdlength;
    (next <= resp.len()).then_some(next)
}

/// Parse the OPT record from a response's additional section.
///
/// Returns `None` when the response carries no OPT, the sections do not parse,
/// or the additional section is truncated. Only the first OPT is returned.
pub fn parse_opt(resp: &[u8]) -> Option<OptRecord> {
    if resp.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let nscount = u16::from_be_bytes([resp[8], resp[9]]) as usize;
    let arcount = u16::from_be_bytes([resp[10], resp[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_wire_name(resp, pos) + 4; // QNAME + QTYPE + QCLASS
        if pos > resp.len() {
            return None;
        }
    }
    for _ in 0..(ancount + nscount) {
        pos = skip_rr(resp, pos)?;
    }
    for _ in 0..arcount {
        let name_end = skip_wire_name(resp, pos);
        if name_end + 10 > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[name_end], resp[name_end + 1]]);
        let class = u16::from_be_bytes([resp[name_end + 2], resp[name_end + 3]]);
        let ttl = u32::from_be_bytes([
            resp[name_end + 4],
            resp[name_end + 5],
            resp[name_end + 6],
            resp[name_end + 7],
        ]);
        let rdlen = u16::from_be_bytes([resp[name_end + 8], resp[name_end + 9]]);

        if rtype == 41 {
            return Some(OptRecord {
                payload: class,
                ext_rcode: (ttl >> 24) as u8,
                version: ((ttl >> 16) & 0xFF) as u8,
                flags: (ttl & 0xFFFF) as u16,
                rdlen,
            });
        }

        let next = name_end + 10 + rdlen as usize;
        if next > resp.len() {
            return None;
        }
        pos = next;
    }

    None
}

/// Decode the question name when the header declares exactly one question.
///
/// Returns `None` for QDCOUNT 0 or a question name that does not decode; this
/// is what makes a "QDCOUNT says zero but bytes follow" response detectable.
pub fn response_question(resp: &[u8]) -> Option<String> {
    if resp.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([resp[4], resp[5]]) != 1 {
        return None;
    }
    read_wire_name(resp, 12)
}
