/// DNS response wire-format parsing helpers for integration tests.
///
/// These functions read fields from raw DNS response buffers without
/// allocating.  All indices are bounds-checked against `resp.len()`.

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
