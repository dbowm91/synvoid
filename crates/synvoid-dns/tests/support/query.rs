/// Common DNS query builders for integration tests.
///
/// All functions return explicit `Vec<u8>` wire-format buffers.
/// No global state is mutated.  Callers own the returned buffers.

/// Build a standard DNS query in wire format.
///
/// Returns a buffer containing a single-question query with RD=1,
/// CLASS=IN.  The caller supplies the transaction ID, QNAME (dotted,
/// may be empty or `"."` for the root), and numeric QTYPE.
///
/// ```text
/// Wire layout:
///   [0..2]   ID
///   [2..4]   Flags (RD=1)
///   [4..6]   QDCOUNT = 1
///   [6..8]   ANCOUNT = 0
///   [8..10]  NSCOUNT = 0
///   [10..12] ARCOUNT = 0
///   [12..]   QNAME (labels + 0x00)
///   [..]     QTYPE (2 bytes)
///   [..]     QCLASS = IN (2 bytes)
/// ```
pub fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + 256 + 4);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    if qname.is_empty() || qname == "." {
        q.push(0);
    } else {
        for label in qname.split('.').filter(|s| !s.is_empty()) {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
    }

    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN

    q
}

/// Build an AXFR query (standard opcode, QTYPE=252).
///
/// Wraps [`build_query`] with `qtype = 252`.
pub fn build_axfr_query(id: u16, qname: &str) -> Vec<u8> {
    build_query(id, qname, 252)
}

/// Build an IXFR query (standard opcode, QTYPE=251).
///
/// Wraps [`build_query`] with `qtype = 251`.
pub fn build_ixfr_query(id: u16, qname: &str) -> Vec<u8> {
    build_query(id, qname, 251)
}

/// Build a NOTIFY query (opcode=4, AA=1, RD=0, QTYPE=SOA).
///
/// The returned buffer sets the OPCODE field to 4 (NOTIFY) and clears
/// the RD bit, matching RFC 1996 semantics.
pub fn build_notify_query(id: u16, qname: &str) -> Vec<u8> {
    let mut q = build_query(id, qname, 6); // SOA = 6
    // Set opcode to 4 (NOTIFY): bits 15-11 of the flags word.
    let flags = u16::from_be_bytes([q[2], q[3]]);
    let new_flags = (flags & 0x87FF) | (4 << 11);
    q[2] = (new_flags >> 8) as u8;
    q[3] = (new_flags & 0xFF) as u8;
    q
}

/// Build a query with an EDNS OPT record containing the DO bit set.
///
/// Appends a single OPT record to the AR section (ARCOUNT=1) with:
/// - Name: root (0x00)
/// - Type: OPT (41)
/// - Class: UDP payload size (4096)
/// - TTL: DO=1 (`0x0000_8000`)
/// - RDLENGTH: 0
pub fn build_query_with_do_bit(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut q = build_query(id, qname, qtype);
    q.push(0); // root name
    q.extend_from_slice(&41u16.to_be_bytes()); // type OPT
    q.extend_from_slice(&4096u16.to_be_bytes()); // class = UDP payload size
    q.extend_from_slice(&0x0000_8000u32.to_be_bytes()); // TTL: DO=1
    q.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
    // Update ARCOUNT to 1
    let arcount_pos = 10;
    q[arcount_pos] = 0;
    q[arcount_pos + 1] = 1;
    q
}

/// Encode a domain name into DNS wire-format labels.
///
/// Trailing dots are stripped; empty or `"."` input produces a
/// single zero byte (root label).
pub fn encode_qname(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Build a DNS UPDATE header (opcode=5) with the given section counts.
///
/// Returns the 12-byte DNS header only; the caller appends the zone,
/// prerequisite, update, and additional sections.
pub fn build_update_header(qdcount: u16, ancount: u16, nscount: u16, arcount: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x1234u16.to_be_bytes());
    let flags: u16 = (5u16) << 11; // opcode = UPDATE (5)
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&qdcount.to_be_bytes());
    buf.extend_from_slice(&ancount.to_be_bytes());
    buf.extend_from_slice(&nscount.to_be_bytes());
    buf.extend_from_slice(&arcount.to_be_bytes());
    buf
}

/// Build a zone question section (zone name + SOA + IN).
pub fn build_zone_question(zone: &str) -> Vec<u8> {
    let mut buf = encode_qname(zone);
    buf.extend_from_slice(&6u16.to_be_bytes()); // SOA
    buf.extend_from_slice(&1u16.to_be_bytes()); // IN
    buf
}

/// Build a single RR for inclusion in an UPDATE section.
pub fn build_rr(name: &str, rtype: u16, rdata: &[u8], ttl: u32) -> Vec<u8> {
    let mut buf = encode_qname(name);
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // IN
    buf.extend_from_slice(&ttl.to_be_bytes());
    buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(rdata);
    buf
}

/// Build a complete DNS UPDATE query that adds a single record.
///
/// The query contains:
/// - 1 zone question (SOA)
/// - 0 prerequisites
/// - 1 update RR
/// - 0 additional data
pub fn build_update_add_record(zone: &str, name: &str, rtype: u16, rdata: &[u8], ttl: u32) -> Vec<u8> {
    let mut buf = build_update_header(1, 0, 0, 1);
    buf.extend_from_slice(&build_zone_question(zone));
    buf.extend_from_slice(&build_rr(name, rtype, rdata, ttl));
    buf
}
