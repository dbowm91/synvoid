#[derive(Debug, Clone)]
pub struct ProtocolDetectionResult<P> {
    pub protocol: P,
    pub confidence: f32,
    pub matched_pattern: String,
}

#[inline]
pub fn looks_like_dns(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let opcode = (flags >> 11) & 0xF;
    if opcode > 2 {
        return false;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    qdcount != 0 && qdcount <= 100
}

#[inline]
pub fn extract_first_line(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let start = data.first()
        .map(|&b| if b == b'\r' { 1 } else { 0 })
        .unwrap_or(0);

    if start >= end {
        return String::new();
    }

    let slice = &data[start..end];
    String::from_utf8_lossy(slice).into_owned()
}
