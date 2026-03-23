use crate::protocol::detect_common::{looks_like_dns, ProtocolDetectionResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpProtocol {
    Dns,
    Dhcp,
    Ntp,
    Snmp,
    Stun,
    Quic,
    Mdns,
    Syslog,
    Rtp,
    Ssdp,
    Coap,
    WireGuard,
    OpenVPN,
    DtLs,
    Unknown,
}

impl UdpProtocol {
    pub fn as_str(&self) -> &str {
        match self {
            UdpProtocol::Dns => "dns",
            UdpProtocol::Dhcp => "dhcp",
            UdpProtocol::Ntp => "ntp",
            UdpProtocol::Snmp => "snmp",
            UdpProtocol::Stun => "stun",
            UdpProtocol::Quic => "quic",
            UdpProtocol::Mdns => "mdns",
            UdpProtocol::Syslog => "syslog",
            UdpProtocol::Rtp => "rtp",
            UdpProtocol::Ssdp => "ssdp",
            UdpProtocol::Coap => "coap",
            UdpProtocol::WireGuard => "wireguard",
            UdpProtocol::OpenVPN => "openvpn",
            UdpProtocol::DtLs => "dtls",
            UdpProtocol::Unknown => "unknown",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "dns" => UdpProtocol::Dns,
            "dhcp" => UdpProtocol::Dhcp,
            "ntp" => UdpProtocol::Ntp,
            "snmp" => UdpProtocol::Snmp,
            "stun" => UdpProtocol::Stun,
            "quic" => UdpProtocol::Quic,
            "mdns" => UdpProtocol::Mdns,
            "syslog" => UdpProtocol::Syslog,
            "rtp" => UdpProtocol::Rtp,
            "ssdp" => UdpProtocol::Ssdp,
            "coap" => UdpProtocol::Coap,
            "wireguard" | "wg" => UdpProtocol::WireGuard,
            "openvpn" => UdpProtocol::OpenVPN,
            "dtls" => UdpProtocol::DtLs,
            _ => UdpProtocol::Unknown,
        }
    }
}

impl crate::filter::Protocol for UdpProtocol {
    fn as_str(&self) -> &str {
        UdpProtocol::as_str(self)
    }

    fn from_str(s: &str) -> Self {
        UdpProtocol::from_str(s)
    }
}

pub type UdpProtocolResult = ProtocolDetectionResult<UdpProtocol>;

pub struct UdpProtocolDetector {
    min_packet_size: usize,
}

impl Default for UdpProtocolDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for UdpProtocolDetector {
    fn clone(&self) -> Self {
        Self {
            min_packet_size: self.min_packet_size,
        }
    }
}

impl UdpProtocolDetector {
    pub fn new() -> Self {
        Self {
            min_packet_size: 12,
        }
    }

    pub fn detect_from_bytes(&self, data: &[u8]) -> UdpProtocolResult {
        if data.len() < 2 {
            return UdpProtocolResult {
                protocol: UdpProtocol::Unknown,
                confidence: 0.0,
                matched_pattern: "too_short".to_string(),
            };
        }

        let protocol = self.detect_protocol(data);

        UdpProtocolResult {
            protocol,
            confidence: 1.0,
            matched_pattern: "packet_bytes".to_string(),
        }
    }

    fn detect_protocol(&self, data: &[u8]) -> UdpProtocol {
        if data.len() < 2 {
            return UdpProtocol::Unknown;
        }

        if self.looks_like_quic(data) {
            return UdpProtocol::Quic;
        }

        if self.looks_like_wireguard(data) {
            return UdpProtocol::WireGuard;
        }

        if self.looks_like_stun(data) {
            return UdpProtocol::Stun;
        }

        if looks_like_dns(data) {
            return UdpProtocol::Dns;
        }

        if self.looks_like_dhcp(data) {
            return UdpProtocol::Dhcp;
        }

        if self.looks_like_ntp(data) {
            return UdpProtocol::Ntp;
        }

        if self.looks_like_snmp(data) {
            return UdpProtocol::Snmp;
        }

        if self.looks_like_ssdp(data) {
            return UdpProtocol::Ssdp;
        }

        if self.looks_like_coap(data) {
            return UdpProtocol::Coap;
        }

        if self.looks_like_rtp(data) {
            return UdpProtocol::Rtp;
        }

        if self.looks_like_dtls(data) {
            return UdpProtocol::DtLs;
        }

        if self.looks_like_openvpn(data) {
            return UdpProtocol::OpenVPN;
        }

        if self.looks_like_syslog(data) {
            return UdpProtocol::Syslog;
        }

        UdpProtocol::Unknown
    }

    fn has_valid_dns_question(&self, data: &[u8], _is_query: bool) -> bool {
        let mut pos = 12;
        let max_pos = data.len();

        if pos >= max_pos {
            return false;
        }

        loop {
            if pos >= max_pos {
                return false;
            }

            let label_len = data[pos] as usize;

            if label_len == 0 {
                pos += 1;
                break;
            }

            if label_len > 63 {
                if label_len >= 0xC0 {
                    if pos + 1 >= max_pos {
                        return false;
                    }
                    pos += 2;
                    break;
                }
                return false;
            }

            pos += 1 + label_len;

            if pos > max_pos {
                return false;
            }
        }

        if pos + 4 > max_pos {
            return false;
        }

        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);

        if qtype > 259 {
            return false;
        }

        if qclass != 1 && qclass != 255 && qclass != 3 && qclass != 4 {
            return false;
        }

        true
    }

    fn looks_like_dhcp(&self, data: &[u8]) -> bool {
        if data.len() < 240 {
            return false;
        }

        let op = data[0];
        if op != 1 && op != 2 {
            return false;
        }

        let htype = data[1];
        if htype != 1 {
            return false;
        }

        let hlen = data[2];
        if hlen != 6 {
            return false;
        }

        let magic = &data[236..240];
        if magic != [0x63, 0x82, 0x53, 0x63] {
            return false;
        }

        true
    }

    fn looks_like_ntp(&self, data: &[u8]) -> bool {
        if data.len() != 48 {
            return false;
        }

        let first_byte = data[0];
        let _li = (first_byte >> 6) & 0x3;
        let vn = (first_byte >> 3) & 0x7;
        let mode = first_byte & 0x7;

        if vn < 1 || vn > 4 {
            return false;
        }

        if mode < 1 || mode > 7 {
            return false;
        }

        let stratum = data[1];
        if stratum > 16 && stratum != 0 {
            return false;
        }

        true
    }

    fn looks_like_snmp(&self, data: &[u8]) -> bool {
        if data.len() < 10 {
            return false;
        }

        if data[0] != 0x30 {
            return false;
        }

        if data.len() > 2 && data[2] == 0x02 && data[3] == 0x01 {
            let version = data[4];
            if version <= 2 {
                if data.len() > 5 && data[5] == 0x04 {
                    return true;
                }
            }
        }

        false
    }

    fn looks_like_stun(&self, data: &[u8]) -> bool {
        if data.len() < 20 {
            return false;
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);

        let is_binding =
            msg_type == 0x0001 || msg_type == 0x0101 || msg_type == 0x0111 || msg_type == 0x0112;

        if !is_binding && (msg_type & 0xC000) != 0 {
            return false;
        }

        let magic_cookie = &data[4..8];
        if magic_cookie != [0x21, 0x12, 0xA4, 0x42] {
            return false;
        }

        true
    }

    fn looks_like_quic(&self, data: &[u8]) -> bool {
        if data.len() < 17 {
            return false;
        }

        let first_byte = data[0];
        let is_long_header = (first_byte & 0x80) != 0;

        if is_long_header {
            if data.len() < 6 {
                return false;
            }
            let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            if version == 0 {
                if data.len() >= 5 {
                    let ver = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
                    if ver == 0xff000016 || ver == 0xff000017 || ver == 0xff00001d {
                        return true;
                    }
                }
                return false;
            }
            if version == 1 || version == 2 || (version & 0xFF000000) == 0xFF000000 {
                return true;
            }
            return false;
        }

        false
    }

    fn looks_like_mdns(&self, data: &[u8]) -> bool {
        if data.len() < 12 {
            return false;
        }

        let flags = u16::from_be_bytes([data[2], data[3]]);
        let _qr = (flags >> 15) & 1;

        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);

        if qdcount == 0 && ancount == 0 {
            return false;
        }

        if data.len() > 12 {
            if let Some(&label_len) = data.get(12) {
                if label_len > 0 && label_len <= 63 {
                    if let Some(&first_char) = data.get(13) {
                        if first_char == b'_' {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn looks_like_syslog(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        if data[0] == b'<' {
            if let Some(pos) = data.iter().position(|&b| b == b'>') {
                if pos > 1 && pos < 5 {
                    let priority: Result<u8, _> =
                        std::str::from_utf8(&data[1..pos]).unwrap_or("0").parse();
                    if let Ok(p) = priority {
                        if p <= 191 {
                            return true;
                        }
                    }
                }
            }
        }

        if data[0] >= b'0' && data[0] <= b'9' {
            if data.len() >= 2 && data[1] == b' ' {
                return true;
            }
            if data.len() >= 3 && data[2] == b'>' {
                return true;
            }
        }

        false
    }

    fn looks_like_rtp(&self, data: &[u8]) -> bool {
        if data.len() < 12 {
            return false;
        }

        let first_byte = data[0];
        let version = (first_byte >> 6) & 0x3;

        if version != 2 {
            return false;
        }

        let pt = data[1] & 0x7F;
        if pt > 127 {
            return false;
        }

        let _seq = u16::from_be_bytes([data[2], data[3]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        if ssrc == 0 {
            return false;
        }

        true
    }

    fn looks_like_ssdp(&self, data: &[u8]) -> bool {
        if data.len() < 20 {
            return false;
        }

        let first_line = String::from_utf8_lossy(&data[..20.min(data.len())]);

        if first_line.starts_with("M-SEARCH ")
            || first_line.starts_with("NOTIFY ")
            || first_line.starts_with("HTTP/1.")
        {
            if first_line.contains("* HTTP")
                || first_line.contains("ST:")
                || first_line.contains("NT:")
                || first_line.contains("LOCATION:")
            {
                return true;
            }
        }

        false
    }

    fn looks_like_coap(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        let first_byte = data[0];
        let version = (first_byte >> 6) & 0x3;
        let type_val = (first_byte >> 4) & 0x3;
        let tkl = first_byte & 0x0F;

        if version != 1 {
            return false;
        }

        if type_val > 3 {
            return false;
        }

        if tkl > 8 {
            return false;
        }

        let code = data[1];
        if code > 5 && code < 64 {
            return false;
        }

        true
    }

    fn looks_like_wireguard(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        let msg_type = data[0];

        if msg_type >= 1 && msg_type <= 4 {
            let reserved = u32::from_le_bytes([data[1], data[2], data[3], 0]);
            if reserved == 0 {
                match msg_type {
                    1 => return data.len() >= 148,
                    2 => return data.len() >= 92,
                    3 => return data.len() >= 44,
                    4 => return data.len() >= 16 && data.len() <= 65535,
                    _ => {}
                }
            }
        }

        false
    }

    fn looks_like_openvpn(&self, data: &[u8]) -> bool {
        if data.len() < 6 {
            return false;
        }

        if data[0] == 0x38 || data[0] == 0x40 {
            if data.len() >= 14 {
                let opcode = data[0] >> 3;
                let _key_id = data[0] & 0x07;

                if opcode >= 1 && opcode <= 10 {
                    if data[1] == 0x00 || data[1] == 0x01 {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn looks_like_dtls(&self, data: &[u8]) -> bool {
        if data.len() < 13 {
            return false;
        }

        let content_type = data[0];
        if content_type < 20 || content_type > 26 {
            return false;
        }

        let version = u16::from_be_bytes([data[1], data[2]]);
        if version != 0xFEFF && version != 0xFDFD {
            return false;
        }

        let _epoch = u16::from_be_bytes([data[3], data[4]]);

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_detection() {
        let detector = UdpProtocolDetector::new();

        let dns_query = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        assert_eq!(
            detector.detect_from_bytes(&dns_query).protocol,
            UdpProtocol::Dns
        );
    }

    #[test]
    fn test_ntp_detection() {
        let detector = UdpProtocolDetector::new();

        let mut ntp_packet = [0u8; 48];
        ntp_packet[0] = 0x1B;
        ntp_packet[1] = 0x00;

        assert_eq!(
            detector.detect_from_bytes(&ntp_packet).protocol,
            UdpProtocol::Ntp
        );
    }

    #[test]
    fn test_stun_detection() {
        let detector = UdpProtocolDetector::new();

        let mut stun_packet = [0u8; 20];
        stun_packet[0] = 0x00;
        stun_packet[1] = 0x01;
        stun_packet[4] = 0x21;
        stun_packet[5] = 0x12;
        stun_packet[6] = 0xA4;
        stun_packet[7] = 0x42;

        assert_eq!(
            detector.detect_from_bytes(&stun_packet).protocol,
            UdpProtocol::Stun
        );
    }

    #[test]
    fn test_quic_detection() {
        let detector = UdpProtocolDetector::new();

        let mut quic_packet = [0u8; 20];
        quic_packet[0] = 0xC0;
        quic_packet[1] = 0x00;
        quic_packet[2] = 0x00;
        quic_packet[3] = 0x00;
        quic_packet[4] = 0x01;

        assert_eq!(
            detector.detect_from_bytes(&quic_packet).protocol,
            UdpProtocol::Quic
        );

        let mut quic_v2_packet = [0u8; 20];
        quic_v2_packet[0] = 0xD0;
        quic_v2_packet[1] = 0x00;
        quic_v2_packet[2] = 0x00;
        quic_v2_packet[3] = 0x00;
        quic_v2_packet[4] = 0x02;

        assert_eq!(
            detector.detect_from_bytes(&quic_v2_packet).protocol,
            UdpProtocol::Quic
        );
    }

    #[test]
    fn test_syslog_detection() {
        let detector = UdpProtocolDetector::new();

        let syslog = b"<134>Feb 18 12:00:00 host message";
        assert_eq!(
            detector.detect_from_bytes(syslog).protocol,
            UdpProtocol::Syslog
        );
    }

    #[test]
    fn test_ssdp_detection() {
        let detector = UdpProtocolDetector::new();

        let ssdp = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n";
        assert_eq!(detector.detect_from_bytes(ssdp).protocol, UdpProtocol::Ssdp);
    }

    #[test]
    fn test_wireguard_detection() {
        let detector = UdpProtocolDetector::new();

        let mut wg_packet = [0u8; 148];
        wg_packet[0] = 0x01;

        assert_eq!(
            detector.detect_from_bytes(&wg_packet).protocol,
            UdpProtocol::WireGuard
        );
    }
}
