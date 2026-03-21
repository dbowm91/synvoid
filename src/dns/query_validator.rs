use std::net::IpAddr;

use super::server::RecordType;

#[derive(Clone, Default)]
pub struct DnsQueryValidator {
    max_query_size: usize,
    max_labels: usize,
    max_label_length: usize,
    max_name_length: usize,
    max_records: usize,
    max_record_size: usize,
    max_ttl: u32,
}

impl DnsQueryValidator {
    pub fn new() -> Self {
        Self {
            max_query_size: 65535,
            max_labels: 16,
            max_label_length: 63,
            max_name_length: 255,
            max_records: 100,
            max_record_size: 65535,
            max_ttl: 86400,
        }
    }

    pub fn from_config(
        max_query_size: usize,
        max_labels: usize,
        max_label_length: usize,
        max_name_length: usize,
        max_records: usize,
        max_record_size: usize,
        max_ttl: u32,
    ) -> Self {
        Self {
            max_query_size: max_query_size.max(512),
            max_labels: max_labels.max(1).min(127),
            max_label_length: max_label_length.max(1).min(63),
            max_name_length: max_name_length.max(1).min(255),
            max_records: max_records.max(1),
            max_record_size: max_record_size.max(512),
            max_ttl: max_ttl.min(86400 * 7),
        }
    }

    pub fn validate_query(&self, query: &[u8]) -> Result<(), String> {
        if query.len() > self.max_query_size {
            return Err(format!(
                "Query size {} exceeds maximum {}",
                query.len(),
                self.max_query_size
            ));
        }

        if query.len() < 12 {
            return Err("Query too small".to_string());
        }

        let flags = match super::wire::get_message_flags(query) {
            Some(f) => f,
            None => return Err("Invalid DNS header".to_string()),
        };

        if !flags.is_standard_query() {
            return Err("Not a standard query".to_string());
        }

        if flags.is_response {
            return Err("Not a query message".to_string());
        }

        let qdcount = u16::from_be_bytes([query[4], query[5]]);

        if qdcount == 0 {
            return Err("No questions in query".to_string());
        }

        if qdcount > 1 {
            return Err("Multiple questions not supported".to_string());
        }

        let mut pos = 12;
        let mut labels_count = 0;
        let mut name_length = 0;

        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }

            if len > self.max_label_length {
                return Err(format!(
                    "Label length {} exceeds maximum {}",
                    len, self.max_label_length
                ));
            }

            if pos + 1 + len > query.len() {
                return Err("Incomplete label in query name".to_string());
            }

            labels_count += 1;
            name_length += 1 + len;

            if labels_count > self.max_labels {
                return Err(format!(
                    "Too many labels ({} > {})",
                    labels_count, self.max_labels
                ));
            }

            if name_length > self.max_name_length {
                return Err(format!(
                    "Name length {} exceeds maximum {}",
                    name_length, self.max_name_length
                ));
            }

            pos += 1 + len;
        }

        if pos + 4 > query.len() {
            return Err("Incomplete query structure".to_string());
        }

        let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
        let qclass = u16::from_be_bytes([query[pos + 2], query[pos + 3]]);

        if qclass != 1 {
            return Err("Unsupported query class".to_string());
        }

        if qtype == 0 {
            return Err("Invalid query type 0".to_string());
        }

        let end_of_question = pos + 4;

        if end_of_question < query.len() {
            Self::validate_edns_options(query, end_of_question)?;
        }

        Ok(())
    }

    fn validate_edns_options(query: &[u8], pos: usize) -> Result<(), String> {
        if pos + 11 > query.len() {
            return Ok(());
        }

        let udp_payload_size = u16::from_be_bytes([query[pos], query[pos + 1]]);
        if udp_payload_size != 0 && udp_payload_size < 512 {
            return Err(format!(
                "Invalid EDNS UDP payload size: {}",
                udp_payload_size
            ));
        }

        let _extended_rcode = query[pos + 2];
        let version = query[pos + 3];

        if version > 0 {
            return Err(format!("Unsupported EDNS version: {}", version));
        }

        let _z = u16::from_be_bytes([query[pos + 4], query[pos + 5]]);

        let rdlen = u16::from_be_bytes([query[pos + 10], query[pos + 11]]);

        if rdlen > 0 {
            let rdata_start = pos + 12;
            if rdata_start + rdlen as usize > query.len() {
                return Err("Incomplete EDNS options".to_string());
            }

            let mut opt_pos = rdata_start;
            let opt_end = rdata_start + rdlen as usize;

            while opt_pos + 4 < opt_end {
                let opt_code = u16::from_be_bytes([query[opt_pos], query[opt_pos + 1]]);
                let opt_len = u16::from_be_bytes([query[opt_pos + 2], query[opt_pos + 3]]);

                if opt_code == 0 && opt_len == 0 {
                    opt_pos += 4;
                    continue;
                }

                if opt_pos + 4 + opt_len as usize > query.len() {
                    return Err("Incomplete EDNS option data".to_string());
                }

                opt_pos += 4 + opt_len as usize;
            }
        }

        Ok(())
    }

    pub fn validate_response(&self, response: &[u8]) -> Result<(), String> {
        if response.len() > self.max_record_size {
            return Err(format!(
                "Response size {} exceeds maximum {}",
                response.len(),
                self.max_record_size
            ));
        }

        if response.len() < 12 {
            return Err("Response too small".to_string());
        }

        let flags = u16::from_be_bytes([response[2], response[3]]);
        let qr = (flags & 0x8000) != 0;
        if !qr {
            return Err("Not a response message".to_string());
        }

        let ancount = u16::from_be_bytes([response[4], response[5]]);
        if ancount as usize > self.max_records {
            return Err(format!(
                "Too many answer records ({} > {})",
                ancount, self.max_records
            ));
        }

        Ok(())
    }

    pub fn validate_response_data(
        &self,
        response: &[u8],
        block_private_ips: bool,
    ) -> Result<(), String> {
        if response.len() < 12 {
            return Ok(());
        }

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        if ancount == 0 {
            return Ok(());
        }

        if !block_private_ips {
            return Ok(());
        }

        let mut pos = 12;

        let qdcount = u16::from_be_bytes([response[4], response[5]]);
        for _ in 0..qdcount {
            while pos < response.len() {
                let len = response[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                pos += 1 + len;
            }
            if pos + 4 > response.len() {
                break;
            }
            pos += 4;
        }

        for _ in 0..ancount {
            while pos < response.len() {
                let len = response[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                pos += 1 + len;
            }

            if pos + 10 > response.len() {
                break;
            }

            let record_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
            pos += 10;

            let rdlen = if pos + 2 > response.len() {
                break;
            } else {
                u16::from_be_bytes([response[pos], response[pos + 1]]) as usize
            };
            pos += 2;

            if pos + rdlen > response.len() {
                break;
            }

            if record_type == 1 {
                if rdlen == 4 {
                    let ip = IpAddr::from([
                        response[pos],
                        response[pos + 1],
                        response[pos + 2],
                        response[pos + 3],
                    ]);
                    if Self::is_internal_ip(ip) {
                        return Err(format!("Response contains private IP: {}", ip));
                    }
                }
            } else if record_type == 28 {
                if rdlen == 16 {
                    let segments = [
                        u16::from_be_bytes([response[pos], response[pos + 1]]),
                        u16::from_be_bytes([response[pos + 2], response[pos + 3]]),
                        u16::from_be_bytes([response[pos + 4], response[pos + 5]]),
                        u16::from_be_bytes([response[pos + 6], response[pos + 7]]),
                        u16::from_be_bytes([response[pos + 8], response[pos + 9]]),
                        u16::from_be_bytes([response[pos + 10], response[pos + 11]]),
                        u16::from_be_bytes([response[pos + 12], response[pos + 13]]),
                        u16::from_be_bytes([response[pos + 14], response[pos + 15]]),
                    ];
                    let ip = IpAddr::V6(std::net::Ipv6Addr::from(segments));
                    if Self::is_internal_ip(ip) {
                        return Err(format!("Response contains private IPv6: {}", ip));
                    }
                }
            }

            pos += rdlen;
        }

        Ok(())
    }

    pub fn validate_record_ttl(&self, ttl: u32) -> Result<(), String> {
        if ttl > self.max_ttl {
            return Err(format!("TTL {} exceeds maximum {}", ttl, self.max_ttl));
        }
        Ok(())
    }

    pub fn validate_record_size(&self, size: usize) -> Result<(), String> {
        if size > self.max_record_size {
            return Err(format!(
                "Record size {} exceeds maximum {}",
                size, self.max_record_size
            ));
        }
        Ok(())
    }

    pub fn validate_query_with_response(&self, query: &[u8]) -> Result<(), Option<Vec<u8>>> {
        if query.len() > self.max_query_size {
            let resp = super::wire::build_error_response(query, super::wire::RCODE_REFUSED);
            return Err(resp);
        }

        if query.len() < 12 {
            let resp = super::wire::build_error_response(query, super::wire::RCODE_REFUSED);
            return Err(resp);
        }

        let flags = match super::wire::get_message_flags(query) {
            Some(f) => f,
            None => {
                let resp = super::wire::build_error_response(query, super::wire::RCODE_REFUSED);
                return Err(resp);
            }
        };

        if !flags.is_standard_query() {
            let resp = super::wire::build_error_response(query, super::wire::RCODE_NOTIMP);
            return Err(resp);
        }

        if flags.is_response {
            let resp = super::wire::build_error_response(query, super::wire::RCODE_REFUSED);
            return Err(resp);
        }

        let qdcount = u16::from_be_bytes([query[4], query[5]]);

        if qdcount == 0 {
            let resp = super::wire::build_error_response(query, super::wire::RCODE_REFUSED);
            return Err(resp);
        }

        if qdcount > 1 {
            let resp = super::wire::build_error_response(query, super::wire::RCODE_NOTIMP);
            return Err(resp);
        }

        let mut pos = 12;
        let mut labels_count = 0;
        let mut name_length = 0;

        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }

            if len > self.max_label_length {
                let resp = super::wire::build_error_response(query, super::wire::RCODE_REFUSED);
                return Err(resp);
            }

            labels_count += 1;
            name_length += 1 + len;

            if labels_count > self.max_labels {
                let resp = super::wire::build_error_response(query, super::wire::RCODE_REFUSED);
                return Err(resp);
            }

            if name_length > self.max_name_length {
                let resp = super::wire::build_error_response(query, super::wire::RCODE_REFUSED);
                return Err(resp);
            }

            pos += 1 + len;
        }

        if pos + 4 > query.len() {
            let resp = super::wire::build_error_response(query, super::wire::RCODE_REFUSED);
            return Err(resp);
        }

        let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
        let qclass = u16::from_be_bytes([query[pos + 2], query[pos + 3]]);

        if qclass != 1 {
            let resp = super::wire::build_error_response(query, super::wire::RCODE_NOTIMP);
            return Err(resp);
        }

        let qtype_record = RecordType::from(qtype);
        if qtype == 255 || qtype == 252 {
            return Ok(());
        }

        // Allow unknown query types for forward compatibility
        // RFC 1035 Section 3.2.2: TYPE values are an unsigned 16-bit integer
        // New types can be defined over time, so we should not reject unknown ones
        let unknown_type = RecordType::NULL;
        if qtype_record == unknown_type && qtype != 0 {
            // Only reject type 0 which is reserved
            return Ok(());
        }

        Ok(())
    }

    pub fn is_internal_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(addr) => {
                addr.octets()[0] == 10 || // 10.0.0.0/8
                (addr.octets()[0] == 172 && (addr.octets()[1] & 0xF0) == 16) || // 172.16.0.0/12
                (addr.octets()[0] == 192 && addr.octets()[1] == 168) || // 192.168.0.0/16
                (addr.octets()[0] == 169 && addr.octets()[1] == 254) || // 169.254.0.0/16
                ((addr.octets()[0] & 0xFE) == 0xFC) // 224.0.0.0/3
            }
            IpAddr::V6(addr) => {
                addr.segments()[0] == 0xFE80 || // fe80::/10
                addr.segments()[0] == 0xFC00 || // fc00::/7
                addr.segments()[0] == 0xFF00 || // ff00::/8
                addr.segments()[0] == 0xFE80 || // fe80::/10
                addr.segments()[0] == 0x0000 || // ::/128
                addr.segments()[0] == 0x2001 && addr.segments()[1] == 0xDB8 // 2001:db8::/32
            }
        }
    }

    pub fn is_reserved_name(name: &str) -> bool {
        let reserved = [
            "localhost",
            "localdomain",
            "example",
            "invalid",
            "test",
            "arpa",
            "in-addr.arpa",
            "ip6.arpa",
            "root-servers.net",
            "iana-servers.net",
        ];

        let name_lower = name.to_lowercase();
        reserved
            .iter()
            .any(|r| name_lower.ends_with(r) || name_lower.starts_with(r))
    }
}

#[derive(Debug)]
pub enum DnsQueryType {
    Standard,
    ZoneTransfer,
    Status,
    IQuery,
    Notify,
    Update,
    DynamicUpdate,
}

impl DnsQueryType {
    pub fn from_flags(flags: u16) -> Self {
        let opcode = (flags & 0x7800) >> 11;
        match opcode {
            0 => DnsQueryType::Standard,
            1 => DnsQueryType::ZoneTransfer,
            2 => DnsQueryType::Status,
            3 => DnsQueryType::IQuery,
            4 => DnsQueryType::Notify,
            5 => DnsQueryType::Update,
            _ => DnsQueryType::Standard,
        }
    }

    pub fn is_standard_query(&self) -> bool {
        matches!(self, DnsQueryType::Standard)
    }
}

#[derive(Debug)]
pub enum DnsQueryClass {
    Internet,
    CSNet,
    Chaos,
    Hesiod,
    Any,
}

impl DnsQueryClass {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => DnsQueryClass::Internet,
            2 => DnsQueryClass::CSNet,
            3 => DnsQueryClass::Chaos,
            4 => DnsQueryClass::Hesiod,
            255 => DnsQueryClass::Any,
            _ => DnsQueryClass::Internet,
        }
    }

    pub fn is_supported(&self) -> bool {
        matches!(self, DnsQueryClass::Internet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_valid_query(qname: &str, qtype: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&0x1234u16.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());

        for part in qname.split('.') {
            query.push(part.len() as u8);
            query.extend_from_slice(part.as_bytes());
        }
        query.push(0);

        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());

        query
    }

    #[test]
    fn test_valid_a_query() {
        let validator = DnsQueryValidator::new();
        let query = build_valid_query("example.com", 1);
        assert!(validator.validate_query(&query).is_ok());
    }

    #[test]
    fn test_valid_aaaa_query() {
        let validator = DnsQueryValidator::new();
        let query = build_valid_query("example.com", 28);
        assert!(validator.validate_query(&query).is_ok());
    }

    #[test]
    fn test_valid_txt_query() {
        let validator = DnsQueryValidator::new();
        let query = build_valid_query("example.com", 16);
        assert!(validator.validate_query(&query).is_ok());
    }

    #[test]
    fn test_query_too_small() {
        let validator = DnsQueryValidator::new();
        let result = validator.validate_query(b"too short");
        assert!(result.is_err());
    }

    #[test]
    fn test_query_no_question() {
        let mut query = vec![0u8; 12];
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        let validator = DnsQueryValidator::new();
        let result = validator.validate_query(&query);
        assert!(result.is_err());
    }

    #[test]
    fn test_query_multiple_questions() {
        let mut query = build_valid_query("example.com", 1);
        // bytes 4-5 are qdcount (question count) in big endian
        query[4] = 0;
        query[5] = 2; // Set qdcount to 2
        let validator = DnsQueryValidator::new();
        let result = validator.validate_query(&query);
        assert!(result.is_err());
    }

    #[test]
    fn test_query_label_too_long() {
        let mut query = build_valid_query("example.com", 1);
        query[12] = 64;
        let validator = DnsQueryValidator::new();
        let result = validator.validate_query(&query);
        assert!(result.is_err());
    }

    #[test]
    fn test_query_too_many_labels() {
        let name = "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a";
        let query = build_valid_query(name, 1);
        let validator = DnsQueryValidator::new();
        let result = validator.validate_query(&query);
        assert!(result.is_err());
    }

    #[test]
    fn test_query_name_too_long() {
        let name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let query = build_valid_query(name, 1);
        let validator = DnsQueryValidator::new();
        let result = validator.validate_query(&query);
        assert!(result.is_err());
    }

    #[test]
    fn test_query_unsupported_class() {
        let mut query = build_valid_query("example.com", 1);
        let len = query.len();
        query[len - 2] = 2;
        let validator = DnsQueryValidator::new();
        let result = validator.validate_query(&query);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_internal_ip_v4_private() {
        assert!(DnsQueryValidator::is_internal_ip(
            "10.0.0.1".parse().unwrap()
        ));
        assert!(DnsQueryValidator::is_internal_ip(
            "172.16.0.1".parse().unwrap()
        ));
        assert!(DnsQueryValidator::is_internal_ip(
            "192.168.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_internal_ip_v4_public() {
        assert!(!DnsQueryValidator::is_internal_ip(
            "8.8.8.8".parse().unwrap()
        ));
        assert!(!DnsQueryValidator::is_internal_ip(
            "1.1.1.1".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_internal_ip_v6_link_local() {
        assert!(DnsQueryValidator::is_internal_ip(
            "fe80::1".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_internal_ip_v6_unique_local() {
        assert!(DnsQueryValidator::is_internal_ip(
            "fc00::1".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_reserved_name() {
        assert!(DnsQueryValidator::is_reserved_name("localhost"));
        assert!(DnsQueryValidator::is_reserved_name("localhost.example.com"));
        assert!(DnsQueryValidator::is_reserved_name("example.in-addr.arpa"));
    }

    #[test]
    fn test_response_validation() {
        let validator = DnsQueryValidator::new();
        let mut response = build_valid_query("example.com", 1);
        assert!(response.len() >= 12);
        // Set the QR bit (bit 15) to make it a response
        response[2] |= 0x80;
        let result = validator.validate_response(&response);
        assert!(result.is_ok(), "Valid response should pass validation");
    }

    #[test]
    fn test_query_any_type_allowed() {
        let validator = DnsQueryValidator::new();
        let query = build_valid_query("example.com", 255);
        let result = validator.validate_query(&query);
        assert!(result.is_ok(), "ANY query type (255) should be allowed");
    }

    #[test]
    fn test_query_axfr_type_allowed() {
        let validator = DnsQueryValidator::new();
        let query = build_valid_query("example.com", 252);
        let result = validator.validate_query(&query);
        assert!(result.is_ok(), "AXFR query type (252) should be allowed");
    }

    #[test]
    fn test_query_caa_type_allowed() {
        let validator = DnsQueryValidator::new();
        let query = build_valid_query("example.com", 257);
        let result = validator.validate_query(&query);
        assert!(result.is_ok(), "CAA query type (257) should be allowed");
    }

    #[test]
    fn test_query_ttl_validation() {
        let validator = DnsQueryValidator::new();
        let result = validator.validate_record_ttl(86400);
        assert!(result.is_ok(), "Max TTL should be allowed");

        let result = validator.validate_record_ttl(86401);
        assert!(result.is_err(), "TTL exceeding max should be rejected");
    }

    #[test]
    fn test_query_critical_types_allowed() {
        let validator = DnsQueryValidator::new();
        let critical_types = [2, 5, 6, 12, 15, 16, 28, 33];
        for qtype in critical_types {
            let query = build_valid_query("example.com", qtype);
            let result = validator.validate_query(&query);
            assert!(result.is_ok(), "Query type {} should be allowed", qtype);
        }
    }
}
