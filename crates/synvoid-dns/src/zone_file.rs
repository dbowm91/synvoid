use std::collections::HashMap;

use thiserror::Error;

use crate::server::{RecordType, Zone};

#[derive(Debug, Clone)]
pub struct ZoneFileParser {
    origin: String,
    default_ttl: u32,
    soa_serial: u32,
    soa_refresh: u32,
    soa_retry: u32,
    soa_expire: u32,
    soa_minimum: u32,
    soa_mname: String,
    soa_rname: String,
}

#[derive(Debug, Clone)]
pub struct ParsedRecord {
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub value: String,
    pub priority: Option<u32>,
}

#[derive(Debug, Error)]
pub enum ZoneParseError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Invalid record: {0}")]
    InvalidRecord(String),
}

impl ZoneFileParser {
    pub fn new(origin: String) -> Self {
        Self {
            origin: origin.trim_end_matches('.').to_string(),
            default_ttl: 3600,
            soa_serial: 1,
            soa_refresh: 3600,
            soa_retry: 600,
            soa_expire: 604800,
            soa_minimum: 86400,
            soa_mname: String::new(),
            soa_rname: String::new(),
        }
    }

    pub fn parse_file(&mut self, path: &str) -> Result<Zone, ZoneParseError> {
        let content = std::fs::read_to_string(path)?;
        self.parse_content(&content)
    }

    pub fn parse_content(&mut self, content: &str) -> Result<Zone, ZoneParseError> {
        let mut records: HashMap<(String, RecordType), Vec<crate::server::DnsZoneRecord>> =
            HashMap::new();
        let mut current_name = String::new();
        let mut current_ttl = self.default_ttl;

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            if line.starts_with('$') {
                self.parse_directive(line)?;
                continue;
            }

            if let Some(record) =
                self.parse_record_line(line, &mut current_name, &mut current_ttl)?
            {
                let key = (record.name.clone(), record.record_type);
                records
                    .entry(key)
                    .or_default()
                    .push(crate::server::DnsZoneRecord {
                        name: record.name.clone(),
                        record_type: record.record_type,
                        value: record.value,
                        ttl: record.ttl,
                        priority: record.priority,
                    });
            }
        }

        if self.soa_mname.is_empty() {
            self.soa_mname = format!("ns1.{}", self.origin);
        }
        if self.soa_rname.is_empty() {
            self.soa_rname = format!("admin.{}", self.origin);
        }

        let soa_value = format!(
            "{} {} {} {} {} {} {}",
            self.soa_mname,
            self.soa_rname,
            self.soa_serial,
            self.soa_refresh,
            self.soa_retry,
            self.soa_expire,
            self.soa_minimum
        );

        let soa_key = ("@".to_string(), RecordType::SOA);
        records
            .entry(soa_key)
            .or_default()
            .push(crate::server::DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::SOA,
                value: soa_value,
                ttl: current_ttl,
                priority: None,
            });

        Ok(Zone {
            origin: self.origin.clone(),
            serial: self.soa_serial,
            records,
            dnskey_ttl: None,
            ksk_key: None,
            zsk_key: None,
            nsec3_enabled: false,
            nsec_enabled: true,
            nsec3param: None,
            history: Vec::new(),
        })
    }

    fn parse_directive(&mut self, directive: &str) -> Result<(), ZoneParseError> {
        let parts: Vec<&str> = directive.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        match parts[0].to_uppercase().as_str() {
            "$ORIGIN" => {
                if let Some(origin) = parts.get(1) {
                    self.origin = origin.trim_end_matches('.').to_string();
                }
            }
            "$TTL" => {
                if let Some(ttl) = parts.get(1) {
                    self.default_ttl = ttl.parse().unwrap_or(3600);
                }
            }
            "$INCLUDE" => {
                return Err(ZoneParseError::ParseError(
                    "$INCLUDE not supported".to_string(),
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn parse_record_line(
        &mut self,
        line: &str,
        current_name: &mut String,
        current_ttl: &mut u32,
    ) -> Result<Option<ParsedRecord>, ZoneParseError> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Ok(None);
        }

        let mut pos = 0;
        let mut name = parts[pos].to_string();

        if name
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            if let Ok(ttl) = name.parse::<u32>() {
                *current_ttl = ttl;
                pos += 1;
                if pos >= parts.len() {
                    return Ok(None);
                }
                name = parts[pos].to_string();
            }
        }

        if name == "@" {
            name = self.origin.clone();
        } else if !name.contains('.') && name != "IN" {
            if name != *current_name {
                *current_name = name.clone();
            }
            name = format!("{}.{}", name, self.origin);
        }

        if name.ends_with('.') {
            name.pop();
        }

        pos += 1;
        if pos >= parts.len() {
            return Ok(None);
        }

        if parts[pos] == "IN" {
            pos += 1;
        }
        if pos >= parts.len() {
            return Ok(None);
        }

        let record_type_str = parts[pos].to_uppercase();
        let record_type = match record_type_str.as_str() {
            "A" => RecordType::A,
            "AAAA" => RecordType::AAAA,
            "CNAME" => RecordType::CNAME,
            "MX" => RecordType::MX,
            "TXT" => RecordType::TXT,
            "NS" => RecordType::NS,
            "SOA" => RecordType::SOA,
            "SRV" => RecordType::SRV,
            "PTR" => RecordType::PTR,
            "CAA" => RecordType::CAA,
            "TLSA" => RecordType::TLSA,
            "SVCB" => RecordType::SVCB,
            "HTTPS" => RecordType::HTTPS,
            "NAPTR" => RecordType::NAPTR,
            "SSHFP" => RecordType::SSHFP,
            "DS" => RecordType::DS,
            "DNSKEY" => RecordType::DNSKEY,
            "RRSIG" => RecordType::RRSIG,
            "NSEC" => RecordType::NSEC,
            "NSEC3" => RecordType::NSEC3,
            "NSEC3PARAM" => RecordType::NSEC3PARAM,
            _ => return Ok(None),
        };

        pos += 1;
        if pos >= parts.len() {
            return Ok(None);
        }

        if record_type == RecordType::SOA {
            return self.parse_soa_record(&parts[pos..], name, *current_ttl);
        }

        let priority = if record_type == RecordType::MX || record_type == RecordType::SRV {
            let prio: u32 = parts[pos].parse().map_err(|e: std::num::ParseIntError| {
                ZoneParseError::InvalidRecord(format!(
                    "Invalid {} priority '{}': {}",
                    record_type_str, parts[pos], e
                ))
            })?;
            if prio > u16::MAX as u32 {
                return Err(ZoneParseError::InvalidRecord(format!(
                    "{} priority {} exceeds u16::MAX (65535)",
                    record_type_str, prio
                )));
            }
            pos += 1;
            Some(prio)
        } else {
            None
        };

        let value = if record_type == RecordType::TXT {
            parts[pos..].join(" ")
        } else {
            parts[pos].to_string()
        };

        Ok(Some(ParsedRecord {
            name,
            record_type,
            ttl: *current_ttl,
            value,
            priority,
        }))
    }

    fn parse_soa_record(
        &mut self,
        parts: &[&str],
        name: String,
        ttl: u32,
    ) -> Result<Option<ParsedRecord>, ZoneParseError> {
        if parts.len() < 7 {
            return Err(ZoneParseError::InvalidRecord(
                "SOA record requires 7 fields: mname rname serial refresh retry expire minimum"
                    .to_string(),
            ));
        }

        let mut mname = parts[0].trim_end_matches('.').to_string();
        if !mname.contains('.') {
            mname = format!("{}.{}", mname, self.origin);
        }
        self.soa_mname = mname.clone();

        let mut rname = parts[1].trim_end_matches('.').to_string();
        if !rname.contains('.') {
            rname = format!("{}.{}", rname, self.origin);
        }
        self.soa_rname = rname.clone();

        self.soa_serial = parts[2].parse().map_err(|e: std::num::ParseIntError| {
            ZoneParseError::InvalidRecord(format!(
                "SOA serial '{}' is not a valid u32: {}",
                parts[2], e
            ))
        })?;
        self.soa_refresh = parts[3].parse().map_err(|e: std::num::ParseIntError| {
            ZoneParseError::InvalidRecord(format!(
                "SOA refresh '{}' is not a valid u32: {}",
                parts[3], e
            ))
        })?;
        self.soa_retry = parts[4].parse().map_err(|e: std::num::ParseIntError| {
            ZoneParseError::InvalidRecord(format!(
                "SOA retry '{}' is not a valid u32: {}",
                parts[4], e
            ))
        })?;
        self.soa_expire = parts[5].parse().map_err(|e: std::num::ParseIntError| {
            ZoneParseError::InvalidRecord(format!(
                "SOA expire '{}' is not a valid u32: {}",
                parts[5], e
            ))
        })?;
        self.soa_minimum = parts[6].parse().map_err(|e: std::num::ParseIntError| {
            ZoneParseError::InvalidRecord(format!(
                "SOA minimum '{}' is not a valid u32: {}",
                parts[6], e
            ))
        })?;

        let value = format!(
            "{} {} {} {} {} {} {}",
            mname,
            rname,
            self.soa_serial,
            self.soa_refresh,
            self.soa_retry,
            self.soa_expire,
            self.soa_minimum
        );

        Ok(Some(ParsedRecord {
            name,
            record_type: RecordType::SOA,
            ttl,
            value,
            priority: None,
        }))
    }
}

pub fn parse_zone_file(path: &str, origin: &str) -> Result<Zone, ZoneParseError> {
    let mut parser = ZoneFileParser::new(origin.to_string());
    parser.parse_file(path)
}

pub fn parse_zone_content(content: &str, origin: &str) -> Result<Zone, ZoneParseError> {
    let mut parser = ZoneFileParser::new(origin.to_string());
    parser.parse_content(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_zone() {
        let content = r#"$TTL 3600
$ORIGIN example.com.
@       IN      SOA     ns1.example.com. admin.example.com. 2024030901 3600 600 604800 86400
@       IN      NS      ns1.example.com.
@       IN      A       192.0.2.1
www     IN      A       192.0.2.2
mail    IN      A       192.0.2.3
@       IN      MX      10 mail.example.com.
        "#;

        let zone = parse_zone_content(content, "example.com").unwrap();

        assert_eq!(zone.origin, "example.com");
        assert_eq!(zone.serial, 2024030901);

        // The zone parser stores "@" as the origin name
        let soa_key = ("example.com".to_string(), RecordType::SOA);
        assert!(zone.records.contains_key(&soa_key));

        let a_key = ("example.com".to_string(), RecordType::A);
        assert!(zone.records.contains_key(&a_key));
    }

    #[test]
    fn test_mx_priority_exceeds_u16_max_rejected() {
        let content = r#"$TTL 3600
$ORIGIN example.com.
@       IN      SOA     ns1.example.com. admin.example.com. 2024030901 3600 600 604800 86400
@       IN      MX      70000 mail.example.com.
        "#;

        let result = parse_zone_content(content, "example.com");
        assert!(
            result.is_err(),
            "MX priority > u16::MAX should be rejected at parse time"
        );
        let err = result.unwrap_err();
        let err_str = format!("{}", err);
        assert!(
            err_str.contains("exceeds u16::MAX"),
            "Error should mention u16::MAX: {}",
            err_str
        );
    }

    #[test]
    fn test_mx_priority_at_u16_max_accepted() {
        let content = r#"$TTL 3600
$ORIGIN example.com.
@       IN      SOA     ns1.example.com. admin.example.com. 2024030901 3600 600 604800 86400
@       IN      MX      65535 mail.example.com.
        "#;

        let result = parse_zone_content(content, "example.com");
        assert!(result.is_ok(), "MX priority at u16::MAX should be accepted");
    }

    #[test]
    fn test_soa_invalid_serial_rejected() {
        let content = r#"$TTL 3600
$ORIGIN example.com.
@       IN      SOA     ns1.example.com. admin.example.com. not-a-number 3600 600 604800 86400
        "#;

        let result = parse_zone_content(content, "example.com");
        assert!(
            result.is_err(),
            "SOA with non-numeric serial should be rejected"
        );
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("SOA serial"),
            "Error should mention SOA serial: {}",
            err_str
        );
    }

    #[test]
    fn test_soa_invalid_refresh_rejected() {
        let content = r#"$TTL 3600
$ORIGIN example.com.
@       IN      SOA     ns1.example.com. admin.example.com. 2024030901 not-a-number 600 604800 86400
        "#;

        let result = parse_zone_content(content, "example.com");
        assert!(
            result.is_err(),
            "SOA with non-numeric refresh should be rejected"
        );
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("SOA refresh"),
            "Error should mention SOA refresh: {}",
            err_str
        );
    }

    #[test]
    fn test_soa_too_few_fields_rejected() {
        let content = r#"$TTL 3600
$ORIGIN example.com.
@       IN      SOA     ns1.example.com. admin.example.com. 2024030901
        "#;

        let result = parse_zone_content(content, "example.com");
        assert!(
            result.is_err(),
            "SOA with too few fields should be rejected"
        );
    }

    #[test]
    fn test_soa_numeric_field_validation_covers_all_fields() {
        // Test each numeric field of SOA
        for (idx, field_name) in ["serial", "refresh", "retry", "expire", "minimum"]
            .iter()
            .enumerate()
        {
            let mut fields = vec![
                "ns1.example.com",
                "admin.example.com",
                "2024030901",
                "3600",
                "600",
                "604800",
                "86400",
            ];
            fields[2 + idx] = "not-a-number";
            let soa_line = format!("@       IN      SOA     {}", fields.join(" "));
            let content = format!("$TTL 3600\n$ORIGIN example.com.\n{}\n", soa_line);

            let result = parse_zone_content(&content, "example.com");
            assert!(
                result.is_err(),
                "SOA with invalid {} should be rejected",
                field_name
            );
        }
    }
}
