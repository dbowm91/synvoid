use std::collections::HashMap;

use thiserror::Error;

use crate::server::{RecordMap, RecordType, SerialPolicy, Zone};

#[derive(Debug, Clone)]
pub struct ZoneFileParser {
    /// The zone identity. `$ORIGIN` never changes this.
    zone_origin: String,
    /// Parse-scoped origin for relative owner and RDATA names. `$ORIGIN`
    /// changes this for subsequent lines only (R4).
    current_origin: String,
    default_ttl: u32,
    soa_serial: u32,
    soa_refresh: u32,
    soa_retry: u32,
    soa_expire: u32,
    soa_minimum: u32,
    soa_mname: String,
    soa_rname: String,
    soa_seen: bool,
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
        let origin = origin.trim_end_matches('.').to_string();
        Self {
            zone_origin: origin.clone(),
            current_origin: origin,
            default_ttl: 3600,
            soa_serial: 1,
            soa_refresh: 3600,
            soa_retry: 600,
            soa_expire: 604800,
            soa_minimum: 86400,
            soa_mname: String::new(),
            soa_rname: String::new(),
            soa_seen: false,
        }
    }

    pub fn parse_file(&mut self, path: &str) -> Result<Zone, ZoneParseError> {
        let content = std::fs::read_to_string(path)?;
        self.parse_content(&content)
    }

    pub fn parse_content(&mut self, content: &str) -> Result<Zone, ZoneParseError> {
        // Parse-scoped state starts fresh for every document: a previous
        // `$ORIGIN` must not leak into the next parse.
        self.current_origin = self.zone_origin.clone();
        self.soa_seen = false;

        let mut records: RecordMap = HashMap::new();
        // The last explicit owner, already resolved to an absolute name. Owner
        // inheritance after `$ORIGIN` keeps pointing at the same name.
        let mut current_name: Option<String> = None;
        let mut current_ttl = self.default_ttl;

        for raw_line in content.lines() {
            // RFC 1035 §5.1: a line that begins with whitespace inherits the
            // previous owner. Detect that *before* trimming; the old parser
            // trimmed first and turned the inherited line into a record named
            // after its type token.
            let indented = raw_line.starts_with(|c: char| c.is_ascii_whitespace());
            let line = raw_line.trim();

            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            if line.starts_with('$') {
                self.parse_directive(line)?;
                continue;
            }

            if let Some(record) =
                self.parse_record_line(line, indented, &mut current_name, &mut current_ttl)?
            {
                let key = (record.name.clone(), record.record_type);
                records
                    .entry(key)
                    .or_default()
                    .push(crate::server::DnsZoneRecord {
                        name: record.name,
                        record_type: record.record_type,
                        value: record.value,
                        ttl: record.ttl,
                        priority: record.priority,
                    });
            }
        }

        if !self.soa_seen {
            self.soa_mname = if self.soa_mname.is_empty() {
                format!("ns1.{}", self.zone_origin)
            } else {
                self.soa_mname.clone()
            };
            self.soa_rname = if self.soa_rname.is_empty() {
                format!("admin.{}", self.zone_origin)
            } else {
                self.soa_rname.clone()
            };

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

            records.insert(
                ("@".to_string(), RecordType::SOA),
                vec![crate::server::DnsZoneRecord {
                    name: "@".to_string(),
                    record_type: RecordType::SOA,
                    value: soa_value,
                    ttl: current_ttl,
                    priority: None,
                }],
            );
        }

        let mut zone = Zone::new(self.zone_origin.clone());
        // Single writer: relative keys, deduplicated RRsets, rebuilt owner
        // index, and the zone serial adopted from the SOA.
        zone.commit_records(records, SerialPolicy::AdoptSoa)
            .map_err(ZoneParseError::InvalidRecord)?;
        zone.nsec_enabled = true;
        Ok(zone)
    }

    fn parse_directive(&mut self, directive: &str) -> Result<(), ZoneParseError> {
        let parts: Vec<&str> = directive.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        match parts[0].to_uppercase().as_str() {
            "$ORIGIN" => {
                // RFC 1035 §5.1: `$ORIGIN` changes the origin used for
                // subsequent relative names. It is parse-scoped state, not a
                // change to the zone's identity.
                if let Some(raw) = parts.get(1) {
                    let raw = raw.trim();
                    let absolute = raw.ends_with('.');
                    let name = raw.trim_end_matches('.').to_lowercase();
                    self.current_origin = if absolute || name.is_empty() {
                        name
                    } else if name == "@" {
                        self.current_origin.clone()
                    } else {
                        format!("{name}.{}", self.current_origin)
                    };
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
        indented: bool,
        current_name: &mut Option<String>,
        current_ttl: &mut u32,
    ) -> Result<Option<ParsedRecord>, ZoneParseError> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(None);
        }

        let mut pos = 0;
        let owner = if indented {
            match current_name {
                Some(name) => name.clone(),
                None => {
                    return Err(ZoneParseError::InvalidRecord(
                        "line begins with whitespace but there is no previous owner".to_string(),
                    ))
                }
            }
        } else {
            let name = self.resolve_name(parts[pos])?;
            pos += 1;
            *current_name = Some(name.clone());
            name
        };

        // The class and TTL may appear in either order before the type.
        while pos < parts.len() {
            let token = parts[pos];
            if token.eq_ignore_ascii_case("IN") {
                pos += 1;
                continue;
            }
            if !token.is_empty() && token.chars().all(|c| c.is_ascii_digit()) {
                let ttl: u32 = token
                    .parse()
                    .map_err(|_| ZoneParseError::InvalidRecord(format!("Invalid TTL '{token}'")))?;
                *current_ttl = ttl;
                pos += 1;
                continue;
            }
            break;
        }

        let Some(type_token) = parts.get(pos) else {
            return Ok(None);
        };
        let record_type_str = type_token.to_uppercase();
        let record_type = match record_type_str.as_str() {
            "A" => RecordType::A,
            "AAAA" => RecordType::AAAA,
            "CNAME" => RecordType::CNAME,
            "DNAME" => RecordType::DNAME,
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
            _ => {
                // R4: an unsupported type is rejected, never silently dropped
                // and never parsed as a one-token RDATA.
                return Err(ZoneParseError::InvalidRecord(format!(
                    "unsupported record type '{record_type_str}' at '{owner}'"
                )));
            }
        };
        pos += 1;

        let rdata = &parts[pos..];
        if rdata.is_empty() {
            return Err(ZoneParseError::InvalidRecord(format!(
                "{record_type_str} record at '{owner}' has no RDATA"
            )));
        }

        let name = Zone::normalize_record_name(&self.zone_origin, &owner)
            .map_err(ZoneParseError::InvalidRecord)?;

        if record_type == RecordType::SOA {
            self.soa_seen = true;
            return self.parse_soa_record(rdata, name, *current_ttl);
        }

        let (priority, value) = if matches!(record_type, RecordType::MX | RecordType::SRV) {
            let prio: u32 = rdata[0].parse().map_err(|e: std::num::ParseIntError| {
                ZoneParseError::InvalidRecord(format!(
                    "Invalid {} priority '{}': {}",
                    record_type_str, rdata[0], e
                ))
            })?;
            if prio > u16::MAX as u32 {
                return Err(ZoneParseError::InvalidRecord(format!(
                    "{} priority {} exceeds u16::MAX (65535)",
                    record_type_str, prio
                )));
            }
            if rdata.len() < 2 {
                return Err(ZoneParseError::InvalidRecord(format!(
                    "{record_type_str} record at '{owner}' is missing its target"
                )));
            }
            (Some(prio), join_rdata(record_type, &rdata[1..]))
        } else {
            (None, join_rdata(record_type, rdata))
        };

        Ok(Some(ParsedRecord {
            name,
            record_type,
            ttl: *current_ttl,
            value,
            priority,
        }))
    }

    /// Resolve an owner token against the parse-scoped origin.
    ///
    /// A trailing dot is absolute; anything else — including a multi-label
    /// name like `a.b` — is relative to the current `$ORIGIN` (RFC 1035
    /// §5.1). The old parser treated any name with a dot as absolute, which
    /// stored `a.b` at the DNS root of the zone file instead of under it.
    fn resolve_name(&self, token: &str) -> Result<String, ZoneParseError> {
        let token = token.trim();
        if token == "@" {
            return Ok(self.current_origin.clone());
        }
        if let Some(absolute) = token.strip_suffix('.') {
            return Ok(absolute.to_lowercase());
        }
        if self.current_origin.is_empty() {
            return Ok(token.to_lowercase());
        }
        Ok(format!("{}.{}", token.to_lowercase(), self.current_origin))
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

        let mname = self.absolute_from_current(parts[0]);
        self.soa_mname = mname.clone();

        let rname = self.absolute_from_current(parts[1]);
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

    /// Treat a zone-file name as absolute unless it carries a trailing dot
    /// (RFC 1035 §5.1), resolving relatives against the current origin.
    fn absolute_from_current(&self, token: &str) -> String {
        let token = token.trim();
        if let Some(absolute) = token.strip_suffix('.') {
            return absolute.to_lowercase();
        }
        if self.current_origin.is_empty() {
            token.to_lowercase()
        } else {
            format!("{}.{}", token.to_lowercase(), self.current_origin)
        }
    }
}

/// Join every RDATA token instead of truncating to the first one.
///
/// Hex-encoded internal RDATA (`DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`,
/// `NSEC3PARAM`, `DS`) may be split across tokens, so it is concatenated;
/// presentation-format RDATA (`NAPTR`, `TXT`, `CAA`, `SVCB`, ...) keeps its
/// separating spaces so the one RDATA encoder can parse it.
fn join_rdata(record_type: RecordType, tokens: &[&str]) -> String {
    match record_type {
        RecordType::DNSKEY
        | RecordType::RRSIG
        | RecordType::NSEC
        | RecordType::NSEC3
        | RecordType::NSEC3PARAM
        | RecordType::DS => tokens.concat(),
        _ => tokens.join(" "),
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

        // R4: owners are stored in the origin-relative spelling the query path
        // looks up, and the file's SOA is the only SOA — the parser must not
        // add a second, synthesized apex SOA.
        let soa_key = ("@".to_string(), RecordType::SOA);
        assert_eq!(
            zone.records.get(&soa_key).map(|r| r.len()),
            Some(1),
            "exactly one apex SOA"
        );
        assert!(zone.records.contains_key(&("@".to_string(), RecordType::A)));
        assert!(zone
            .records
            .contains_key(&("www".to_string(), RecordType::A)));
        assert!(zone
            .records
            .contains_key(&("mail".to_string(), RecordType::A)));
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
            let mut fields = [
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
