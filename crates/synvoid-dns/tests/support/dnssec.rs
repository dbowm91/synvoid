//! DNSSEC verification helpers for integration tests.
//!
//! These helpers **verify** a response the way a validating resolver does;
//! they never inspect internal record state or assert on shape:
//!
//! 1. the response is decoded with `hickory-proto`, so the owner names, the
//!    RDATA and the RRSIG fields are whatever actually reached the wire;
//! 2. the RFC 4034 §3.1.2 signed data is reconstructed by hickory
//!    (`TBS::from_input`), which derives the owner name from the RRset's
//!    fully-qualified name and the RRSIG `Labels` field (including the
//!    wildcard rule of RFC 4035 §5.3.2);
//! 3. the signature is checked with hickory's `dnssec-ring` verifier against
//!    the public part of a DNSKEY.
//!
//! No private key material is needed, produced, or read: a [`DnskeyParts`] is
//! built either from the served DNSKEY RRset or from a key handle's public
//! `dnskey_rdata()`.
//!
//! An error string is returned, never asserted: the caller decides which
//! property it is testing, and a failure message names the RRset and the
//! reason.
#![allow(dead_code)] // Not every suite uses every helper (same as `support::zone`).

use std::str::FromStr;

use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
use hickory_proto::dnssec::{Algorithm, PublicKey, PublicKeyBuf, Verifier, TBS};
use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use synvoid_dns::dnssec::{calculate_key_tag, ZoneSigningKey};

/// Response section a record was served in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Answer,
    Authority,
}

impl Section {
    fn records<'m>(&self, message: &'m Message) -> &'m [Record] {
        match self {
            Self::Answer => &message.answers,
            Self::Authority => &message.authorities,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Answer => "answer",
            Self::Authority => "authority",
        }
    }
}

/// The public DNSKEY RDATA needed to verify a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnskeyParts {
    pub flags: u16,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl DnskeyParts {
    /// Public parts of a key handle. Only public metadata is touched —
    /// `dnskey_rdata` is the same bytes the server publishes.
    pub fn from_key(key: &ZoneSigningKey) -> Self {
        Self::from_dnskey_rdata(&key.dnskey_rdata())
            .expect("a key handle always yields well-formed DNSKEY RDATA")
    }

    /// Parse DNSKEY RDATA: flags(2) + protocol(1) + algorithm(1) + key.
    pub fn from_dnskey_rdata(rdata: &[u8]) -> Result<Self, String> {
        if rdata.len() < 5 {
            return Err(format!(
                "DNSKEY RDATA of {} bytes is too short",
                rdata.len()
            ));
        }
        let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
        if rdata[2] != 3 {
            return Err(format!("DNSKEY protocol is {}, not 3", rdata[2]));
        }
        Ok(Self {
            flags,
            algorithm: rdata[3],
            public_key: rdata[4..].to_vec(),
        })
    }

    /// RFC 4034 Appendix B key tag, computed over the public DNSKEY RDATA.
    pub fn key_tag(&self) -> u16 {
        calculate_key_tag(self.flags, 3, self.algorithm, &self.public_key)
    }

    /// DNSKEY flags field.
    pub fn is_secure_entry_point(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    fn to_dnskey(&self) -> Result<DNSKEY, String> {
        let algorithm = Algorithm::from_u8(self.algorithm);
        if matches!(algorithm, Algorithm::Unknown(_)) {
            return Err(format!(
                "DNSKEY algorithm {} is not supported by the verifier",
                self.algorithm
            ));
        }
        Ok(DNSKEY::with_flags(
            self.flags,
            PublicKeyBuf::new(self.public_key.clone(), algorithm),
        ))
    }
}

/// Decode a response exactly as a client does.
pub fn decode_response(resp: &[u8]) -> Message {
    Message::from_vec(resp).unwrap_or_else(|e| panic!("response must parse as a DNS message: {e}"))
}

/// The DNSKEY RRset of a DNSKEY answer, as public parts.
pub fn served_dnskeys(resp: &[u8]) -> Vec<DnskeyParts> {
    decode_response(resp)
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => Some(DnskeyParts {
                flags: dnskey.flags(),
                algorithm: dnskey.public_key().algorithm().into(),
                public_key: dnskey.public_key().public_bytes().to_vec(),
            }),
            _ => None,
        })
        .collect()
}

/// Verify every RRset in the answer section against `dnskey`.
pub fn verify_answer(resp: &[u8], dnskey: &DnskeyParts) -> Result<(), String> {
    verify_section(resp, Section::Answer, dnskey)
}

/// Verify every RRset in the authority section against `dnskey`.
pub fn verify_authority(resp: &[u8], dnskey: &DnskeyParts) -> Result<(), String> {
    verify_section(resp, Section::Authority, dnskey)
}

/// Verify every RRset in `section` — each one must have an RRSIG that verifies.
pub fn verify_section(resp: &[u8], section: Section, dnskey: &DnskeyParts) -> Result<(), String> {
    let message = decode_response(resp);
    let records = section.records(&message);

    let mut rrset_count = 0;
    let mut seen: Vec<(Name, RecordType)> = Vec::new();
    for record in records {
        if record.record_type() == RecordType::RRSIG {
            continue;
        }
        let key = (record.name.clone(), record.record_type());
        if seen.contains(&key) {
            continue;
        }
        rrset_count += 1;
        verify_section_rrset(records, &key.0, key.1, dnskey)
            .map_err(|e| format!("{} section: {e}", section.label()))?;
        seen.push(key);
    }

    if rrset_count == 0 {
        return Err(format!(
            "{} section contains no RRset to verify",
            section.label()
        ));
    }
    Ok(())
}

/// Verify one named RRset in `section` against `dnskey`.
pub fn verify_rrset(
    resp: &[u8],
    section: Section,
    owner: &str,
    record_type: RecordType,
    dnskey: &DnskeyParts,
) -> Result<(), String> {
    let message = decode_response(resp);
    let owner = absolute_name(owner)?;
    verify_section_rrset(section.records(&message), &owner, record_type, dnskey)
        .map_err(|e| format!("{} section: {e}", section.label()))
}

/// The RRSIG covering `(owner, record_type)` in `section`, for field
/// assertions (`Labels`, `key_tag`, ...) that intentionally do not verify.
pub fn rrsig(
    resp: &[u8],
    section: Section,
    owner: &str,
    record_type: RecordType,
) -> Result<RRSIG, String> {
    let message = decode_response(resp);
    let owner = absolute_name(owner)?;
    find_rrsig(section.records(&message), &owner, record_type).cloned()
}

/// Verify a signature over caller-supplied RFC 4034 §3.1.2 signed data.
///
/// Used where a test builds the signed data itself (for example to exercise
/// the RRSIG formatter) but still wants the verdict of a real verifier rather
/// than a shape comparison.
pub fn verify_signed_data(
    signed_data: &[u8],
    signature: &[u8],
    dnskey: &DnskeyParts,
) -> Result<(), String> {
    dnskey
        .to_dnskey()?
        .verify(signed_data, signature)
        .map_err(|e| format!("signature does not verify: {e}"))
}

/// Prove that the **old** signing input does not verify.
///
/// The pre-fix signer signed the origin-relative storage name (`www`, or the
/// literal `@` for the apex) and derived `Labels` from that name. This
/// reconstructs exactly that signed data — same served RDATA, same RRSIG
/// fields, but the owner name is `relative_owner` and its label count — and
/// verifies the served signature against it.
///
/// * `Ok(())` — the served signature does **not** authenticate the relative
///   name, which is the property this campaign establishes.
/// * `Err(..)` — the signature *does* verify the old input (the signer
///   regressed to the storage key), or the old input could not be built.
pub fn relative_owner_signature_is_rejected(
    resp: &[u8],
    section: Section,
    owner: &str,
    record_type: RecordType,
    dnskey: &DnskeyParts,
    relative_owner: &str,
) -> Result<(), String> {
    let message = decode_response(resp);
    let served_owner = absolute_name(owner)?;
    let records = section.records(&message);

    let rrset: Vec<&Record> = records
        .iter()
        .filter(|r| r.name == served_owner && r.record_type() == record_type)
        .collect();
    if rrset.is_empty() {
        return Err(format!(
            "no {record_type} RRset for {served_owner} in the {} section",
            section.label()
        ));
    }
    let served_rrsig = find_rrsig(records, &served_owner, record_type)?;

    // The bytes the old signer covered: the relative storage name, and the
    // label count it derived from that name.
    let relative = absolute_name(relative_owner)?;
    let old_input = hickory_proto::dnssec::rdata::SigInput {
        num_labels: relative.num_labels(),
        ..served_rrsig.input().clone()
    };
    let old_rrset: Vec<Record> = rrset
        .iter()
        .map(|record| {
            Record::from_rdata(
                relative.clone(),
                served_rrsig.input().original_ttl,
                record.data.clone(),
            )
        })
        .collect();

    let tbs = TBS::from_input(&relative, DNSClass::IN, &old_input, old_rrset.iter())
        .map_err(|e| format!("could not reconstruct the old signed data: {e}"))?;

    match dnskey.to_dnskey()?.verify(tbs.as_ref(), served_rrsig.sig()) {
        Ok(()) => Err(format!(
            "the signature for {served_owner} ALSO verifies when the owner is the \
             relative storage name '{relative_owner}' — the signer is not covering \
             the canonical FQDN"
        )),
        Err(_) => Ok(()),
    }
}

/// Verify a wildcard-expanded answer (RFC 4035 §3.1.3.3 / §5.3.2).
///
/// The RRset is served at `qname`, but its RRSIG keeps the wildcard owner.
/// A validator rebuilds the signed data under the wildcard name (derived from
/// the RRSIG `Labels` field), so the RRset is renamed to `wildcard` here before
/// the TBS is constructed.
pub fn verify_wildcard_rrset(
    resp: &[u8],
    qname: &str,
    wildcard: &str,
    record_type: RecordType,
    dnskey: &DnskeyParts,
) -> Result<(), String> {
    let message = decode_response(resp);
    let qname = absolute_name(qname)?;
    let wildcard = absolute_name(wildcard)?;

    let rrsig = find_rrsig(&message.answers, &wildcard, record_type)?;
    let input = rrsig.input();

    let rrset: Vec<Record> = message
        .answers
        .iter()
        .filter(|record| record.name == qname && record.record_type() == record_type)
        .map(|record| {
            let mut renamed = record.clone();
            renamed.name = wildcard.clone();
            renamed
        })
        .collect();
    if rrset.is_empty() {
        return Err(format!(
            "no {record_type} RRset for the synthesized owner {qname}"
        ));
    }
    // RFC 4034 §3.1.5: the Labels field is the label count of the original
    // owner *without* the wildcard label (and without the root).
    let wildcard_text = wildcard.to_string();
    let expected_labels = wildcard_text
        .trim_end_matches('.')
        .split('.')
        .filter(|label| !label.is_empty() && *label != "*")
        .count();
    if usize::from(input.num_labels) != expected_labels {
        return Err(format!(
            "wildcard RRSIG Labels {} does not describe {wildcard} as a wildcard",
            input.num_labels
        ));
    }

    if input.algorithm != Algorithm::from_u8(dnskey.algorithm) {
        return Err(format!(
            "{wildcard} {record_type}: RRSIG algorithm {} does not match the DNSKEY algorithm {}",
            u8::from(input.algorithm),
            dnskey.algorithm
        ));
    }
    let expected_tag = dnskey.key_tag();
    if input.key_tag != expected_tag {
        return Err(format!(
            "{wildcard} {record_type}: RRSIG key tag {} does not match the DNSKEY key tag {expected_tag}",
            input.key_tag
        ));
    }

    let tbs = TBS::from_input(&wildcard, DNSClass::IN, input, rrset.iter())
        .map_err(|e| format!("{wildcard} {record_type}: cannot reconstruct signed data: {e}"))?;

    dnskey
        .to_dnskey()?
        .verify(tbs.as_ref(), rrsig.sig())
        .map_err(|e| format!("{wildcard} {record_type}: wildcard RRSIG does not verify: {e}"))
}

fn verify_section_rrset(
    records: &[Record],
    owner: &Name,
    record_type: RecordType,
    dnskey: &DnskeyParts,
) -> Result<(), String> {
    let rrset: Vec<&Record> = records
        .iter()
        .filter(|r| &r.name == owner && r.record_type() == record_type)
        .collect();
    if rrset.is_empty() {
        return Err(format!("no {record_type} RRset for {owner}"));
    }

    let rrsig = find_rrsig(records, owner, record_type)?;
    let input = rrsig.input();

    if input.algorithm != Algorithm::from_u8(dnskey.algorithm) {
        return Err(format!(
            "{owner} {record_type}: RRSIG algorithm {} does not match the DNSKEY algorithm {}",
            u8::from(input.algorithm),
            dnskey.algorithm
        ));
    }
    let expected_tag = dnskey.key_tag();
    if input.key_tag != expected_tag {
        return Err(format!(
            "{owner} {record_type}: RRSIG key tag {} does not match the DNSKEY key tag {expected_tag}",
            input.key_tag
        ));
    }

    let tbs = TBS::from_input(owner, DNSClass::IN, input, rrset.into_iter())
        .map_err(|e| format!("{owner} {record_type}: cannot reconstruct signed data: {e}"))?;

    dnskey
        .to_dnskey()?
        .verify(tbs.as_ref(), rrsig.sig())
        .map_err(|e| format!("{owner} {record_type}: RRSIG does not verify: {e}"))
}

fn find_rrsig<'a>(
    records: &'a [Record],
    owner: &Name,
    record_type: RecordType,
) -> Result<&'a RRSIG, String> {
    records
        .iter()
        .filter(|record| &record.name == owner && record.record_type() == RecordType::RRSIG)
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig))
                if rrsig.input().type_covered == record_type =>
            {
                Some(rrsig)
            }
            _ => None,
        })
        .ok_or_else(|| format!("no RRSIG covering {record_type} for {owner}"))
}

fn absolute_name(name: &str) -> Result<Name, String> {
    let name = name.trim();
    let absolute = if name.is_empty() || name == "." {
        ".".to_string()
    } else if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    Name::from_str(&absolute).map_err(|e| format!("invalid name '{name}': {e}"))
}
