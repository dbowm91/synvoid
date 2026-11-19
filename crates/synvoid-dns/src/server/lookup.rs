//! The authoritative lookup state machine (phase 09 R1).
//!
//! One algorithm, used by the signed and the unsigned answer path. It reads
//! the phase-05 canonical owner index ([`ZoneDenial`]) rather than probing the
//! record map for the exact question: the index already knows every
//! authoritative owner, every empty non-terminal, and every delegation, so a
//! wildcard, a referral and a name error are different outcomes of one walk
//! instead of three unrelated blocks.
//!
//! Order of the walk (RFC 1034 §3.6.2, RFC 4592, RFC 6672 §3.2):
//!
//! 1. a zone cut at or above the qname is a **referral** — a parent never
//!    answers a child's names from its own data. At the cut itself only `NS`
//!    (the parent's delegation RRset) and `DS` (parent-side data) are answered
//!    locally;
//! 2. an exact owner answers the qtype, or follows a `CNAME` chain
//!    (loop-guarded, in-zone targets only), or is `NODATA`;
//! 3. the qname existing as an **empty non-terminal** is `NODATA`, and a
//!    wildcard is never consulted for a name that exists;
//! 4. a `DNAME` at the closest encloser synthesizes the CNAME and carries the
//!    DNAME (RFC 6672 §3.1);
//! 5. `*.<closest encloser>` answers the qname when it exists (RFC 4592),
//!    including the CNAME-at-wildcard case and wildcard NODATA;
//! 6. otherwise the name does not exist.
//!
//! The outcome is a description only — no wire encoding, no signing and no
//! denial proof selection happen here. The query path builds the response and
//! selects the phase-05 proof from the outcome (a wildcard answer needs the
//! next-closer proof, a name error needs the covering proof, and so on).

use std::collections::HashSet;

use super::{DnsZoneRecord, RecordType, Zone};
use crate::denial::display_name;

/// How many CNAME hops a single answer may follow before the chain is
/// declared a loop. RFC 1034 §3.6.2 chains are expected to be short; the cap
/// bounds the work an adversarial zone can cause per query.
const MAX_CNAME_HOPS: usize = 8;

/// The shape of an authoritative answer.
#[derive(Debug, Clone)]
pub enum LookupOutcome {
    /// The exact owner has an RRset of the requested type.
    Answer {
        /// Absolute owner name (no trailing dot).
        owner: String,
        records: Vec<DnsZoneRecord>,
    },
    /// The exact owner is a CNAME: its RRset plus any in-zone target RRsets.
    Cname { records: Vec<DnsZoneRecord> },
    /// A DNAME at an ancestor synthesized a CNAME. `answer` carries the DNAME
    /// RRset first and the synthesized CNAME second (RFC 6672 §3.1).
    Dname { answer: Vec<DnsZoneRecord> },
    /// A name below a zone cut.
    Referral {
        /// Absolute delegation name (no trailing dot).
        delegation: String,
        /// The delegation's NS RRset.
        authority: Vec<DnsZoneRecord>,
        /// In-bailiwick glue (A/AAAA) for the NS targets.
        additional: Vec<DnsZoneRecord>,
    },
    /// The owner exists but the type does not.
    NoData,
    /// The name exists only as an empty non-terminal.
    EmptyNonTerminal,
    /// `*.<closest encloser>` exists but has no RRset of the requested type.
    WildcardNoData { wildcard: String },
    /// `*.<closest encloser>` answered; `records` are synthesized at the
    /// qname and `wildcard` is the owner whose RRSIG covers them.
    WildcardAnswer {
        wildcard: String,
        records: Vec<DnsZoneRecord>,
    },
    /// The CNAME chain revisited a name.
    Loop,
    /// A DNAME substitution would overflow the legal name length
    /// (RFC 6672 §3.2 — answer YXDOMAIN).
    DnameOverflow,
    /// Neither the name nor a wildcard match exists.
    NxDomain,
}

impl Zone {
    /// The authoritative lookup. See the module documentation for the order.
    ///
    /// `qname` may be an in-zone absolute name (`www.example.com`) or the
    /// origin-relative spelling (`www`, `@`); both resolve to the same name.
    pub fn lookup(&self, qname: &str, qtype: RecordType) -> LookupOutcome {
        let origin = self.origin.trim_end_matches('.').to_ascii_lowercase();
        if origin.is_empty() {
            return LookupOutcome::NxDomain;
        }
        let qname = display_name(&origin, qname);
        if !is_within(&qname, &origin) {
            // The caller found this zone by suffix, so a foreign qname is a
            // programming error, not a zone fact. Fail closed as a name error
            // rather than answering from another zone's tree.
            return LookupOutcome::NxDomain;
        }

        let origin_labels = labels(&origin).len();
        let qname_labels = labels(&qname);
        let depth = qname_labels.len().saturating_sub(origin_labels);

        // Step 1: the nearest zone cut on the path from the qname up to the
        // apex. The apex has a SOA, so it is never a delegation.
        let cut = (0..depth).find_map(|index| {
            let candidate = qname_labels[index..].join(".");
            if self.is_delegation(&candidate) {
                Some(candidate)
            } else {
                None
            }
        });

        let at_cut = cut.as_deref() == Some(qname.as_str());
        if let Some(cut) = cut {
            // At the cut the parent is authoritative only for the delegation
            // NS RRset and for DS. Everything else — including the child's
            // names — is a referral (RFC 2181 §6.1).
            let answered_at_cut = at_cut && matches!(qtype, RecordType::NS | RecordType::DS);
            if !answered_at_cut {
                return self.referral(&cut);
            }
        }

        // Step 2: exact owner.
        if self.denial.is_owner(&qname) {
            if let Some(records) = self.rrset(&qname, qtype) {
                return LookupOutcome::Answer {
                    owner: qname,
                    records: records.to_vec(),
                };
            }
            if let Some(cname) = self.rrset(&qname, RecordType::CNAME) {
                return self.follow_cname(&qname, cname, qtype);
            }
            return LookupOutcome::NoData;
        }

        // Step 3: a name that exists as an empty non-terminal exists. A
        // wildcard never matches an existing name (RFC 4592 §2.2.2).
        if self.denial.is_empty_non_terminal(&qname) {
            return LookupOutcome::EmptyNonTerminal;
        }

        // Step 4: the closest encloser is the deepest existing ancestor. The
        // apex always exists (it owns the SOA).
        let encloser = (1..=depth)
            .map(|index| qname_labels[index..].join("."))
            .find(|candidate| self.denial.exists(candidate))
            .unwrap_or_else(|| origin.clone());

        if let Some(dname) = self.rrset(&encloser, RecordType::DNAME) {
            return self.synthesize_dname(&qname, &encloser, dname);
        }

        // Step 5: the wildcard at the closest encloser.
        let wildcard = format!("*.{encloser}");
        if self.denial.is_owner(&wildcard) {
            if let Some(records) = self.rrset(&wildcard, qtype) {
                return LookupOutcome::WildcardAnswer {
                    wildcard,
                    records: synthesize(records, &qname),
                };
            }
            if let Some(cname) = self.rrset(&wildcard, RecordType::CNAME) {
                return LookupOutcome::WildcardAnswer {
                    wildcard,
                    records: synthesize(cname, &qname),
                };
            }
            return LookupOutcome::WildcardNoData { wildcard };
        }

        // Step 6.
        LookupOutcome::NxDomain
    }

    /// An RRset at an in-zone name, keyed the way the zone stores it.
    pub(crate) fn rrset(&self, name: &str, record_type: RecordType) -> Option<&[DnsZoneRecord]> {
        let relative = self.relative_name(name)?;
        self.records
            .get(&(relative, record_type))
            .map(|records| records.as_slice())
    }

    /// A name cut off from this zone's authoritative data: NS present and no
    /// SOA (RFC 1034 §4.2, RFC 4035 §2.3).
    fn is_delegation(&self, name: &str) -> bool {
        self.rrset(name, RecordType::NS).is_some() && self.rrset(name, RecordType::SOA).is_none()
    }

    /// True when `name` is at or below one of this zone's cuts.
    fn is_below_delegation(&self, name: &str) -> bool {
        let origin = self.origin.trim_end_matches('.').to_ascii_lowercase();
        if !is_within(name, &origin) {
            return false;
        }
        let name_labels = labels(name);
        let depth = name_labels.len().saturating_sub(labels(&origin).len());
        (0..depth).any(|index| self.is_delegation(&name_labels[index..].join(".")))
    }

    /// Follow an exact-owner CNAME for `qtype`, appending in-zone target
    /// RRsets (RFC 1034 §3.6.2).
    ///
    /// A chain that revisits a name is a loop; the answer is refused rather
    /// than emitted. An out-of-zone target or a target below a zone cut ends
    /// the chain: this server cannot answer for it and must not answer from
    /// parent data.
    fn follow_cname(
        &self,
        qname: &str,
        cname: &[DnsZoneRecord],
        qtype: RecordType,
    ) -> LookupOutcome {
        let origin = self.origin.trim_end_matches('.').to_ascii_lowercase();
        let mut records = cname.to_vec();
        let mut visited: HashSet<String> = HashSet::from([qname.to_string()]);
        let mut target = cname_target(&cname[0]);

        for _ in 0..MAX_CNAME_HOPS {
            if !is_within(&target, &origin) || self.is_below_delegation(&target) {
                break;
            }
            if !visited.insert(target.clone()) {
                return LookupOutcome::Loop;
            }

            if let Some(records_at_target) = self.rrset(&target, qtype) {
                records.extend(records_at_target.iter().cloned());
                break;
            }
            match self.rrset(&target, RecordType::CNAME) {
                Some(next) => {
                    records.extend(next.iter().cloned());
                    target = cname_target(&next[0]);
                }
                None => break,
            }
        }

        LookupOutcome::Cname { records }
    }

    /// Synthesize the CNAME a DNAME at `encloser` implies for `qname`
    /// (RFC 6672 §3.1). The DNAME is always included.
    fn synthesize_dname(
        &self,
        qname: &str,
        encloser: &str,
        dname: &[DnsZoneRecord],
    ) -> LookupOutcome {
        let prefix = match qname.strip_suffix(&format!(".{encloser}")) {
            Some(prefix) if !prefix.is_empty() => prefix,
            _ => return LookupOutcome::DnameOverflow,
        };
        let dname_record = &dname[0];
        let target = dname_record.value.trim().trim_end_matches('.');
        let substituted = if target.is_empty() {
            prefix.to_string()
        } else {
            format!("{prefix}.{target}")
        };

        if crate::wire::encode_name(&substituted).is_err() {
            return LookupOutcome::DnameOverflow;
        }

        let mut answer = dname.to_vec();
        answer.push(DnsZoneRecord {
            name: qname.to_string(),
            record_type: RecordType::CNAME,
            value: substituted,
            ttl: dname_record.ttl,
            priority: None,
        });
        LookupOutcome::Dname { answer }
    }

    /// The referral for a cut: the delegation's NS RRset plus in-bailiwick
    /// glue (A/AAAA for NS targets below the cut, RFC 1034 §4.3.2).
    fn referral(&self, cut: &str) -> LookupOutcome {
        let authority: Vec<DnsZoneRecord> = self
            .rrset(cut, RecordType::NS)
            .map(|records| records.to_vec())
            .unwrap_or_default();

        let mut additional = Vec::new();
        for ns in &authority {
            let target = ns.value.trim().trim_end_matches('.').to_ascii_lowercase();
            // Only in-bailiwick targets (below this cut) need glue; an
            // out-of-bailiwick target is resolved by the client.
            if !is_strict_descendant(&target, cut) {
                continue;
            }
            for record_type in [RecordType::A, RecordType::AAAA] {
                if let Some(records) = self.rrset(&target, record_type) {
                    additional.extend(records.iter().cloned());
                }
            }
        }

        LookupOutcome::Referral {
            delegation: cut.to_string(),
            authority,
            additional,
        }
    }
}

/// Copy an RRset to a synthesized owner name (a wildcard expansion).
fn synthesize(records: &[DnsZoneRecord], owner: &str) -> Vec<DnsZoneRecord> {
    records
        .iter()
        .map(|record| {
            let mut synthesized = record.clone();
            synthesized.name = owner.to_string();
            synthesized
        })
        .collect()
}

/// The absolute target of a CNAME record, lowercase, no trailing dot.
fn cname_target(record: &DnsZoneRecord) -> String {
    record
        .value
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn labels(name: &str) -> Vec<&str> {
    name.split('.').filter(|label| !label.is_empty()).collect()
}

/// True when `name` is `origin` or a descendant of it.
fn is_within(name: &str, origin: &str) -> bool {
    name == origin
        || (name.len() > origin.len()
            && name.ends_with(origin)
            && name.as_bytes()[name.len() - origin.len() - 1] == b'.')
}

fn is_strict_descendant(name: &str, ancestor: &str) -> bool {
    name.len() > ancestor.len() + 1
        && name.ends_with(ancestor)
        && name.as_bytes()[name.len() - ancestor.len() - 1] == b'.'
}
