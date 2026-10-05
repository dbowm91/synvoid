//! A minimal, self-contained MaxMind DB (MMDB) writer used only by the
//! `synvoid-geoip` provider-evidence tests.
//!
//! Phase 133 Workstream B requires proving what a real GeoIP provider returns
//! for a *covered* address, not just for the degenerate "no database loaded"
//! case. The repository ships no `.mmdb` fixture and the published `maxminddb`
//! crate is read-only, so the fixture is written here rather than depended on.
//!
//! Scope: the subset of the MMDB v2 spec that `synvoid-geoip` reads —
//! `record_size = 32`, `ip_version = 4`, one data record per network, and the
//! data paths `country.iso_code`, `country.names.en`, `subdivisions[0].names.en`,
//! `city.names.en`, `autonomous_system_number`, and
//! `autonomous_system_organization`. Encodings are taken from the reader
//! implementation in `maxminddb-0.27.3` (`src/decoder.rs`, `src/reader.rs`) so
//! the fixture and the consumer agree by construction.

use std::net::Ipv4Addr;

const RECORD_SIZE: u32 = 32;
/// Separator between the search tree and the data section, as resolved by
/// `Reader::pointer_base` = `search_tree_size + DATA_SECTION_SEPARATOR_SIZE`.
const DATA_SECTION_SEPARATOR_SIZE: usize = 16;
const METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";

// Type numbers as defined by the reader's decoder.
const TYPE_STRING: u8 = 2;
const TYPE_UINT16: u8 = 5;
const TYPE_UINT32: u8 = 6;
const TYPE_MAP: u8 = 7;
const TYPE_UINT64: u8 = 9;
const TYPE_ARRAY: u8 = 11;

/// One data record to be reachable from a network prefix.
pub struct Record {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
    /// Already-encoded MMDB data section bytes for this record.
    pub data: Vec<u8>,
}

impl Record {
    pub fn new(network: Ipv4Addr, prefix_len: u8, data: Vec<u8>) -> Self {
        Self {
            network,
            prefix_len,
            data,
        }
    }
}

enum Slot {
    Unset,
    Node(usize),
    Data(usize),
}

/// Serialize `records` into a valid IPv4-only MMDB image.
pub fn build(records: &[Record]) -> Vec<u8> {
    // ---- data section ----------------------------------------------------
    // Records are concatenated in declaration order, so each record's data
    // offset is known before the tree is built.
    let mut data_section = Vec::new();
    let mut offsets = Vec::with_capacity(records.len());
    for record in records {
        offsets.push(data_section.len());
        data_section.extend_from_slice(&record.data);
    }

    // ---- search tree -----------------------------------------------------
    // Sparse trie: only nodes on a path to a record exist. `Unset` records are
    // written as the `node_count` sentinel, which the reader treats as
    // "no data" and terminates the walk on.
    let mut nodes: Vec<[Slot; 2]> = vec![[Slot::Unset, Slot::Unset]];
    for (record, offset) in records.iter().zip(offsets.iter()) {
        let bits = u32::from_be_bytes(network_bits(record.network));
        let mut node = 0usize;
        for i in 0..record.prefix_len {
            let bit = ((bits >> (31 - i)) & 1) as usize;
            if matches!(nodes[node][bit], Slot::Unset) {
                nodes.push([Slot::Unset, Slot::Unset]);
                let new_index = nodes.len() - 1;
                nodes[node][bit] = Slot::Node(new_index);
            }
            node = match nodes[node][bit] {
                Slot::Node(next) => next,
                _ => unreachable!("a node slot was overwritten by data"),
            };
        }
        nodes[node] = [Slot::Data(*offset), Slot::Data(*offset)];
    }
    let node_count = nodes.len();

    let mut tree = Vec::with_capacity(node_count * 8);
    for node in &nodes {
        for slot in node {
            let value = match slot {
                // node_count is the "no data" sentinel.
                Slot::Unset => node_count as u32,
                Slot::Node(next) => *next as u32,
                // Data pointers are node_count + 16 + offset, per
                // `Reader::resolve_data_pointer`.
                Slot::Data(offset) => (node_count + DATA_SECTION_SEPARATOR_SIZE + offset) as u32,
            };
            tree.extend_from_slice(&value.to_be_bytes());
        }
    }
    debug_assert_eq!(tree.len(), node_count * (RECORD_SIZE as usize / 4));

    // ---- metadata --------------------------------------------------------
    let mut metadata = Vec::new();
    write_map(
        &mut metadata,
        &[
            ("binary_format_major_version", uint16(2)),
            ("binary_format_minor_version", uint16(0)),
            ("build_epoch", uint64(1_700_000_000)),
            ("database_type", string("SynVoid-Phase133-Test")),
            ("description", {
                let mut inner = Vec::new();
                write_map(&mut inner, &[("en", string("Phase 133 evidence fixture"))]);
                inner
            }),
            ("ip_version", uint16(4)),
            ("languages", array(&[string("en")])),
            ("node_count", uint32(node_count as u32)),
            ("record_size", uint16(RECORD_SIZE as u16)),
        ],
    );

    let mut out = Vec::new();
    out.extend_from_slice(&tree);
    out.extend_from_slice(&[0u8; DATA_SECTION_SEPARATOR_SIZE]);
    out.extend_from_slice(&data_section);
    out.extend_from_slice(METADATA_MARKER);
    out.extend_from_slice(&metadata);
    out
}

fn network_bits(ip: Ipv4Addr) -> [u8; 4] {
    ip.octets()
}

// ---- data-section encoders -------------------------------------------------

/// Write a control byte plus size, following `Decoder::size_from_ctrl_byte`.
///
/// Types 0-7 pack the size into the low 5 bits with the usual 29/30/31
/// extended forms. Extended types (>= 8) read the low 5 bits as the size
/// directly with no extended form, so their size must fit in five bits.
fn write_ctrl(out: &mut Vec<u8>, type_num: u8, size: usize) {
    if type_num < 8 {
        if size < 29 {
            out.push((type_num << 5) | size as u8);
        } else if size < 285 {
            out.push((type_num << 5) | 29);
            out.push((size - 29) as u8);
        } else if size < 65821 {
            out.push((type_num << 5) | 30);
            let v = (size - 285) as u32;
            out.extend_from_slice(&v.to_be_bytes()[2..]);
        } else {
            out.push((type_num << 5) | 31);
            let v = (size - 65821) as u32;
            out.extend_from_slice(&v.to_be_bytes()[1..]);
        }
    } else {
        out.push(size as u8);
        out.push(type_num - 7);
    }
}

pub fn string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    write_ctrl(&mut out, TYPE_STRING, bytes.len());
    out.extend_from_slice(bytes);
    out
}

pub fn uint16(value: u16) -> Vec<u8> {
    let mut out = Vec::new();
    write_ctrl(&mut out, TYPE_UINT16, bytes_for(value as u64));
    out.extend_from_slice(&integer_bytes(value as u64, bytes_for(value as u64)));
    out
}

fn uint32(value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    write_ctrl(&mut out, TYPE_UINT32, bytes_for(value as u64));
    out.extend_from_slice(&integer_bytes(value as u64, bytes_for(value as u64)));
    out
}

fn uint64(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_ctrl(&mut out, TYPE_UINT64, bytes_for(value));
    out.extend_from_slice(&integer_bytes(value, bytes_for(value)));
    out
}

fn bytes_for(mut value: u64) -> usize {
    let mut n = 0usize;
    while value > 0 {
        n += 1;
        value >>= 8;
    }
    n
}

fn integer_bytes(mut value: u64, width: usize) -> Vec<u8> {
    let mut out = vec![0u8; width];
    for slot in out.iter_mut().rev() {
        *slot = (value & 0xff) as u8;
        value >>= 8;
    }
    out
}

pub fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    write_ctrl(&mut out, TYPE_ARRAY, items.len());
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

pub fn map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    write_map(&mut out, entries);
    out
}

fn write_map(out: &mut Vec<u8>, entries: &[(&str, Vec<u8>)]) {
    write_ctrl(out, TYPE_MAP, entries.len());
    for (key, value) in entries {
        out.extend_from_slice(&string(key));
        out.extend_from_slice(value);
    }
}
