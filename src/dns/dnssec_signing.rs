// DNSSEC signing: RRSET signing, NSEC/NSEC3 record generation, RRSIG creation

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};

use super::dnssec::{Algorithm, CryptoRngAdapter, Nsec3Config, ZoneSigningKey};

pub fn sign_data(data: &[u8], key: &ZoneSigningKey) -> Result<Vec<u8>, String> {
    match key.algorithm {
        Algorithm::Ed25519 => {
            let signing_key = ed25519_dalek::SigningKey::from_bytes(
                key.private_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid Ed25519 private key length")?,
            );
            let sig = signing_key.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
        Algorithm::RSA => {
            use rsa::pkcs1v15::Pkcs1v15Sign;
            use rsa::pkcs8::DecodePrivateKey;
            use rsa::traits::SignatureScheme;

            let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&key.private_key)
                .map_err(|e| format!("Invalid RSA private key: {}", e))?;
            let hashed = Sha256::digest(data);
            let scheme = Pkcs1v15Sign::new::<Sha256>();
            scheme
                .sign(Some(&mut CryptoRngAdapter), &private_key, &hashed)
                .map_err(|e| format!("RSA signing failed: {}", e))
        }
    }
}

pub fn create_rrsig_record(
    key: &ZoneSigningKey,
    type_covered: u16,
    original_ttl: u32,
    signer_name: &str,
    signature: &[u8],
    labels_count: u8,
) -> Vec<u8> {
    let mut rrsig = Vec::new();

    rrsig.extend_from_slice(&type_covered.to_be_bytes());
    rrsig.push(key.algorithm.to_u8());
    rrsig.push(labels_count);
    rrsig.extend_from_slice(&original_ttl.to_be_bytes());

    let now = chrono::Utc::now().timestamp() as u64;
    let sig_expire = now + (7 * 86400);
    let sig_inception = now - (86400);

    rrsig.extend_from_slice(&(sig_expire as u32).to_be_bytes());
    rrsig.extend_from_slice(&(sig_inception as u32).to_be_bytes());
    rrsig.extend_from_slice(&key.key_tag.to_be_bytes());

    let signer_name_labels = signer_name.trim_end_matches('.');
    let signer_name_parts: Vec<&str> = signer_name_labels.split('.').collect();
    for part in &signer_name_parts {
        rrsig.push((*part).len() as u8);
        rrsig.extend_from_slice(part.as_bytes());
    }
    rrsig.push(0);

    rrsig.extend_from_slice(signature);

    rrsig
}

fn build_type_bitmap(type_codes: &[u16]) -> Vec<(u8, Vec<u8>)> {
    let mut window_blocks = Vec::new();
    let mut current_window: u8 = 0;
    let mut block_bits = Vec::new();

    for &rt in type_codes {
        let window = (rt / 256) as u8;
        let bit = rt % 256;

        if window != current_window && !block_bits.is_empty() {
            window_blocks.push((current_window, std::mem::take(&mut block_bits)));
            current_window = window;
        }

        let byte_index = bit / 8;
        let bit_index = bit % 8;

        while block_bits.len() <= byte_index as usize {
            block_bits.push(0);
        }
        block_bits[byte_index as usize] |= 1 << (7 - bit_index);
    }

    if !block_bits.is_empty() {
        while block_bits.last() == Some(&0) {
            block_bits.pop();
        }
        if !block_bits.is_empty() {
            window_blocks.push((current_window, block_bits));
        }
    }

    window_blocks
}

pub fn create_nsec_record(_current_name: &str, next_name: &str, type_bitmap: &[u16]) -> Vec<u8> {
    let mut nsec = Vec::new();

    let next_name_labels = next_name.trim_end_matches('.');
    let next_name_parts: Vec<&str> = next_name_labels.split('.').collect();
    for part in &next_name_parts {
        nsec.push((*part).len() as u8);
        nsec.extend_from_slice(part.as_bytes());
    }
    nsec.push(0);

    for (window, bits) in build_type_bitmap(type_bitmap) {
        nsec.push(window);
        nsec.push(bits.len() as u8);
        nsec.extend_from_slice(&bits);
    }

    nsec
}

pub fn get_nsec_type_bitmap() -> Vec<u16> {
    vec![1, 2, 5, 6, 15, 16, 28, 33, 46, 47, 50]
}

pub fn find_next_name_in_zone(zone: &super::server::Zone, current_name: &str) -> Option<String> {
    let origin = zone.origin.trim_end_matches('.').to_lowercase();
    let current_lower = current_name
        .to_lowercase()
        .trim_end_matches('.')
        .to_string();

    let mut all_names: Vec<String> = zone
        .records
        .keys()
        .filter(|(name, _)| {
            let full_name = if name.is_empty() || *name == "@" {
                origin.clone()
            } else {
                format!("{}.{}", name, origin)
            };
            !full_name.is_empty()
        })
        .map(|(name, _)| {
            if name.is_empty() || *name == "@" {
                origin.clone()
            } else {
                format!("{}.{}", name, origin)
            }
        })
        .collect();

    all_names.sort();
    all_names.dedup();

    let mut found_current = false;
    for name in &all_names {
        if name.to_lowercase() == current_lower {
            found_current = true;
        } else if found_current {
            return Some(name.clone());
        }
    }

    if !all_names.is_empty() {
        Some(all_names[0].clone())
    } else {
        None
    }
}

pub fn hash_name_nsec3(name: &str, config: &Nsec3Config) -> Vec<u8> {
    use sha1::Sha1;

    let mut name_lower = name.to_lowercase();
    if name_lower.ends_with('.') {
        name_lower.pop();
    }
    name_lower.push('.');

    // First iteration: hash(name || salt) per RFC 5155 Section 5.1
    let mut hash = name_lower.as_bytes().to_vec();
    hash.extend_from_slice(&config.salt);

    for _ in 0..config.iterations {
        match config.algorithm {
            1 => {
                let mut hasher = Sha1::new();
                hasher.update(&hash);
                hash = hasher.finalize().to_vec();
            }
            2 => {
                let mut hasher = Sha256::new();
                hasher.update(&hash);
                hash = hasher.finalize().to_vec();
            }
            _ => {
                tracing::warn!(
                    "Unsupported NSEC3 algorithm {}, falling back to SHA-1",
                    config.algorithm
                );
                let mut hasher = Sha1::new();
                hasher.update(&hash);
                hash = hasher.finalize().to_vec();
            }
        }
    }

    hash
}

pub fn create_nsec3_record(
    _owner_name: &str,
    next_name: &str,
    config: &Nsec3Config,
    type_bitmap: &[u16],
) -> Vec<u8> {
    let mut nsec3 = Vec::new();

    nsec3.push(config.algorithm);
    nsec3.push(config.flags);
    nsec3.extend_from_slice(&config.iterations.to_be_bytes());
    nsec3.push(config.salt.len() as u8);
    nsec3.extend_from_slice(&config.salt);

    let next_hash = hash_name_nsec3(next_name, config);
    nsec3.extend_from_slice(&next_hash);

    for (window, bits) in build_type_bitmap(type_bitmap) {
        nsec3.push(window);
        nsec3.push(bits.len() as u8);
        nsec3.extend_from_slice(&bits);
    }

    nsec3
}

pub fn create_nsec3param_record(config: &Nsec3Config) -> Vec<u8> {
    let mut nsec3param = Vec::new();

    nsec3param.push(config.algorithm);
    nsec3param.push(config.flags);
    nsec3param.extend_from_slice(&config.iterations.to_be_bytes());
    nsec3param.push(config.salt.len() as u8);
    nsec3param.extend_from_slice(&config.salt);

    nsec3param
}

pub fn get_nsec3_type_bitmap() -> Vec<u16> {
    vec![1, 2, 5, 6, 15, 16, 28, 33, 46, 47, 50]
}

pub fn create_nsec3_owner_name(base_name: &str, hash: &[u8]) -> String {
    let hash_b32 = base32_encode(hash);
    format!("{}.{}.{}", hash_b32.len(), hash_b32, base_name)
}

pub fn base32_encode(input: &[u8]) -> String {
    const BASE32_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut result = String::new();

    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in input {
        buffer = (buffer << 8) | (byte as u64);
        bits_in_buffer += 8;

        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            result.push(BASE32_ALPHABET[index] as char);
        }
    }

    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        result.push(BASE32_ALPHABET[index] as char);
    }

    result
}
