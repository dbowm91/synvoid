//! Post-Quantum Cryptography abstraction layer
//!
//! Final FIPS 203 ML-KEM-768 via RustCrypto `ml-kem` (Phase 44).
//!
//! ## Protocol compatibility (Workstream A)
//!
//! The WASM PoW consumer exchanges only ephemeral challenge state:
//!
//! - encapsulation (public) key: 1184 bytes, base64 `URL_SAFE_NO_PAD` in
//!   `KeyExchangeRequest.client_ml_kem_pubkey`, sent to `/mesh/key-request`;
//! - ciphertext: 1088 bytes, base64 in `KeyExchangeResponse.server_ml_kem_ciphertext`,
//!   returned by the server;
//! - shared secret: 32 bytes, never transmitted — both sides derive it locally
//!   and combine it with the X25519 secret via `combine_wasm_secrets`;
//! - decapsulation (secret) key: 64-byte seed, **client-local only**, never sent
//!   over the wire and never persisted.
//!
//! Sessions are single-use: a fresh keypair is generated per `init_key_exchange`
//! call, used once, and dropped. No key material is written to disk, localStorage,
//! or the DHT, and no upgrade compatibility is required — an in-flight session
//! from an older release fails closed to X25519-only (the existing fallback in
//! `lib.rs`) rather than producing a mismatched hybrid secret.
//!
//! ## Backend provenance (Workstream D)
//!
//! Previous backend `pqc_kyber_edit 0.7.2` was a renamed fork of draft Kyber.
//! Despite matching wire sizes (1184/2400/1088), draft Kyber is NOT
//! byte-compatible with final FIPS 203 ML-KEM: cross-implementation tests
//! (draft encap → final decap and final encap → draft decap) produce mismatched
//! shared secrets via implicit rejection. The server already speaks final ML-KEM
//! through `aws-lc-rs` (`pqc` crate), so the old client was silently falling back
//! to X25519-only. This module now uses maintained final ML-KEM (`ml-kem` 0.3,
//! RustCrypto), verified bidirectionally interoperable with `aws-lc-rs`
//! ML_KEM_768 (see spike evidence in Phase 44 handoff).
//!
//! ## Secret handling (Workstream E)
//!
//! The WASM API must return owned bytes to JavaScript (`generate_ml_kem_keypair`
//! → `PqcKeyPair`, `ml_kem_decapsulate` → `Vec<u8>`), so JS-visible secrets
//! cannot enjoy Rust drop-zeroization: WASM linear memory is readable from JS
//! and `JsValue` copies outlive Rust owners. Exposure lifetime is kept minimal
//! (one session, no persistence) and this is documented for auditors.
//!
//! Inside Rust:
//!
//! - decapsulation keys are `ml_kem::DecapsulationKey` (zeroizes on drop via the
//!   `zeroize` feature);
//! - the 64-byte seed buffer is `Zeroizing<[u8; 64]>` so stack copies are wiped;
//! - errors report only expected/got sizes, never key material;
//! - `PqcKeyPair`/`PqcEncapsulationResult` intentionally do NOT implement `Debug`
//!   so secrets cannot leak through `{:?}` logging.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// Trait imports for `ml-kem` operations.
use ml_kem::{Decapsulate, Encapsulate, KeyExport};

/// Final ML-KEM-768 wire sizes (FIPS 203).
pub const PUBLIC_KEY_SIZE: usize = 1184;
/// 64-byte seed (`d || z`), the preferred `ml-kem` private-key encoding.
/// Changed from 2400-byte expanded draft-Kyber secrets in Phase 44; the secret
/// never crosses the wire so no server change was needed.
pub const SECRET_KEY_SIZE: usize = 64;
pub const CIPHERTEXT_SIZE: usize = 1088;
pub const SHARED_SECRET_SIZE: usize = 32;

/// Backend identifier for audits and guards.
pub const BACKEND: &str = "ml-kem/0.3 (FIPS 203 final, RustCrypto)";

// NOTE: no `Debug` derive — secrets must never appear in `{:?}` output.
#[derive(Serialize, Deserialize)]
pub struct PqcKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

// NOTE: no `Debug` derive — see above.
#[derive(Serialize, Deserialize)]
pub struct PqcEncapsulationResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Infallible OS RNG adapter over `getrandom 0.2` (with `js` feature for wasm).
///
/// `ml-kem`/`rand_core 0.10` requires `CryptoRng` (`Error = Infallible`);
/// entropy failures fail loudly via `expect`, matching the existing
/// fail-closed RNG policy in `lib.rs` (`generate_x25519_key_pair`,
/// `generate_nonce`).
struct OsAdapter;

impl rand_core::TryRng for OsAdapter {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).expect("getrandom failed: entropy source unavailable");
        Ok(u32::from_ne_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).expect("getrandom failed: entropy source unavailable");
        Ok(u64::from_ne_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::getrandom(dst).expect("getrandom failed: entropy source unavailable");
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OsAdapter {}

/// Deterministic keypair from an explicit 64-byte seed (`d || z`).
///
/// Test seam for FIPS 203 known-answer vectors; production uses [`generate_keypair`].
pub fn generate_keypair_from_seed(seed: &[u8]) -> Result<PqcKeyPair, String> {
    if seed.len() != SECRET_KEY_SIZE {
        return Err(format!(
            "Invalid seed size: expected {}, got {}",
            SECRET_KEY_SIZE,
            seed.len()
        ));
    }
    let seed_arr: ml_kem::Seed = seed
        .try_into()
        .map_err(|_| "Invalid seed encoding".to_string())?;
    let dk = ml_kem::DecapsulationKey768::from_seed(seed_arr);
    let ek_bytes = dk.encapsulation_key().to_bytes();
    debug_assert_eq!(ek_bytes.len(), PUBLIC_KEY_SIZE);
    Ok(PqcKeyPair {
        public_key: ek_bytes.as_slice().to_vec(),
        secret_key: seed.to_vec(),
    })
}

pub fn generate_keypair() -> Result<PqcKeyPair, String> {
    // Zeroized on drop; only the returned `Vec` copies outlive this scope,
    // and those must cross the JS boundary (see module docs).
    let mut seed = Zeroizing::new([0u8; SECRET_KEY_SIZE]);
    getrandom::getrandom(&mut *seed)
        .map_err(|e| format!("Key generation failed: entropy error: {}", e))?;
    generate_keypair_from_seed(seed.as_slice())
}

pub fn encapsulate(public_key: &[u8]) -> Result<PqcEncapsulationResult, String> {
    if public_key.len() != PUBLIC_KEY_SIZE {
        return Err(format!(
            "Invalid public key size: expected {}, got {}",
            PUBLIC_KEY_SIZE,
            public_key.len()
        ));
    }

    let ek_arr: ml_kem::Key<ml_kem::EncapsulationKey768> = public_key.try_into().map_err(|_| {
        format!(
            "Invalid public key size: expected {}, got {}",
            PUBLIC_KEY_SIZE,
            public_key.len()
        )
    })?;
    let ek = ml_kem::EncapsulationKey768::new(&ek_arr)
        .map_err(|_| "Encapsulation failed: invalid encapsulation key".to_string())?;

    let (ct, ss) = ek.encapsulate_with_rng(&mut OsAdapter);
    debug_assert_eq!(ct.len(), CIPHERTEXT_SIZE);
    debug_assert_eq!(ss.len(), SHARED_SECRET_SIZE);

    Ok(PqcEncapsulationResult {
        ciphertext: ct.as_slice().to_vec(),
        shared_secret: ss.as_slice().to_vec(),
    })
}

pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() != CIPHERTEXT_SIZE {
        return Err(format!(
            "Invalid ciphertext size: expected {}, got {}",
            CIPHERTEXT_SIZE,
            ciphertext.len()
        ));
    }
    if secret_key.len() != SECRET_KEY_SIZE {
        return Err(format!(
            "Invalid secret key size: expected {}, got {}",
            SECRET_KEY_SIZE,
            secret_key.len()
        ));
    }

    let seed_arr: ml_kem::Seed = secret_key.try_into().map_err(|_| {
        format!(
            "Invalid secret key size: expected {}, got {}",
            SECRET_KEY_SIZE,
            secret_key.len()
        )
    })?;
    let dk = ml_kem::DecapsulationKey768::from_seed(seed_arr);
    let ct_arr: ml_kem::Ciphertext<ml_kem::MlKem768> = ciphertext.try_into().map_err(|_| {
        format!(
            "Invalid ciphertext size: expected {}, got {}",
            CIPHERTEXT_SIZE,
            ciphertext.len()
        )
    })?;

    // Infallible by FIPS 203 design: tampered ciphertexts yield an unrelated
    // implicit-rejection secret rather than an error (tested below).
    let ss = dk.decapsulate(&ct_arr);
    debug_assert_eq!(ss.len(), SHARED_SECRET_SIZE);
    Ok(ss.as_slice().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST FIPS 203 ML-KEM-768 key-generation vector (key-gen.json tcId 26).
    /// Seed = d || z; expected encapsulation key is 1184 bytes.
    const KAT_D_HEX: &str = "E34A701C4C87582F42264EE422D3C684D97611F2523EFE0C998AF05056D693DC";
    const KAT_Z_HEX: &str = "A85768F3486BD32A01BF9A8F21EA938E648EAE4E5448C34C3EB88820B159EEDD";
    // Full 1184-byte expected ek (2368 hex chars) from the same vector.
    const KAT_EK_HEX: &str = concat!(
        "6D14A071F7CC452558D5E71A7B087062ECB1386844588246126402B1FA163773",
        "3CD5F60CC84BCB646A7892614D7C51B1C7F1A2799132F13427DC482158DA2544",
        "70A59E00A4E49686FDC077559367270C2153F11007592C9C4310CF8A12C6A871",
        "3BD6BB51F3124F989BA0D54073CC242E0968780B875A869EFB851586B9A868A3",
        "84B9E6821B201B932C455369A739EC22569C977C212B381871813656AF5B567E",
        "F893B584624C863A259000F17B254B98B185097C50EBB68B244342E05D4DE520",
        "125B8E1033B1436093ACE7CE8E71B458D525673363045A3B3EEA9455428A3987",
        "05A42327ADB3774B7057F42B017EC0739A983F19E8214D09195FA24D2D571DB7",
        "3C19A6F8460E50830D415F627B88E94A7B153791A0C0C7E9484C74D53C714889",
        "F0E321B6660A532A5BC0E557FBCA35E29BC611200ED3C633077A4D873C5CC670",
        "06B753BF6D6B7AF6CA402AB618236C0AFFBC801F8222FBC36CE0984E2B18C944",
        "BBCBEF03B1E1361C1F44B0D734AFB1566CFF8744DA8B9943D6B45A3C09030702",
        "CA201FFE20CB7EC5B0D4149EE2C28E8B23374F471B57150D0EC9336261A2D5CB",
        "84A3ACACC4289473A4C0ABC617C9ABC178734434C82E1685588A5C2EA2678F6B",
        "3C2228733130C466E5B86EF491153E48662247B875D201020B566B81B64D839A",
        "B4633BAA8ACE202BAAB4496297F9807ADBBB1E332C6F8022B2A18CFDD4A82530",
        "B6D3F007C3353898D966CC2C21CB4244BD00443F209870ACC42BC33068C724EC",
        "17223619C1093CCA6AEB29500664D1225036B4B81091906969481F1C723C140B",
        "9D6C168F5B64BEA69C5FD6385DF7364B8723BCC85E038C7E464A900D68A21278",
        "18994217AEC8BDB39A970A9963DE93688E2AC82ABCC22FB9277BA22009E87838",
        "1A38163901C7D4C85019538D35CAAE9C41AF8C929EE20BB08CA619E72C2F2262",
        "C1C9938572551AC02DC9268FBCC35D79011C3C090AD40A4F111C9BE55C427EB7",
        "96C1932D8673579AF1B4C638B0944489012A2559A3B02481B01AC30BA8960F80",
        "C0C2B3947D36A12C080498BEE448716C973416C8242804A3DA099EE137B0BA90",
        "FE4A5C6A89200276A0CFB643EC2C56A2D708D7B4373E44C1502A763A600586E6",
        "CDA6273897D44448287DC2E602DC39200BF6166236559FD12A60892AEB153DD6",
        "51BB469910B4B34669F91DA8654D1EB72EB6E02800B3B0A7D0A48C836854D3A8",
        "3E65569CB7230BB44F3F143A6DEC5F2C39AB90F274F2088BD3D6A6FCA0070273",
        "BEDC84777FB52E3C558B0AE06183D5A48D452F68E15207F861627ACA14279630",
        "F82EC3A0CA078633B600AFA79743A600215BE5637458CE2CE8AFF5A08EB5017B",
        "2C766577479F8DC6BF9F5CC75089932161B96CEA406620AEDB630407F7687EBB",
        "B4814C7981637A48A90DE68031E062A7AF7612B4F5C7A6DA86BD136529E64295",
        "A5613EA73BD3D4448CB81F243135C0A660BEB9C17E651DEF469A7D90A15D3481",
        "090BCBF227012328941FA46F39C5006AD93D458AA6ADD655862B418C3094F551",
        "460DF2153A5810A7DA74F0614C2588BE49DC6F5E88154642BD1D376256332643",
        "3507156A57C57694BDD26E7A246FEB723AED67B04887C8E476B48CAB59E5362F",
        "26A9EF50C2BC80BA146226216FE62968A60D04E8C170D741C7A2B0E1ABDAC968",
    );

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).expect("hex") as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).expect("hex") as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    #[test]
    fn test_wire_sizes_match_server_backend() {
        // Server speaks final ML-KEM-768 via aws-lc-rs (`pqc` crate):
        // 1184-byte ek / 1088-byte ct / 32-byte ss. Client must agree.
        assert_eq!(PUBLIC_KEY_SIZE, 1184);
        assert_eq!(CIPHERTEXT_SIZE, 1088);
        assert_eq!(SHARED_SECRET_SIZE, 32);
        // Client secret is the 64-byte seed form (never transmitted).
        assert_eq!(SECRET_KEY_SIZE, 64);
    }

    #[test]
    fn test_fips203_mlkem768_keygen_kat() {
        let mut seed_hex = String::with_capacity(128);
        seed_hex.push_str(KAT_D_HEX);
        seed_hex.push_str(KAT_Z_HEX);
        let seed = hex_to_bytes(&seed_hex);
        assert_eq!(seed.len(), SECRET_KEY_SIZE);

        let kp = generate_keypair_from_seed(&seed).expect("KAT keygen failed");
        assert_eq!(kp.public_key.len(), PUBLIC_KEY_SIZE);
        assert_eq!(kp.secret_key.len(), SECRET_KEY_SIZE);

        let expected_ek = hex_to_bytes(KAT_EK_HEX);
        assert_eq!(expected_ek.len(), PUBLIC_KEY_SIZE);
        assert_eq!(
            kp.public_key, expected_ek,
            "seed-derived encapsulation key must match NIST FIPS 203 vector"
        );
    }

    #[test]
    fn test_seed_determinism() {
        let seed = vec![0x42u8; SECRET_KEY_SIZE];
        let kp1 = generate_keypair_from_seed(&seed).expect("keygen 1");
        let kp2 = generate_keypair_from_seed(&seed).expect("keygen 2");
        assert_eq!(kp1.public_key, kp2.public_key);
        assert_eq!(kp1.secret_key, kp2.secret_key);
    }

    #[test]
    fn test_round_trip() {
        let kp = generate_keypair().expect("keygen failed");
        assert_eq!(kp.public_key.len(), PUBLIC_KEY_SIZE);
        assert_eq!(kp.secret_key.len(), SECRET_KEY_SIZE);

        let enc = encapsulate(&kp.public_key).expect("encapsulate failed");
        assert_eq!(enc.ciphertext.len(), CIPHERTEXT_SIZE);
        assert_eq!(enc.shared_secret.len(), SHARED_SECRET_SIZE);

        let dec = decapsulate(&enc.ciphertext, &kp.secret_key).expect("decapsulate failed");
        assert_eq!(dec, enc.shared_secret);
    }

    #[test]
    fn test_modified_ciphertext_implicit_rejection() {
        // FIPS 203 §6: decapsulation never fails on well-formed input; tampered
        // ciphertexts yield an unrelated implicit-rejection secret.
        let kp = generate_keypair().expect("keygen failed");
        let enc = encapsulate(&kp.public_key).expect("encapsulate failed");

        let mut tampered = enc.ciphertext.clone();
        tampered[0] ^= 0xFF;
        assert_ne!(tampered, enc.ciphertext);

        let dec = decapsulate(&tampered, &kp.secret_key).expect("decap must not error");
        assert_eq!(dec.len(), SHARED_SECRET_SIZE);
        assert_ne!(
            dec, enc.shared_secret,
            "tampered ciphertext must not reproduce the original secret"
        );
    }

    #[test]
    fn test_wrong_size_rejection_at_boundary() {
        assert!(encapsulate(&[0u8; 100]).is_err());
        assert!(encapsulate(&[0u8; PUBLIC_KEY_SIZE + 1]).is_err());
        assert!(decapsulate(&[0u8; 100], &[0u8; SECRET_KEY_SIZE]).is_err());
        assert!(decapsulate(&[0u8; CIPHERTEXT_SIZE], &[0u8; 100]).is_err());
        assert!(generate_keypair_from_seed(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_errors_carry_sizes_not_secrets() {
        let pk = vec![0xABu8; 100];
        let err = match encapsulate(&pk) {
            Ok(_) => panic!("encapsulate with short key must fail"),
            Err(e) => e,
        };
        assert!(
            err.contains("1184") && err.contains("100"),
            "error must report sizes, got: {}",
            err
        );
        assert!(
            !err.contains("abab"),
            "error must never echo key material, got: {}",
            err
        );

        let ct = vec![0u8; CIPHERTEXT_SIZE];
        let sk = vec![0xCDu8; 16];
        let err = match decapsulate(&ct, &sk) {
            Ok(_) => panic!("decapsulate with short secret must fail"),
            Err(e) => e,
        };
        assert!(err.contains("64") && err.contains("16"));
        assert!(!err.contains("cdcd"));
    }

    #[test]
    fn test_backend_identifier() {
        assert!(BACKEND.contains("ml-kem"));
        assert!(BACKEND.contains("FIPS 203"));
    }
}
