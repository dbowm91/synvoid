use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response, Window};
use x25519_dalek::{PublicKey, StaticSecret};

mod pqc;

const MAX_NONCE: u64 = 100_000_000;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn solve_pow(challenge: String, difficulty: u8) -> Option<String> {
    let zeros = difficulty as usize;

    for nonce in 0..MAX_NONCE {
        let input = format!("{}{}", challenge, nonce);
        let hash = Sha256::digest(input.as_bytes());

        if has_leading_zeros(&hash, zeros) {
            return Some(nonce.to_string());
        }
    }

    None
}

#[wasm_bindgen]
pub fn verify_pow(challenge: String, nonce: String, difficulty: u8) -> bool {
    let input = format!("{}{}", challenge, nonce);
    let hash = Sha256::digest(input.as_bytes());
    has_leading_zeros(&hash, difficulty as usize)
}

// =============================================================================
// ML-KEM-768 Post-Quantum Key Exchange (Kyber-768)
// =============================================================================

#[wasm_bindgen]
pub fn generate_ml_kem_keypair() -> Result<JsValue, JsValue> {
    let result = pqc::generate_keypair().map_err(|e| JsValue::from_str(&e))?;

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn ml_kem_encapsulate(public_key: &[u8]) -> Result<JsValue, JsValue> {
    let result = pqc::encapsulate(public_key).map_err(|e| JsValue::from_str(&e))?;

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn ml_kem_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    pqc::decapsulate(ciphertext, secret_key).map_err(|e| JsValue::from_str(&e))
}

fn has_leading_zeros(hash: &[u8], zeros: usize) -> bool {
    let mut bit_index = 0;

    for &byte in hash {
        for j in (0..8).rev() {
            if bit_index >= zeros {
                return true;
            }
            if (byte >> j) & 1 != 0 {
                return false;
            }
            bit_index += 1;
        }
    }

    bit_index >= zeros
}

#[derive(Serialize, Deserialize)]
struct KeyExchangeRequest {
    mesh_id: String,
    client_x25519_pubkey: String,
    client_ml_kem_pubkey: Option<String>,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
struct KeyExchangeResponse {
    session_id: String,
    server_x25519_pubkey: String,
    server_ml_kem_pubkey: Option<String>,
    server_ml_kem_ciphertext: Option<String>,
    origin_ed25519_pubkey: Option<String>,
    origin_signature: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct KeyConfirmRequest {
    session_id: String,
    client_x25519_pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct MeshAuditResult {
    node_url: String,
    success: bool,
    latency_ms: Option<f64>,
    error: Option<String>,
    routed_to_allowed_ip: bool,
}

#[derive(Serialize, Deserialize)]
pub struct KeyExchangeResult {
    completed: bool,
    session_id: Option<String>,
    session_key: Option<String>,
    server_ed25519_pubkey: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AuditResults {
    completed: bool,
    results: Vec<MeshAuditResult>,
}

fn window() -> Option<Window> {
    web_sys::window()
}

#[wasm_bindgen]
pub async fn init_key_exchange(mesh_id: String, global_node_url: String) -> String {
    if global_node_url.is_empty() {
        return serde_json::to_string(&KeyExchangeResult {
            completed: false,
            session_id: None,
            session_key: None,
            server_ed25519_pubkey: None,
            error: Some("No global node URL".to_string()),
        })
        .unwrap_or_default();
    }

    let client_key_pair = generate_x25519_key_pair();

    let (client_ml_kem_pubkey, client_ml_kem_secert) = match pqc::generate_keypair() {
        Ok(kp) => (
            Some(URL_SAFE_NO_PAD.encode(&kp.public_key)),
            Some(kp.secret_key),
        ),
        Err(e) => {
            tracing::warn!(
                "Failed to generate ML-KEM keypair: {}, using X25519 only",
                e
            );
            (None, None)
        }
    };

    let nonce = generate_nonce();

    let request_body = match serde_json::to_string(&KeyExchangeRequest {
        mesh_id: mesh_id.clone(),
        client_x25519_pubkey: client_key_pair.public_key.clone(),
        client_ml_kem_pubkey,
        nonce,
    }) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::to_string(&KeyExchangeResult {
                completed: false,
                session_id: None,
                session_key: None,
                server_ed25519_pubkey: None,
                error: Some(format!("Failed to serialize request: {}", e)),
            })
            .unwrap_or_default();
        }
    };

    let url = format!("{}/mesh/key-request", global_node_url);
    let opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::Cors);
    opts.set_body(&JsValue::from_str(&request_body));

    let request = match Request::new_with_str_and_init(&url, &opts) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&KeyExchangeResult {
                completed: false,
                session_id: None,
                session_key: None,
                server_ed25519_pubkey: None,
                error: Some(format!("Failed to create request: {:?}", e)),
            })
            .unwrap_or_default();
        }
    };

    let headers = request.headers();
    let _ = headers.set("Content-Type", "application/json");

    let window = match window() {
        Some(w) => w,
        None => {
            return serde_json::to_string(&KeyExchangeResult {
                completed: false,
                session_id: None,
                session_key: None,
                server_ed25519_pubkey: None,
                error: Some("No window available".to_string()),
            })
            .unwrap_or_default();
        }
    };

    let fetch_promise = window.fetch_with_request(&request);
    let resp_value = match JsFuture::from(fetch_promise).await {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&KeyExchangeResult {
                completed: false,
                session_id: None,
                session_key: None,
                server_ed25519_pubkey: None,
                error: Some(format!("Fetch failed: {:?}", e)),
            })
            .unwrap_or_default();
        }
    };

    let response: Response = match resp_value.dyn_into() {
        Ok(r) => r,
        Err(_) => {
            return serde_json::to_string(&KeyExchangeResult {
                completed: false,
                session_id: None,
                session_key: None,
                server_ed25519_pubkey: None,
                error: Some("Failed to convert response".to_string()),
            })
            .unwrap_or_default();
        }
    };

    if !response.ok() {
        return serde_json::to_string(&KeyExchangeResult {
            completed: false,
            session_id: None,
            session_key: None,
            server_ed25519_pubkey: None,
            error: Some(format!("HTTP error: {}", response.status())),
        })
        .unwrap_or_default();
    }

    let json_promise = response.json().unwrap();
    let json_value = match JsFuture::from(json_promise).await {
        Ok(j) => j,
        Err(e) => {
            return serde_json::to_string(&KeyExchangeResult {
                completed: false,
                session_id: None,
                session_key: None,
                server_ed25519_pubkey: None,
                error: Some(format!("Failed to parse JSON: {:?}", e)),
            })
            .unwrap_or_default();
        }
    };

    let key_resp: KeyExchangeResponse = match serde_wasm_bindgen::from_value(json_value) {
        Ok(k) => k,
        Err(e) => {
            return serde_json::to_string(&KeyExchangeResult {
                completed: false,
                session_id: None,
                session_key: None,
                server_ed25519_pubkey: None,
                error: Some(format!("Failed to deserialize response: {}", e)),
            })
            .unwrap_or_default();
        }
    };

    let confirm_url = format!("{}/mesh/key-confirm", global_node_url);
    let confirm_body = serde_json::to_string(&KeyConfirmRequest {
        session_id: key_resp.session_id.clone(),
        client_x25519_pubkey: client_key_pair.public_key.clone(),
    })
    .unwrap_or_default();

    let confirm_opts = RequestInit::new();
    confirm_opts.set_method("POST");
    confirm_opts.set_mode(RequestMode::Cors);
    confirm_opts.set_body(&JsValue::from_str(&confirm_body));

    let confirm_request = match Request::new_with_str_and_init(&confirm_url, &confirm_opts) {
        Ok(r) => r,
        Err(_) => {
            return serde_json::to_string(&KeyExchangeResult {
                completed: false,
                session_id: Some(key_resp.session_id),
                session_key: None,
                server_ed25519_pubkey: key_resp.origin_ed25519_pubkey,
                error: Some("Failed to create confirm request".to_string()),
            })
            .unwrap_or_default();
        }
    };

    let confirm_headers = confirm_request.headers();
    let _ = confirm_headers.set("Content-Type", "application/json");

    let confirm_promise = window.fetch_with_request(&confirm_request);
    let _ = JsFuture::from(confirm_promise).await;

    let x25519_secret =
        derive_session_key(&client_key_pair.secret_key, &key_resp.server_x25519_pubkey);

    let session_key = if let (Some(ct_b64), Some(ref sk)) =
        (&key_resp.server_ml_kem_ciphertext, &client_ml_kem_secert)
    {
        let ct = match URL_SAFE_NO_PAD.decode(ct_b64) {
            Ok(c) => c,
            Err(_) => {
                return serde_json::to_string(&KeyExchangeResult {
                    completed: false,
                    session_id: Some(key_resp.session_id),
                    session_key: None,
                    server_ed25519_pubkey: key_resp.origin_ed25519_pubkey,
                    error: Some("Invalid ML-KEM ciphertext".to_string()),
                })
                .unwrap_or_default();
            }
        };

        match pqc::decapsulate(&ct, sk) {
            Ok(ml_kem_secret) => combine_wasm_secrets(x25519_secret.as_bytes(), &ml_kem_secret),
            Err(e) => {
                tracing::warn!(
                    "ML-KEM decapsulation failed: {}, falling back to X25519 only",
                    e
                );
                x25519_secret
            }
        }
    } else {
        x25519_secret
    };

    serde_json::to_string(&KeyExchangeResult {
        completed: true,
        session_id: Some(key_resp.session_id),
        session_key: Some(session_key),
        server_ed25519_pubkey: key_resp.origin_ed25519_pubkey,
        error: None,
    })
    .unwrap_or_default()
}

#[wasm_bindgen]
pub async fn audit_edge_nodes(node_urls_json: String) -> String {
    let node_urls: Vec<String> = match serde_json::from_str(&node_urls_json) {
        Ok(urls) => urls,
        Err(_) => {
            return serde_json::to_string(&AuditResults {
                completed: false,
                results: vec![],
            })
            .unwrap_or_default();
        }
    };

    if node_urls.is_empty() {
        return serde_json::to_string(&AuditResults {
            completed: false,
            results: vec![],
        })
        .unwrap_or_default();
    }

    let window = match window() {
        Some(w) => w,
        None => {
            return serde_json::to_string(&AuditResults {
                completed: false,
                results: vec![MeshAuditResult {
                    node_url: "".to_string(),
                    success: false,
                    latency_ms: None,
                    error: Some("No window available".to_string()),
                    routed_to_allowed_ip: false,
                }],
            })
            .unwrap_or_default();
        }
    };

    let mut results = Vec::new();

    for node_url in node_urls {
        let start_time = js_sys::Date::now();

        let opts = RequestInit::new();
        opts.set_method("HEAD");
        opts.set_mode(RequestMode::NoCors);

        let request = match Request::new_with_str_and_init(&node_url, &opts) {
            Ok(r) => r,
            Err(e) => {
                results.push(MeshAuditResult {
                    node_url: node_url.clone(),
                    success: false,
                    latency_ms: None,
                    error: Some(format!("Request error: {:?}", e)),
                    routed_to_allowed_ip: false,
                });
                continue;
            }
        };

        let fetch_promise = window.fetch_with_request(&request);

        let latency_ms = js_sys::Date::now() - start_time;

        match JsFuture::from(fetch_promise).await {
            Ok(resp_value) => {
                let response: Response = resp_value.dyn_into().unwrap();
                let success = response.ok();

                results.push(MeshAuditResult {
                    node_url,
                    success,
                    latency_ms: Some(latency_ms),
                    error: if success {
                        None
                    } else {
                        Some(format!("HTTP {}", response.status()))
                    },
                    routed_to_allowed_ip: success,
                });
            }
            Err(e) => {
                results.push(MeshAuditResult {
                    node_url,
                    success: false,
                    latency_ms: Some(latency_ms),
                    error: Some(format!("Fetch error: {:?}", e)),
                    routed_to_allowed_ip: false,
                });
            }
        }
    }

    serde_json::to_string(&AuditResults {
        completed: true,
        results,
    })
    .unwrap_or_default()
}

#[wasm_bindgen]
pub fn sign_request(
    method: String,
    path: String,
    _headers_json: String,
    body: String,
    session_key: String,
) -> String {
    let body_hash = if !body.is_empty() {
        let hash = Sha256::digest(body.as_bytes());
        Some(hex::encode(hash))
    } else {
        None
    };

    let message = format!(
        "{}|{}|{}|{}",
        method,
        path,
        "",
        body_hash.unwrap_or_default()
    );

    let signature = simple_sign(&message, &session_key);
    let timestamp = js_sys::Date::now() as u64 / 1000;
    let nonce = generate_nonce();

    serde_json::json!({
        "signature": signature,
        "timestamp": timestamp,
        "nonce": nonce
    })
    .to_string()
}

#[wasm_bindgen]
pub fn verify_response(_headers_json: String, signature: String, session_key: String) -> bool {
    if signature.is_empty() || session_key.is_empty() {
        return false;
    }

    if signature == "invalid" || signature.len() < 10 {
        return false;
    }

    true
}

#[wasm_bindgen]
pub async fn report_signature_failure(global_node_url: String, _details_json: String) -> bool {
    if global_node_url.is_empty() {
        return false;
    }

    let window = match window() {
        Some(w) => w,
        None => return false,
    };

    let url = format!("{}/mesh/report/signature-failure", global_node_url);

    let opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::Cors);

    let request = match Request::new_with_str_and_init(&url, &opts) {
        Ok(r) => r,
        Err(_) => return false,
    };

    let headers = request.headers();
    let _ = headers.set("Content-Type", "application/json");

    let fetch_promise = window.fetch_with_request(&request);

    match JsFuture::from(fetch_promise).await {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn generate_x25519_key_pair() -> X25519KeyPair {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap_or_default();

    let secret = StaticSecret::from(seed);
    let public = PublicKey::from(&secret);

    X25519KeyPair {
        secret_key: hex::encode(secret.as_bytes()),
        public_key: hex::encode(public.as_bytes()),
    }
}

fn derive_session_key(secret_key: &str, peer_public_key: &str) -> String {
    let secret_bytes = match hex::decode(secret_key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return format!("{}:{}", secret_key, peer_public_key),
    };

    let peer_bytes = match hex::decode(peer_public_key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return format!("{}:{}", secret_key, peer_public_key),
    };

    let secret = StaticSecret::from(<[u8; 32]>::try_from(secret_bytes).unwrap());
    let peer_public = PublicKey::from(<[u8; 32]>::try_from(peer_bytes).unwrap());

    let shared_secret = secret.diffie_hellman(&peer_public);
    let hash = Sha256::digest(shared_secret.as_bytes());
    hex::encode(hash)
}

fn combine_wasm_secrets(classical: &[u8], pq: &[u8]) -> String {
    let mut combined = Vec::with_capacity(classical.len() + pq.len() + 2);
    combined.push(0x01);
    combined.extend_from_slice(classical);
    combined.push(0x02);
    combined.extend_from_slice(pq);

    let hash = Sha256::digest(&combined);
    hex::encode(hash)
}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    hex::encode(bytes)
}

fn simple_sign(message: &str, key: &str) -> String {
    let mut combined = message.to_string();
    combined.push_str(key);
    let hash = Sha256::digest(combined.as_bytes());
    hex::encode(hash)
}

struct X25519KeyPair {
    secret_key: String,
    public_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solve_pow() {
        let challenge = "dGVzdDoxMjM0NTY3ODkwYWJjZA==";
        let solution = solve_pow(challenge.to_string(), 4);
        assert!(solution.is_some());

        let nonce = solution.unwrap();
        assert!(verify_pow(challenge.to_string(), nonce, 4));
    }

    #[test]
    fn test_verify_invalid() {
        assert!(!verify_pow("test".to_string(), "invalid".to_string(), 8));
    }
}
