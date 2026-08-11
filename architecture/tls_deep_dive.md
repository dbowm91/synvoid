# TLS Deep Dive

SynVoid's TLS crate handles TLS termination, ACME certificate management, SNI handling, and JA4 fingerprinting via `rustls`.

## Architecture

### Core Components

```
TLS
├── CertResolver (SNI-based resolution)
├── AcmeManager (Let's Encrypt)
├── SniPeek (JA4 fingerprinting)
└── CertWatcher (hot-reload)
```

### Certificate Resolution

```rust
pub struct CertResolver {
    certs: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
    wildcard_certs: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
    watcher: Option<notify::RecommendedWatcher>,
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // 1. Exact domain match
        // 2. Wildcard match (*.example.com)
        // 3. Default certificate
    }
}
```

### ACME Protocol

```rust
pub struct AcmeManager {
    account: AcmeAccount,
    config: AcmeConfig,
    cert_store: Arc<CertStore>,
}

impl AcmeManager {
    pub async fn obtain_certificate(&self, domains: &[String]) -> Result<CertifiedKey> {
        // 1. Initialize ACME account
        // 2. Create order for domains
        // 3. Complete HTTP-01 or DNS-01 challenges
        // 4. Finalize order
        // 5. Store certificate
    }
    
    pub async fn renew_if_needed(&self) -> Result<()> {
        // Check expiry, renew if within 30 days
    }
}
```

### JA4 Fingerprinting

```rust
pub fn compute_ja4(client_hello: &ClientHello) -> String {
    // JA4 format: t{TLS_version}{SNI}{Cipher_count}{Extension_count}_{Hash}
    // Example: t13d1516h2_8daaf6152771
    
    let mut ja4 = String::new();
    ja4.push_str(&format!("t{}", tls_version));
    ja4.push_str(if sni { "d" } else { "i" });
    ja4.push_str(&format!("{:02x}", cipher_suites.len()));
    ja4.push_str(&format!("{:02x}", extensions.len()));
    ja4.push('_');
    ja4.push_str(&hash_hex(&hash_input));
    
    ja4
}
```

### Hot-Reload

```rust
pub fn watch_for_cert_changes(
    cert_path: &Path,
    key_path: &Path,
    resolver: Arc<CertResolver>,
) -> Result<()> {
    let mut watcher = notify::RecommendedWatcher::new(
        move |event| {
            if event.kind == EventKind::Modify(_) || event.kind == EventKind::Create(_) {
                // Reload certificate
                if let Ok(cert) = load_certificate(cert_path, key_path) {
                    resolver.insert_cert(cert);
                }
            }
        },
        notify::Config::default(),
    )?;
    
    watcher.watch(cert_path, RecursiveMode::NonRecursive)?;
    Ok(())
}
```

### Key Strength Validation

```rust
pub fn validate_key_strength(key: &PrivateKey) -> Result<()> {
    match key.algorithm() {
        Algorithm::Rsa => {
            let size = key.key_size();
            if size < 2048 {
                return Err(Error::WeakKey(format!("RSA {} bits < 2048", size)));
            }
        }
        Algorithm::Ecdsa => {
            // ECDSA keys are generally safe
        }
        Algorithm::Ed25519 => {
            // Ed25519 keys are always safe
        }
    }
    Ok(())
}
```

## Integration Points

- Used by worker/server composition root to build `rustls::ServerConfig`
- `watch_for_cert_changes()` spawns filesystem watcher for live cert rotation
- Supports ACME HTTP-01 and DNS-01 challenges
- JA4 fingerprints used for bot detection and client identification

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `CertResolver` | `crates/synvoid-tls/src/cert_resolver.rs` | SNI-based certificate resolution |
| `AcmeManager` | `crates/synvoid-tls/src/acme.rs` | ACME protocol lifecycle |
| `AcmeDnsManager` | `crates/synvoid-tls/src/acme_dns.rs` | DNS-01 challenge handling |
| `ClientHelloInfo` | `crates/synvoid-tls/src/sni_peek.rs` | SNI extraction + JA4 |
| `CertStore` | `crates/synvoid-tls/src/cert_store.rs` | Certificate storage |
