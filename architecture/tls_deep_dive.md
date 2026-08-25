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
    default_cert: Arc<RwLock<Option<Arc<CertifiedKey>>>>,
    config: InternalTlsConfig,
    reload_tx: broadcast::Sender<()>,
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
    config: InternalAcmeConfig,
    cert_resolver: Arc<CertResolver>,
    account: parking_lot::RwLock<Option<Account>>,
    credentials_path: PathBuf,
    http_challenges: Arc<DashMap<String, String>>,
    dns_challenges: Option<Arc<AcmeDnsChallenge>>,  // behind "dns" feature
    managed_certs: parking_lot::RwLock<HashMap<String, ManagedCert>>,
    renew_callback: parking_lot::RwLock<Option<Box<dyn Fn(Vec<String>) + Send + Sync>>>,
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
pub fn compute_ja4(data: &[u8]) -> Option<String> {
    // JA4 format: {tls_version}{sni_flag}{cipher_count}_{first_alpn}_{cipher_hash}_{ext_hash}
    // Example: 13d0000h2_8daaf6152771
    
    let info = parse_client_hello_info(data).ok()??;
    
    let tls_version = match info.tls_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => return None,
    };
    
    let sni_flag = if info.has_sni { "d" } else { "i" };
    let cipher_count = info.cipher_suites.len().min(99);
    // ... hash computation ...
    
    Some(format!("{}{:02x}{}_...", tls_version, cipher_count, sni_flag))
}
```

### Hot-Reload

```rust
pub fn watch_for_cert_changes(
    resolver: Arc<CertResolver>,
    watch_dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut watcher = notify::recommended_watcher(move |res| {
            if res.is_ok() { let _ = tx.blocking_send(()); }
        })?;
        
        watcher.watch(watch_dir.as_path(), notify::RecursiveMode::Recursive)?;
        
        loop {
            // Wait for filesystem events, debounce, then call resolver.load_certificates()
        }
    })
}
```

### Key Strength Validation

```rust
fn validate_key_strength(&self, key: &PrivateKeyDer<'_>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match key {
        PrivateKeyDer::Pkcs1(pkcs1) => {
            // Estimate RSA key size from DER length; reject < 2048 bits
        }
        PrivateKeyDer::Sec1(_sec1) => {
            // EC keys are inherently strong (>= 160 bits)
        }
        PrivateKeyDer::Pkcs8(pkcs8) => {
            // Try to parse as RSA; reject < 2048 bits
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
| `AcmeDnsChallenge` | `crates/synvoid-tls/src/acme_dns.rs` | DNS-01 challenge handling |
| `SniPeekResult` / `ClientHelloInfo` | `crates/synvoid-tls/src/sni_peek.rs` | SNI extraction + JA4 fingerprinting |
