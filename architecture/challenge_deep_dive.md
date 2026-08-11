# Challenge Deep Dive

SynVoid's challenge system provides multi-layered browser verification to distinguish real browsers from bots, using proof-of-work (PoW) and CSS-based challenges.

## Challenge Types

### Proof-of-Work (PoW) Challenges

SHA-256 based proof-of-work with configurable difficulty.

```rust
pub struct PowChallenge {
    pub timestamp: u64,
    pub difficulty: u32,      // 1-32 bits
    pub hash: [u8; 32],       // SHA-256 of solution
}

pub struct PowSolution {
    pub nonce: u64,
    pub hash: [u8; 32],
}
```

**Verification**:
```rust
fn verify_pow(challenge: &PowChallenge, solution: &PowSolution) -> bool {
    // 1. Check timestamp freshness (±5 minutes)
    // 2. Compute SHA-256(challenge.timestamp + solution.nonce)
    // 3. Verify hash matches challenge.hash
    // 4. Verify leading zeros >= difficulty
    has_leading_zeros_ct(&solution.hash, challenge.difficulty)
}
```

**Adaptive Difficulty**:
- Base difficulty: 6 bits (configurable)
- Scales logarithmically above 100 concurrent challenges
- Maximum: 32 bits
- Minimum: 1 bit

### CSS Challenges

Browser verification via CSS aspect-ratio media queries.

```rust
pub struct CssChallenge {
    pub valid_ratios: Vec<AspectRatio>,     // Real ratios browsers match
    pub invalid_ratios: Vec<AspectRatio>,   // Impossible ratios
    pub trap_paths: Vec<String>,            // Honeypot trap URLs
}
```

**How it works**:
1. Server generates HTML with CSS `@media (aspect-ratio: X/Y)` rules
2. Valid ratios: `1/1`, `4/3`, `16/9` (browsers match these)
3. Invalid ratios: `-1/0`, `0/0`, `99999/1` (browsers skip these)
4. Browser requests assets for valid ratios only
5. Server tracks which assets were requested
6. If all valid assets requested → verification cookie granted

**Honeypot Traps**:
- Hidden `<a>` tags with `/_waf_hp_{random}/{random}` URLs
- If accessed → IP banned (bot behavior)

## Challenge Priority

```rust
pub enum ChallengePriority {
    PowThenCss,      // Default
    CssThenPow,
    PowOnly,
    CssOnly,
    MeshPowThenCss,  // Mesh-distributed PoW
    MeshPowOnly,
}
```

## Flow

```
Request ──► WAF Decision: Challenge
                │
                ▼
        Challenge Manager
                │
                ├── Generate PoW challenge
                │   └── Store in challenge cache (TTL: 5 min)
                │
                ├── Generate CSS challenge
                │   └── Store session tracking
                │
                └── Render HTML page
                    ├── Theme integration (dark/light)
                    ├── WASM PoW solver (optional)
                    └── CSS trap paths
                │
                ▼
        Client receives 403 + HTML
                │
                ▼
        Client solves challenge
                │
                ├── PoW: Compute nonce with leading zeros
                │   └── POST /__waf_pow_verify { nonce, hash }
                │
                └── CSS: Request all valid assets
                    └── Browser auto-requests CSS files
                │
                ▼
        Server verifies
                │
                ├── PoW: Constant-time leading zero check
                │
                └── CSS: Check all valid assets requested
                │
                ▼
        Set verification cookie
        └── sv_trust=<signed_token>
                │
                ▼
        Subsequent requests bypass WAF (trust cookie)
```

## Trust Cookie

```rust
pub struct TrustToken {
    pub ip: IpAddr,
    pub expires_at: u64,
    pub challenge_type: ChallengeType,
    pub signature: [u8; 64],  // Ed25519
}
```

- **Cookie name**: `sv_trust`
- **Flags**: `Secure; SameSite=Strict; HttpOnly`
- **TTL**: Configurable (default 1 hour)
- **Verification**: Constant-time signature check

## Adaptive Difficulty

```rust
impl PowManager {
    fn calculate_difficulty(&self) -> u32 {
        let active = self.active_challenges.load(Ordering::Relaxed);
        let base = self.config.base_difficulty;
        
        if active < 100 {
            base
        } else {
            // Logarithmic scaling
            let scale = (active as f64 / 100.0).log2() as u32;
            (base + scale).min(self.config.max_difficulty)
        }
    }
}
```

## Mesh-PoW Integration

For distributed verification across mesh nodes:

1. Edge node generates PoW challenge
2. Challenge includes edge node's mesh public key
3. Solution signed by client
4. Any mesh node can verify (challenge is self-contained)
5. Trust cookie includes mesh node ID for audit trail

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `PowManager` | `crates/synvoid-challenge/src/pow.rs` | PoW challenge generation/verification |
| `CssManager` | `crates/synvoid-challenge/src/css.rs` | CSS challenge generation |
| `HoneypotTracker` | `crates/synvoid-challenge/src/honeypot.rs` | Trap path generation |
| `ChallengeType` | `crates/synvoid-challenge/src/lib.rs` | PoW, CSS, MeshPow variants |
| `ChallengePriority` | `crates/synvoid-challenge/src/lib.rs` | Challenge ordering |
| `TrustToken` | `crates/synvoid-challenge/src/trust.rs` | Verification cookie payload |
