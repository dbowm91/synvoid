# Challenge Deep Dive

SynVoid's challenge system provides multi-layered browser verification to distinguish real browsers from bots, using proof-of-work (PoW) and CSS-based challenges.

## Challenge Types

### Proof-of-Work (PoW) Challenges

SHA-256 based proof-of-work with configurable difficulty.

```rust
pub struct PowChallenge {
    pub challenge: String,     // Challenge string for hashing
    pub difficulty: u8,        // 1-32 bits
    pub expires_at: u64,       // Expiration timestamp
}
```

**Verification**:
```rust
fn verify_pow_solution(challenge: &str, nonce: &str, difficulty: u8) -> bool {
    let input = format!("{}{}", challenge, nonce);
    let hash = Sha256::digest(input.as_bytes());
    has_leading_zeros(&hash, difficulty as usize)
}
```

**Adaptive Difficulty**:
- Base difficulty: configurable (default varies)
- Scales logarithmically above 100 concurrent challenges
- Maximum: configurable, default 16 (clamped to 32)
- Minimum: 1 bit

### CSS Challenges

Browser verification via CSS aspect-ratio media queries.

```rust
pub struct CssChallengeData {
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

The trust cookie (`sv_trust`) carries a signed token after successful challenge verification:

- **Cookie name**: `sv_trust`
- **Flags**: `Secure; SameSite=Strict; HttpOnly`
- **TTL**: Configurable (default 1 hour)
- **Verification**: Constant-time signature check

## Adaptive Difficulty

```rust
impl PowManager {
    fn get_computed_difficulty(&self) -> u32 {
        if !self.adaptive_difficulty {
            return self.difficulty;
        }

        let active = self.active_challenges.load(Ordering::Relaxed);
        if active < 100 {
            self.difficulty
        } else {
            // Logarithmic scaling: increase difficulty based on active challenges
            let extra_bits = (active as f32 / 100.0).log2() as u8;
            (self.difficulty + extra_bits).min(self.max_difficulty)
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
| `PowManager` | `crates/synvoid-challenge/src/manager_pow.rs` | PoW challenge generation/verification |
| `CssManager` | `crates/synvoid-challenge/src/css.rs` | CSS challenge generation |
| `HoneypotTracker` | `crates/synvoid-challenge/src/honeypot.rs` | Trap path generation |
| `ChallengeType` | `crates/synvoid-challenge/src/types.rs` | PoW, CSS, MeshPow variants |
| `ChallengePriority` | `crates/synvoid-challenge/src/types.rs` | Challenge ordering |
