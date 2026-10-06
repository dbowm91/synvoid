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
    has_leading_zeros_ct(&hash, difficulty as usize).into()
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
        (no verification cookie is issued — see "Trust Cookie")
```

## Trust Cookie (verification only; issuance is unimplemented)

The `sv_trust` cookie is **read and verified** in-tree, but **never issued**.
Split the two halves honestly:

**Implemented (verification side):**
- **Cookie name**: `sv_trust`, parsed by
  `synvoid_http::request_parse::extract_trust_token`
- **Verification**: `should_skip_waf_from_trust_cookie` calls the
  `EarlyWafHooks::verify_trust_token` hook; the production implementation is
  `WafCore::verify_trust_token` (`src/waf/mod.rs`), which recomputes
  `generate_trust_token(client_ip)` — HMAC-SHA256 over the client IP keyed by a
  per-process 32-byte `trust_token_key` (`src/waf/assembly.rs`) — and compares
  the 64 hex chars with `subtle::ConstantTimeEq`
- **Binding**: the token is bound to the client IP, not to a session or a user

**Not implemented (issuance side):**
- No code path anywhere in the tree constructs an `sv_trust` `Set-Cookie`
  header. `generate_trust_token` has exactly one caller — the `verify_trust_token`
  body itself, where it produces the *expected* value to compare against.
- Consequently a successful challenge verification does **not** mint a trust
  cookie, and the "subsequent requests bypass WAF" outcome above is
  unreachable in a running deployment. Every real client fails the comparison
  because no valid token is ever delivered to it.
- Do not read the verification code as evidence that challenge success is
  remembered across requests. It is a seam awaiting its issuer.

Because issuance is absent, the flags and TTL previously documented here
(`Secure; SameSite=Strict; HttpOnly`, 1 hour) have no producer and are not
verifiable from source; they are omitted rather than asserted.

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
