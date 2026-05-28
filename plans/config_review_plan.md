# Configuration Review Plan

**Reviewed:** 2026-05-28
**Documents:** `architecture/config.md`, `architecture/config_deep_dive.md`

## Verified Correct Items

- **ConfigManager struct** (`lib.rs:113-119`): All fields match: `main`, `sites`, `sites_dir`, `config_dir`, `site_filenames` (private). ✓
- **ConfigManager methods** (`lib.rs:121-241`): `new()`, `load_main()`, `load_site()`, `discover_sites()`, `get_site()`, `reload_site()`, `reload_all()` — all verified at correct locations. ✓
- **MainConfig fields** (`main_config.rs:74-143`): All documented fields present in actual struct. ✓
- **SiteConfig fields** (`site/mod.rs:69-128`): All 29 documented fields present. ✓
- **SiteConfig::site_id()** (`site/mod.rs:204-206`): Returns first domain, matches doc. ✓
- **SiteConfig::default_fallback_site()** (`site/mod.rs:131-171`): Uses `_fallback_` domain, matches doc. ✓
- **SiteConfig::app_server_config()** (`site/mod.rs:208-261`): Propagation pattern matches doc. ✓
- **UpstreamConfig** (`site/listen.rs:74-114`): Fields and `get_upstream()` method match doc. ✓
- **UpstreamConfig validation** (`site/listen.rs:142-176`): Supported schemes (http://, https://, tunnel:, unix:) match doc. ✓
- **SiteListenConfig** (`site/listen.rs:9-63`): Fields and `to_socket_addr()` method match doc. ✓
- **AdminConfig** (`admin.rs:36-55`): Fields match doc. ✓
- **AdminConfig::resolve_token()** (`admin.rs:78-90`): Priority order matches doc (env var → config → generate). ✓
- **AdminConfig::validate()** (`admin.rs:110-178`): Port nonzero, bcrypt 12-15, token ≥32 chars, weak patterns rejected — all match doc. ✓
- **MIN_TOKEN_LENGTH** (`admin.rs:7`): Value 32 matches doc. ✓
- **TlsConfig** (`tls.rs:12-39`): Fields match doc. `prefer_post_quantum` defaults true, `tls_1_3_only` defaults true. ✓
- **TlsConfig::validate()** (`tls.rs:70-108`): Checks cert/key exist, ACME validation — matches doc. ✓
- **AcmeConfig** (`tls.rs:157-173`): Fields match doc. ✓
- **AcmeChallengeType** (`tls.rs:175-183`): `Http01`, `Dns01` variants at line 179, matches doc. ✓
- **MainSecurityConfig** (`security.rs:14-27`): Fields and defaults (`ipc_enforce_signing=true`, `sanitize_forwarded_headers=true`, `global_security_headers=true`) match doc. ✓
- **SiteSecurityHeadersConfig** (`site/security.rs:51-91`): Fields match doc (HSTS, CSP, X-Content-Type-Options, X-XSS-Protection, etc.). ✓
- **ConfigValidationError** (`validation.rs:1-5`): `field` and `message` fields match doc. ✓
- **parse_size_string()** (`validation.rs:15-29`): Utility function matches doc. ✓
- **BandwidthLimitAction** (`traffic.rs:23-30`): `Block`, `Throttle` variants at line 24, matches doc. ✓
- **VpnAccessLevel** (`tunnel.rs:231-248`): `General`, `Admin` variants at line 235, matches doc. ✓
- **default_tls_port** (`tls.rs:61`): Value 443 at line 61, matches doc. ✓
- **default_mesh_port** (`mesh.rs:563`): Value 50051 at line 563, matches doc. ✓
- **default_dns_port** (`dns/mod.rs:144`): Value 53 at line 144 (doc says 145 — minor off-by-one). ✓
- **default_wg_port** (`tunnel.rs:86`): Value 51820 at line 87 (doc says 86 — minor off-by-one). ✓
- **default_quic_port** (`tunnel.rs:209`): Value 51821 at line 209, matches doc. ✓
- **DnsMode** (`dns/mod.rs:35-43`): `Standalone`, `Mesh` variants at line 39, matches doc. ✓
- **AppServerConfig defaults** (`app_server.rs:40-68`): Port 8000, host "127.0.0.1" at lines 49-50 — matches doc claim. ✓
- **BlockedDefaults** (`defaults.rs:218-242`): Fields and defaults (paths, use_regex=true, block_methods, block_response_code=403) match doc. ✓
- **BotDefaults** (`defaults.rs:252-357`): `block_ai_crawlers=true`, `enable_css_honeypot=true`, `challenge_window_secs=300`, `js_difficulty=1`, `challenge_max_attempts=5` — all match doc. ✓
- **ConfigManager location** (`lib.rs:113`): Matches AGENTS.md correction. ✓
- **Feature gates** (`Cargo.toml:33-37`): `dns = []`, `icmp-filter = []`, `mesh = ["dep:ed25519-dalek"]`, `rkyv = []` — matches doc. ✓
- **Feature-gated validation** (`main_config.rs:192-213`): DNS and mesh feature-gated checks match doc. ✓

## Discrepancies Found

- **config.md:200** — Claims `MeshNodeRole` is an `enum` at `mesh.rs:223`. Actual: It is a **`struct(u8)`** with associated `const` values (bitflag pattern), not an `enum`. The variants are `GLOBAL`, `EDGE`, `ORIGIN`, `GLOBAL_EDGE`, `GLOBAL_ORIGIN`, `EDGE_ORIGIN`, `ALL`, `SERVERLESS_ORIGIN` as associated constants, not enum variants. This is a significant type-level discrepancy.

- **config.md:98-135** — `MainConfig` struct listing includes `overseer: OverseerConfig` field. Actual: The field is `supervisor_compat: SupervisorConfig` (line 136). `OverseerConfig` exists as a separate struct in `process.rs:98` but is NOT a field of `MainConfig`. The doc should list `supervisor_compat: SupervisorConfig`.

- **config.md:86** — The `default_wg_port` is claimed at `tunnel.rs:86`. Actual: `fn default_wg_port()` is at `tunnel.rs:87` (line 87, not 86).

- **config.md:85** — The `default_dns_port` is claimed at `dns/mod.rs:145`. Actual: `fn default_dns_port()` is at `dns/mod.rs:144` (line 144, not 145).

- **config_deep_dive.md:91-117** — SiteConfig hierarchy is incomplete. Missing fields: `worker_pool`, `logging`, `proxy`, `tcp`, `udp`, `tarpit`, `upload`, `auth`, `tunnel`, `whitelist`, `serverless_only`. Lists `site_id` as a field, but it is a **method**, not a field.

- **config_deep_dive.md:329** — Claims DNS validation runs at step 10 unconditionally (when `dns` feature enabled). Actual (`main_config.rs:200`): DNS validation only runs if **both** `dns` feature is compiled **AND** `self.dns.enabled == true`. The `dns.validate()` call is inside `if self.dns.enabled { ... }` block.

- **config.md:662-707** — Appendix file structure is incomplete. Missing files:
  - `site/misc.rs` (contains `SiteImagePoisonConfig`, `SiteLoggingConfig`, `SiteWorkerPoolConfig`)
  - `icmp_filter.rs` (feature-gated ICMP filtering)
  - DNS subdirectory shows only `mod.rs` but actual has 10 submodules: `dns_anycast.rs`, `dns_dnssec.rs`, `dns_encrypted.rs`, `dns_firewall.rs`, `dns_mesh.rs`, `dns_misc.rs`, `dns_rate_limit.rs`, `dns_recursive.rs`, `dns_settings.rs`, `dns_zones.rs`

## Bugs Identified

- **[LOW] CFG-1**: `config.md` lists `MeshNodeRole` as an `enum` (line 200) when it is actually a `struct(u8)` with associated constants. Misleads developers about the API surface — cannot use `match` on it, must use `contains()` or `is_global()` etc. (`mesh.rs:223`)

- **[LOW] CFG-2**: `config.md` includes non-existent `overseer: OverseerConfig` field in MainConfig struct listing (line 131). The actual field is `supervisor_compat: SupervisorConfig` (line 136). May cause confusion when implementing config-related changes.

- **[LOW] CFG-3**: `config_deep_dive.md` validation sequence (line 329) states `dns.validate()` runs unconditionally when `dns` feature is enabled. Actual behavior requires `dns.enabled == true` as well. This could mislead operators who enable the `dns` feature but set `dns.enabled = false` — they may expect validation errors that never occur.

## Suggested Improvements

- **Documentation accuracy**: Update `config.md` line 200 to describe `MeshNodeRole` as a `struct(u8)` bitflag pattern with associated constants, not an `enum`.

- **Documentation accuracy**: Update `config.md` MainConfig listing (line 131) to show `supervisor_compat: SupervisorConfig` instead of `overseer: OverseerConfig`.

- **Documentation completeness**: Add the 10 missing DNS submodule files to the `config.md` appendix file structure (lines 677-678).

- **Documentation completeness**: Add `site/misc.rs`, `icmp_filter.rs` to the `config.md` appendix file structure.

- **Documentation completeness**: Expand `config_deep_dive.md` SiteConfig hierarchy (lines 91-117) to include all fields, or add a note that it is a summary, not exhaustive.

- **Documentation clarity**: Clarify in `config_deep_dive.md` that `dns.validate()` only runs when `dns.enabled == true` (not just when `dns` feature is compiled).

- **Documentation clarity**: Correct `config.md` line 85 (`dns/mod.rs:145` → `dns/mod.rs:144`) and line 86 (`tunnel.rs:86` → `tunnel.rs:87`) for default function locations.

## Stale Content

- **config.md:131** — `overseer: OverseerConfig` field listed in MainConfig is stale. The code uses `supervisor_compat: SupervisorConfig` instead. The `OverseerConfig` type exists but is not a MainConfig field.

- **config_deep_dive.md:95** — `site_id: String` listed as a SiteConfig field is stale. `site_id` is a **method** (`fn site_id(&self) -> String` at `site/mod.rs:204`), not a field.

## Cross-Reference Status

- **AGENTS.md ConfigManager location** (`crates/synvoid-config/src/lib.rs:113`): Still accurate ✓
- **AGENTS.md DnsConfig.validate() called in MainConfig::validate()**: Still accurate (lines 192-203) ✓
- **AGENTS.md WAF connection limits misdocumented** (`traffic.rs:167-176`): Previously fixed, no recurrence ✓
- **AGENTS.md Known File Path Corrections** — ConfigManager location: Still accurate ✓
