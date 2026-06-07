# SynVoid Image Rights Terminology Rename Pass

> Status: proposed next-pass handoff.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one narrow task at a time.
> Goal: remove stale "poisoning" terminology from the image protection path now that SynVoid uses steganographic rights marking through eggostego/stegoeggo-style metadata/watermarking rather than perturbative image poisoning.

## 0. Context

Earlier SynVoid experiments used language such as:

```text
image_poisoning
poison_image
PoisonImageClient
SiteImagePoisonConfig
IMAGE_POISON_CACHE
apply_image_poisoning
invalidate_image_poison_cache_for_site
```

That terminology is now inaccurate. The current direction is not adversarial perturbation, Nightshade-style data poisoning, or visual image degradation. The intended behavior is rights signaling / steganographic marking / metadata or watermark injection through the eggostego/stegoeggo image-protection path.

This pass should rename code, docs, comments, plan files, public config fields where safe, and internal API identifiers away from "poisoning" and toward neutral rights-marking terminology.

Preferred terminology:

```text
image_rights
rights_marking
image_marking
rights_marker
stego_marking
protected_image
mark_image
ImageRightsClient
SiteImageRightsConfig
apply_image_rights_marking
invalidate_image_rights_cache_for_site
IMAGE_RIGHTS_CACHE
```

Avoid terms:

```text
poison
poisoning
perturb
perturbation
adversarial
nightshade
contaminate
```

Exception: historical migration notes and compatibility aliases may mention old names, but only to explain deprecation.

## 1. Current relevant state

The image helper was recently moved from root HTTP into `synvoid-static-files`:

```text
crates/synvoid-static-files/src/image_poisoning.rs
src/http/image_poisoning.rs  # root compatibility shim
```

The canonical implementation currently lives in `synvoid-static-files`, while root HTTP re-exports it for path stability.

This makes the rename pass easier: the canonical code is already isolated. The pass should rename this isolated module first, then update compatibility shims and references.

## 2. Naming target

Use this target mapping unless source inspection shows a better local name:

```text
image_poisoning.rs                    -> image_rights.rs
apply_image_poisoning                 -> apply_image_rights_marking
invalidate_image_poison_cache_for_site -> invalidate_image_rights_cache_for_site
IMAGE_POISON_CACHE                    -> IMAGE_RIGHTS_CACHE
IMAGE_POISON_CACHE_MAX_CAPACITY       -> IMAGE_RIGHTS_CACHE_MAX_CAPACITY
IMAGE_POISON_CACHE_TTL_SECS           -> IMAGE_RIGHTS_CACHE_TTL_SECS
SiteImagePoisonConfig                 -> SiteImageRightsConfig
PoisonImageClient                     -> ImageRightsClient or ImageMarkerClient
poison_image                          -> mark_image_rights or mark_image
poison_config                         -> rights_config
poison_fingerprint                    -> rights_fingerprint
poisoned                              -> marked
cpu_worker_socket                     -> static_worker_socket if semantically broader
```

Preferred module path:

```rust
synvoid_static_files::image_rights
```

Compatibility path, temporary:

```rust
synvoid_static_files::image_poisoning
src/http/image_poisoning
```

Compatibility should be deprecated where practical, but do not break downstream call sites prematurely.

## 3. Hard constraints

1. Preserve runtime behavior.
2. Do not change image bytes logic except identifier/path names.
3. Do not remove compatibility aliases in the same pass unless all call sites are internal and updated.
4. Do not create new crates.
5. Do not move HTTP server, HTTP3 server, WafCore, worker, supervisor, or mesh code.
6. Do not add dependencies from extracted crates back to root `synvoid`.
7. Keep each task narrow.
8. Do not use "poisoning" in new public docs except in deprecation notes.
9. Prefer additive rename + compatibility first, then cleanup.
10. If config field names change, preserve deserialization aliases for old config keys.

## 4. Validation matrix

After each task, run the task-specific checks. After each wave, run:

```bash
cargo fmt
cargo check -p synvoid-static-files
cargo check -p synvoid-config
cargo check -p synvoid-http
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

At the end of the pass, run:

```bash
cargo check --workspace --all-targets
rg -n "poison|poisoning|perturb|perturbation" .
```

The final `rg` may still find compatibility aliases, changelog notes, or historical plan files. All live/public terminology should be reviewed and either renamed or explicitly marked deprecated.

## 5. Wave N: inventory stale terminology

### Task IRT-N01: create image terminology inventory

Create:

```text
plans/image_rights_terminology_inventory.md
```

Run searches:

```bash
rg -n "poison|poisoning|Poison|POISON|perturb|perturbation|Perturb|PERTURB" src crates plans README.md docs architecture examples tests Cargo.toml
rg -n "SiteImagePoisonConfig|PoisonImageClient|poison_image|apply_image_poisoning|image_poisoning|IMAGE_POISON" src crates plans docs architecture examples tests
rg -n "stegoeggo|eggostego|stego|watermark|metadata|rights" src crates plans docs architecture examples tests README.md Cargo.toml
```

Record a table:

```text
Old symbol/path/text | File(s) | Is live code? | Public API/config? | Replacement | Action | Notes
```

Action values:

```text
RENAME_NOW
ADD_COMPAT_ALIAS
DOC_RENAME
CONFIG_ALIAS_REQUIRED
KEEP_DEPRECATED_COMPAT
KEEP_HISTORICAL_NOTE
UNKNOWN_INVESTIGATE
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

Do not modify live source code in this task except creating the inventory.

## 6. Wave C: config rename with compatibility

Purpose: rename config schema/types without breaking existing configs.

### Task IRT-C01: rename image rights config type

Target crate:

```text
crates/synvoid-config
```

Find:

```text
SiteImagePoisonConfig
image_poison / image_poisoning config fields
poison-related serde names
```

Preferred new type:

```rust
SiteImageRightsConfig
```

Compatibility strategy:

```rust
pub type SiteImagePoisonConfig = SiteImageRightsConfig;
```

If config field names currently use `image_poison` or similar, prefer a new canonical field such as:

```rust
image_rights: Option<SiteImageRightsConfig>
```

and preserve old input keys through serde aliases where possible:

```rust
#[serde(alias = "image_poison", alias = "image_poisoning")]
pub image_rights: Option<SiteImageRightsConfig>,
```

If the field name cannot be changed safely in this pass, rename only the type and add a TODO in the inventory.

Acceptance:

```bash
cargo check -p synvoid-config
cargo check -p synvoid-static-files
cargo check --lib --no-default-features
```

Stop condition:

If renaming the field causes broad config/schema/OpenAPI churn, keep the field name temporarily and only rename the type plus docs.

### Task IRT-C02: update config docs/examples

Update config docs, example config files, and inline comments so user-facing language says image rights marking / steganographic marking, not poisoning.

Search targets:

```text
README.md
docs/
architecture/
examples/
plans/
*.toml
*.md
```

Do not rewrite old historical plans except to add a note if they are likely to confuse future agents.

Acceptance:

```bash
cargo check -p synvoid-config
rg -n "image_poison|image_poisoning|SiteImagePoisonConfig" README.md docs architecture examples crates/synvoid-config src || true
```

Remaining matches must be compatibility aliases or historical notes.

## 7. Wave S: static-files module rename

Purpose: make `synvoid-static-files` use correct canonical terminology.

### Task IRT-S01: add canonical `image_rights` module

Target crate:

```text
crates/synvoid-static-files
```

Move or copy implementation from:

```text
crates/synvoid-static-files/src/image_poisoning.rs
```

to:

```text
crates/synvoid-static-files/src/image_rights.rs
```

Rename symbols according to the mapping:

```text
apply_image_poisoning -> apply_image_rights_marking
invalidate_image_poison_cache_for_site -> invalidate_image_rights_cache_for_site
IMAGE_POISON_CACHE -> IMAGE_RIGHTS_CACHE
SiteImagePoisonConfig -> SiteImageRightsConfig
PoisonImageClient -> ImageRightsClient or ImageMarkerClient if renamed in client module
poison_config -> rights_config
poison_fingerprint -> rights_fingerprint
poisoned -> marked
```

Update `crates/synvoid-static-files/src/lib.rs`:

```rust
pub mod image_rights;
pub use image_rights::{apply_image_rights_marking, invalidate_image_rights_cache_for_site};
```

Keep the old module temporarily as a compatibility shim:

```rust
pub mod image_poisoning;
```

Acceptance:

```bash
cargo check -p synvoid-static-files
```

### Task IRT-S02: convert old static-files image_poisoning module into deprecated shim

Target file:

```text
crates/synvoid-static-files/src/image_poisoning.rs
```

Replace implementation with compatibility aliases:

```rust
//! Deprecated compatibility shim.
//! Use `synvoid_static_files::image_rights` instead.

#[deprecated(note = "use apply_image_rights_marking")]
pub use crate::image_rights::apply_image_rights_marking as apply_image_poisoning;

#[deprecated(note = "use invalidate_image_rights_cache_for_site")]
pub use crate::image_rights::invalidate_image_rights_cache_for_site as invalidate_image_poison_cache_for_site;
```

If deprecation warnings break `-D warnings`, omit `#[deprecated]` for now and add a TODO note instead.

Acceptance:

```bash
cargo check -p synvoid-static-files
cargo check --lib --no-default-features
```

### Task IRT-S03: rename static-files client symbols

Inspect:

```text
crates/synvoid-static-files/src/client.rs
```

Rename if present:

```text
PoisonImageClient -> ImageRightsClient or ImageMarkerClient
poison_image -> mark_image_rights or mark_image
```

Compatibility strategy:

```rust
pub type PoisonImageClient = ImageRightsClient;
```

For methods, add a deprecated forwarding method if needed:

```rust
impl ImageRightsClient {
    pub async fn poison_image(...) -> ... {
        self.mark_image_rights(...).await
    }
}
```

Prefer `ImageRightsClient` and `mark_image_rights` if the API is specifically for rights metadata/marking. Prefer `ImageMarkerClient` and `mark_image` if the API is more generic.

Acceptance:

```bash
cargo check -p synvoid-static-files
cargo check --lib --no-default-features
```

Stop condition:

If renaming the client breaks an IPC protocol string or external worker contract, preserve wire-level names temporarily and rename only Rust wrapper identifiers.

## 8. Wave H: root HTTP compatibility rename

Purpose: keep old root path working while creating the correct canonical path.

### Task IRT-H01: add root canonical module path

Add:

```text
src/http/image_rights.rs
```

with:

```rust
// Root compatibility shim — canonical implementation is in synvoid-static-files.
pub use synvoid_static_files::image_rights::*;
```

Update `src/http/mod.rs`:

```rust
pub mod image_rights;
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task IRT-H02: convert root image_poisoning module into deprecated shim

Target file:

```text
src/http/image_poisoning.rs
```

Replace current shim with a deprecation/compat note:

```rust
//! Deprecated compatibility shim.
//! Use `crate::http::image_rights` or `synvoid_static_files::image_rights`.

pub use crate::http::image_rights::apply_image_rights_marking as apply_image_poisoning;
pub use crate::http::image_rights::invalidate_image_rights_cache_for_site as invalidate_image_poison_cache_for_site;
```

If other symbols need compatibility, add aliases explicitly.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task IRT-H03: update root call sites to canonical names

Search and update internal call sites:

```bash
rg -n "apply_image_poisoning|invalidate_image_poison_cache_for_site|image_poisoning" src crates/synvoid-http crates/synvoid-static-files
```

Replace internal non-compat usages with:

```text
apply_image_rights_marking
invalidate_image_rights_cache_for_site
image_rights
```

Do not change compatibility shim files in this task except as needed.

Acceptance:

```bash
cargo check -p synvoid-http
cargo check -p synvoid-static-files
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

## 9. Wave W: worker/IPC terminology rename

Purpose: remove stale poison terminology from IPC/client/worker-facing names without breaking the protocol.

### Task IRT-W01: inventory worker and IPC naming

Search:

```bash
rg -n "poison|Poison|POISON|image_poison|poison_image" src crates/synvoid-static-files crates/synvoid-ipc crates/synvoid-wasm-pow crates/synvoid-upload
```

Create/update section in:

```text
plans/image_rights_terminology_inventory.md
```

Classify each hit as:

```text
Rust-only identifier
wire protocol message
filesystem path/socket/env var
log message
public CLI/config
compat alias
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task IRT-W02: rename Rust-only worker identifiers

Rename only Rust-level identifiers that do not alter wire protocol or external socket/env names.

Examples:

```text
PoisonImageRequest -> ImageRightsMarkRequest
PoisonImageResponse -> ImageRightsMarkResponse
poison_image_handler -> image_rights_mark_handler
```

Compatibility:

```rust
pub type PoisonImageRequest = ImageRightsMarkRequest;
```

Do not change serialized enum variant names without aliases/backward compatibility.

Acceptance:

```bash
cargo check --workspace --all-targets
```

Stop condition:

If a rename changes serde tag names, IPC message variants, or worker protocol compatibility, stop and document a protocol migration plan instead of changing it silently.

### Task IRT-W03: rename log messages and comments

Update logs/comments to say rights marking, metadata marking, watermarking, or image marking.

Avoid user-visible claims that imply adversarial perturbation.

Acceptance:

```bash
cargo check --workspace --all-targets
rg -n "poison|poisoning|perturb|perturbation" src crates README.md docs architecture examples | tee /tmp/remaining-image-terminology.txt
```

Review remaining matches manually.

## 10. Wave D: documentation and plan cleanup

Purpose: avoid future agents reintroducing the wrong mental model.

### Task IRT-D01: update architecture/docs language

Search and update:

```text
README.md
docs/
architecture/
plans/http_root_only_modules.md
plans/http_module_overlap_matrix.md
plans/http_waf_access_and_static_files_pass.md
```

Use language such as:

```text
image rights marking
steganographic rights marking
metadata/watermark signaling
copyright / AI training restriction metadata
```

Avoid language such as:

```text
image poisoning
model poisoning
adversarial perturbation
Nightshade-style perturbation
```

Acceptance:

```bash
cargo check --workspace --all-targets
rg -n "poison|poisoning|perturb|perturbation" README.md docs architecture plans | tee /tmp/remaining-doc-terminology.txt
```

Remaining matches should be historical/deprecation notes only.

### Task IRT-D02: update public API docs/comments

Update rustdoc comments and public-facing messages in code.

Focus:

```text
crates/synvoid-static-files/src/image_rights.rs
crates/synvoid-static-files/src/client.rs
src/http/image_rights.rs
src/http/image_poisoning.rs compatibility note
crates/synvoid-config config comments
```

Acceptance:

```bash
cargo doc --no-deps -p synvoid-static-files
cargo check --workspace --all-targets
```

## 11. Wave R: final grep and compatibility decision

### Task IRT-R01: final terminology grep

Run:

```bash
rg -n "poison|poisoning|Poison|POISON|perturb|perturbation|Perturb|PERTURB" .
```

Create/update:

```text
plans/image_rights_terminology_inventory.md
```

Add a final section:

```text
Remaining stale terminology
```

For each remaining match, classify:

```text
COMPAT_ALIAS_OK
HISTORICAL_NOTE_OK
MUST_RENAME
UNKNOWN
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task IRT-R02: decide when to remove compatibility aliases

Do not remove aliases now. Add a short note to:

```text
plans/image_rights_terminology_inventory.md
```

Recommended policy:

```text
Keep poisoning compatibility aliases for one or two refactor cycles.
Remove after all internal code and docs use image_rights names and no external config examples reference old names.
If this project has no external consumers yet, removal can happen earlier, but only in a dedicated cleanup commit.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 12. Recommended task order

Use this exact order:

```text
IRT-N01  create image terminology inventory
IRT-C01  rename image rights config type with compatibility
IRT-C02  update config docs/examples
IRT-S01  add canonical image_rights module to synvoid-static-files
IRT-S02  convert old static-files image_poisoning module into shim
IRT-S03  rename static-files client symbols
IRT-H01  add root canonical http::image_rights module
IRT-H02  convert root http::image_poisoning into compatibility shim
IRT-H03  update root/internal call sites to canonical names
IRT-W01  inventory worker and IPC naming
IRT-W02  rename Rust-only worker identifiers
IRT-W03  rename log messages and comments
IRT-D01  update architecture/docs language
IRT-D02  update public API docs/comments
IRT-R01  final terminology grep
IRT-R02  decide when to remove compatibility aliases
```

## 13. Subagent prompt template

Use this for smaller agents:

```text
You are implementing SynVoid terminology rename task IRT-XX from plans/image_rights_terminology_rename_pass.md.
Scope is limited to this task. Preserve behavior. Do not create new crates. Do not move HTTP server, HTTP3 server, WafCore, worker, supervisor, Raft, or mesh code. Rename stale image-poisoning terminology to image-rights/rights-marking terminology while preserving compatibility aliases where needed. Do not change serialized config or IPC wire formats without aliases. Run the task acceptance commands and report exact failures.
```

## 14. Success criteria

This pass is successful when:

```text
1. Canonical module is synvoid_static_files::image_rights.
2. Canonical root path is crate::http::image_rights.
3. Internal call sites use apply_image_rights_marking / invalidate_image_rights_cache_for_site.
4. Poison/poisoning names remain only as compatibility aliases or historical notes.
5. Config uses image rights terminology with serde aliases for old keys if needed.
6. Worker/client Rust identifiers use rights-marking terminology where wire compatibility permits.
7. Docs describe steganographic rights marking, not poisoning or perturbation.
8. No behavior changes occur.
9. Existing feature checks pass.
10. Future agents are no longer guided toward the old poisoning mental model.
```
