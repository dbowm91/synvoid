# SynVoid Image Rights Final Cleanup Plan

> Status: proposed final cleanup after the image-rights terminology rename pass.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one narrow task at a time.
> Goal: clean up the remaining terminology debt after renaming image protection from poisoning/perturbation language to rights-marking language.

## 0. Current state

The main rename pass is substantially complete.

Canonical paths now exist:

```text
synvoid_static_files::image_rights
crate::http::image_rights
```

Canonical functions now exist:

```text
apply_image_rights_marking
invalidate_image_rights_cache_for_site
```

Canonical config now exists:

```text
SiteConfig.image_rights
SiteImageRightsConfig
```

Compatibility paths remain:

```text
synvoid_static_files::image_poisoning
crate::http::image_poisoning
SiteImagePoisonConfig
```

Those compatibility paths are acceptable for now as long as they are documented and do not appear as the preferred API in docs or internal call sites.

Known remaining cleanup issues:

```text
1. `ImageRightsClientError::MarkingFailed` still renders `Poisoning failed: ...`.
2. IPC/wire-level names still use `PoisonImage`, `PoisonImageRequest`, `PoisonImageResponse`, `PoisonImageError`, and `poisoned_body`.
3. The planned `plans/image_rights_terminology_inventory.md` file was not present during review and should be created or restored.
4. Final grep results should classify all remaining poison/perturbation terms as compatibility aliases, historical notes, or must-fix items.
```

## 1. Scope

This is a cleanup pass, not a new refactor pass.

Allowed:

```text
Fix stale user-visible strings.
Create terminology inventory.
Classify IPC names as wire compatibility debt or rename candidates.
Rename Rust-only internal identifiers if no serialized/wire compatibility is affected.
Add compatibility/deprecation notes.
Update docs/comments that still imply perturbative poisoning.
```

Not allowed:

```text
Do not change image marking behavior.
Do not change serialized IPC wire variants without explicit compatibility aliases or a protocol migration.
Do not move HTTP server, HTTP3 server, WafCore, worker, supervisor, Raft, mesh, or proxy code.
Do not create new crates.
Do not remove compatibility aliases in this pass.
```

## 2. Hard constraints

1. Preserve runtime behavior.
2. Preserve config compatibility for the old `image_poison` key.
3. Preserve IPC compatibility unless a task explicitly documents and implements aliases.
4. Do not introduce any dependency from extracted crates back to root `synvoid`.
5. Keep compatibility shims for at least one more refactor cycle.
6. Do not leave new user-facing text saying poisoning, perturbation, adversarial, or Nightshade-style behavior.
7. Every remaining poison/perturb match after this pass must be classified.

## 3. Validation matrix

After each task, run the local acceptance commands.

At the end of the pass, run:

```bash
cargo fmt
cargo check -p synvoid-static-files
cargo check -p synvoid-config
cargo check -p synvoid-ipc
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
cargo check --workspace --all-targets
rg -n "poison|poisoning|Poison|POISON|perturb|perturbation|Perturb|PERTURB" .
```

The final `rg` is allowed to return compatibility aliases, deprecated shims, historical plan notes, and IPC wire-compatibility names, but each remaining result must be classified in the inventory.

## 4. Task IRC-01: fix stale user-visible error string

Target file:

```text
crates/synvoid-static-files/src/client.rs
```

Find:

```rust
ImageRightsClientError::MarkingFailed(e) => write!(f, "Poisoning failed: {}", e),
```

Replace with:

```rust
ImageRightsClientError::MarkingFailed(e) => write!(f, "Image rights marking failed: {}", e),
```

or:

```rust
ImageRightsClientError::MarkingFailed(e) => write!(f, "Rights marking failed: {}", e),
```

Acceptance:

```bash
cargo check -p synvoid-static-files
rg -n "Poisoning failed|poisoning failed" crates/synvoid-static-files src crates
```

The grep should return no live user-facing error strings.

## 5. Task IRC-02: create final terminology inventory

Create:

```text
plans/image_rights_terminology_inventory.md
```

Run:

```bash
rg -n "poison|poisoning|Poison|POISON|perturb|perturbation|Perturb|PERTURB" src crates plans README.md docs architecture examples tests Cargo.toml
```

Record results in sections:

```text
## Must rename now
## Compatibility aliases retained
## IPC wire compatibility retained
## Historical plan notes retained
## Unknown / needs investigation
```

For each entry, record:

```text
Term | File | Context | Classification | Action | Notes
```

Classifications:

```text
MUST_RENAME
COMPAT_ALIAS_OK
IPC_WIRE_COMPAT_OK
HISTORICAL_NOTE_OK
UNKNOWN_INVESTIGATE
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 6. Task IRC-03: classify IPC poison names

Target files likely:

```text
crates/synvoid-ipc/src/**
crates/synvoid-static-files/src/client.rs
src/** worker/static CPU task code
```

Inventory these names:

```text
CpuTaskKind::PoisonImage
CpuTaskPayload::PoisonImage
CpuTaskResult::PoisonImage
Message::PoisonImageRequest
Message::PoisonImageResponse
Message::PoisonImageError
poisoned_body
```

Update `plans/image_rights_terminology_inventory.md` with a protocol section answering:

```text
Are these names serialized or wire-visible?
Are they part of an external/stable protocol?
Can they be renamed now with serde aliases?
Should they remain as compatibility debt until a protocol version bump?
```

Recommended default decision:

```text
If the IPC message names are serialized across worker boundaries, keep them for now and classify as IPC_WIRE_COMPAT_OK.
Do not rename them silently.
Use rights-marking names only in Rust wrapper APIs and user-facing logs/errors.
Plan a later IPC protocol-v2 rename if desired.
```

Acceptance:

```bash
cargo check -p synvoid-ipc
cargo check -p synvoid-static-files
cargo check --workspace --all-targets
```

## 7. Task IRC-04: rename Rust-only IPC-adjacent comments/logs

After IRC-03, rename comments/logs that are not wire identifiers.

Examples:

```text
"poison image task" -> "image rights marking task"
"poisoned image" -> "marked image"
"poisoning failed" -> "image rights marking failed"
```

Do not rename enum variants, serialized field names, or protocol tags in this task.

Acceptance:

```bash
cargo check -p synvoid-ipc
cargo check -p synvoid-static-files
rg -n "poisoning failed|poison image task|poisoned image" src crates
```

Remaining matches should be enum/field compatibility names only.

## 8. Task IRC-05: verify config compatibility and docs language

Check config definitions:

```text
crates/synvoid-config/src/site/mod.rs
crates/synvoid-config/src/site/misc.rs
```

Expected state:

```rust
pub image_rights: SiteImageRightsConfig
#[serde(alias = "image_poison")]
pub type SiteImagePoisonConfig = SiteImageRightsConfig;
```

Update docs/examples so canonical docs use:

```text
[image_rights]
image rights marking
steganographic rights marking
metadata/watermark signaling
```

Do not remove `image_poison` alias yet.

Acceptance:

```bash
cargo check -p synvoid-config
rg -n "image_poison|SiteImagePoisonConfig|poisoning|perturb" README.md docs architecture examples crates/synvoid-config
```

Remaining matches should be compatibility alias comments or historical notes only.

## 9. Task IRC-06: verify canonical call sites

Search internal live code for old canonical function/module usage:

```bash
rg -n "apply_image_poisoning|invalidate_image_poison_cache_for_site|image_poisoning" src crates --glob '!crates/synvoid-static-files/src/image_poisoning.rs' --glob '!src/http/image_poisoning.rs'
```

Replace internal live usages with:

```text
apply_image_rights_marking
invalidate_image_rights_cache_for_site
image_rights
```

Do not modify compatibility shim files except if they contain incorrect docs.

Acceptance:

```bash
cargo check -p synvoid-static-files
cargo check -p synvoid-http
cargo check --lib --no-default-features
```

The grep should return only compatibility shims or inventory notes.

## 10. Task IRC-07: final compatibility policy note

Update:

```text
plans/image_rights_terminology_inventory.md
```

Add a final section:

```text
## Compatibility removal policy
```

Recommended policy:

```text
Keep `image_poisoning` compatibility modules and `SiteImagePoisonConfig` alias for at least one more refactor cycle.
Keep IPC `PoisonImage` wire names until an explicit IPC protocol version bump or alias-based migration is implemented.
Remove compatibility shims only after all internal call sites and docs use image-rights names and no external examples reference old names.
If SynVoid has no external users yet, the compatibility removal can be done earlier, but only in a dedicated cleanup commit with full grep validation.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 11. Recommended task order

Use this exact order:

```text
IRC-01  fix stale user-visible error string
IRC-02  create final terminology inventory
IRC-03  classify IPC poison names
IRC-04  rename Rust-only IPC-adjacent comments/logs
IRC-05  verify config compatibility and docs language
IRC-06  verify canonical call sites
IRC-07  add final compatibility removal policy
```

## 12. Subagent prompt template

Use this prompt for smaller agents:

```text
You are implementing SynVoid image-rights cleanup task IRC-XX from plans/image_rights_final_cleanup.md.
Scope is limited to this task. Preserve behavior. Do not create new crates. Do not move HTTP server, HTTP3 server, WafCore, worker, supervisor, Raft, mesh, or proxy code. Do not rename serialized IPC wire variants unless aliases and a protocol migration are explicitly part of the task. Replace stale poisoning/perturbation language with image-rights/rights-marking terminology. Run the task acceptance commands and report exact failures.
```

## 13. Success criteria

This cleanup pass is successful when:

```text
1. No user-facing error string says "Poisoning failed".
2. `plans/image_rights_terminology_inventory.md` exists.
3. Every remaining poison/perturb match is classified.
4. Internal live code uses image-rights names except compatibility aliases and IPC wire names.
5. Config canonical field/type names remain image-rights based.
6. Old config key compatibility is preserved.
7. IPC poison names are explicitly classified as wire compatibility debt or are migrated with aliases in a separate protocol task.
8. Existing feature checks pass.
```
