# Admin-UI Workspace Fix Plan (SDC-B01/B02/B03)

## SDC-B01: Error Table

| Error | File | Cause | Proposed Fix | Notes |
|-------|------|-------|-------------|-------|
| E0609: no field `wireguard_enabled` on `MeshConfig` | `admin-ui/src/pages/mesh.rs:84` | Field was moved to `TunnelConfig` during refactor | Removed wireguard response parsing (dead code, field no longer on struct) | WireGuard config is now in TunnelConfig |
| E0609: no field `wireguard_enabled` on `UseStateHandle<MeshConfig>` | `admin-ui/src/pages/mesh.rs:277` | Field was moved to `TunnelConfig` during refactor | Removed WireGuard checkbox UI from mesh page | WireGuard toggling belongs in tunnel settings |
| E0609: no field `wireguard_enabled` on `MeshConfig` | `admin-ui/src/pages/mesh.rs:283` | Field was moved to `TunnelConfig` during refactor | Removed WireGuard checkbox UI (same block as 277) | Part of the same removal |
| E0282: type annotations needed | `admin-ui/src/pages/tier_keys.rs:163` | Yew `callback` closure needs explicit type on param `e` | Added `\|e: InputEvent\|` type annotation and `target_unchecked_into()` cast | Pattern matches other closures in codebase |
| E0277: `IntoPropValue<Option<IString>>` not satisfied for `u32` | `admin-ui/src/pages/tier_keys.rs:170` | `<select>` `value` prop expects `Option<IString>`, not `u32` | Changed to `self.issue_tier.to_string()` | Yew select value is always a string |

## SDC-B02: Missing Dependencies

No missing direct dependencies were needed. All 5 errors were type errors, not missing crate imports.

## SDC-B03: Type Error Fixes Applied

### mesh.rs changes
- **Removed** lines 80-86: Parsing `wireguard_enabled` from API response into `MeshConfig` (field doesn't exist on struct)
- **Removed** lines 273-291: "Enable WireGuard" checkbox UI that read/wrote `wireguard_enabled` on `MeshConfig`

### tier_keys.rs changes
- Line 163: Added `InputEvent` type annotation to `oninput` closure parameter
- Line 163: Changed `e.target().unwrap().value()` to `e.target_unchecked_into::<web_sys::HtmlInputElement>().value()`
- Lines 171-173: Added `Event` type annotation to `onchange` closure parameter
- Lines 171-173: Changed `e.target().unwrap().value()` to `e.target_unchecked_into::<web_sys::HtmlInputElement>().value()`
- Line 170: Changed `value={self.issue_tier}` to `value={self.issue_tier.to_string()}`

## Acceptance Results

```
cargo check -p admin-ui          → 0 errors, 48 warnings
cargo check --workspace --all-targets → 3 pre-existing errors in other crates:
  - synvoid-ipc: missing tempfile (test only)
  - synvoid-config: missing sha2/tempfile (test only)
  - myapp-dynamic: cannot move out of shared reference
```

All admin-ui compile errors are resolved. Pre-existing workspace errors are in unrelated crates (synvoid-ipc, synvoid-config, myapp-dynamic) and are outside SDC scope.
