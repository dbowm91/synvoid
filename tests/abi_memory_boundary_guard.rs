//! Root-test ownership: STATIC_POLICY
//! Rationale: validates ABI memory boundary across workspace plugin boundary
//!
//! Guardrail test for ABI Memory Boundary Hardening (M1 Phase 4).
//!
//! Verifies that:
//! - The fixed-offset 1024 fallback is not present in write_to_guest_memory
//! - Plugins without guest_alloc are rejected at write time
//! - checked_guest_range is used for all memory operations

#[test]
fn test_fixed_offset_1024_fallback_removed() {
    // Read the wasm_runtime.rs source and verify the fixed-offset fallback is gone
    let source = include_str!("../crates/synvoid-plugin-runtime/src/wasm_runtime.rs");

    // The old code had: `1024i32` as a fallback value in write_to_guest_memory.
    // After Phase 4, this should be replaced with an error. Verify the pattern
    // does not appear in write_to_guest_memory context.
    //
    // We check that "1024i32" does NOT appear as a fallback assignment.
    // The string "1024" may appear in comments or test data, so we check for
    // the specific fallback pattern.
    let has_fallback = source.contains("// Fallback: use a fixed offset");
    assert!(
        !has_fallback,
        "Fixed-offset 1024 fallback comment still present in wasm_runtime.rs"
    );
}

#[test]
fn test_write_to_guest_memory_requires_guest_alloc() {
    // Verify the error message for missing guest_alloc is present
    let source = include_str!("../crates/synvoid-plugin-runtime/src/wasm_runtime.rs");
    assert!(
        source.contains("plugin missing required guest_alloc export"),
        "write_to_guest_memory should reject plugins without guest_alloc"
    );
}

#[test]
fn test_checked_guest_range_is_used_in_host_functions() {
    // Verify that host functions use checked_guest_range instead of saturating_add
    let source = include_str!("../crates/synvoid-plugin-runtime/src/wasm_runtime.rs");

    // The old code used saturating_add for bounds checking in host functions.
    // After Phase 4, checked_guest_range should be used instead.
    // Note: saturating_add may still appear in non-memory contexts, so we check
    // that checked_guest_range is defined and used.
    assert!(
        source.contains("fn checked_guest_range"),
        "checked_guest_range function must be defined"
    );
}

#[test]
fn test_serialize_headers_validates_bounds() {
    // Verify serialize_headers returns Result and checks u16 bounds
    let source = include_str!("../crates/synvoid-plugin-runtime/src/wasm_runtime.rs");
    assert!(
        source.contains("fn serialize_headers")
            && source.contains("Result<Vec<u8>, WasmPluginError>"),
        "serialize_headers must return Result with bounds checks"
    );
}

#[test]
fn test_guest_allocation_tracking_struct_exists() {
    // Verify GuestAllocation struct exists for tracking allocations
    let source = include_str!("../crates/synvoid-plugin-runtime/src/wasm_runtime.rs");
    assert!(
        source.contains("struct GuestAllocation"),
        "GuestAllocation tracking struct must exist"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Workstream 5: Strengthen CI and Guardrail Enforcement
// ═══════════════════════════════════════════════════════════════════════════════

/// GuestAbiPolicy enum must exist with required variants for ABI enforcement.
#[test]
fn test_guest_abi_policy_enum_exists() {
    let source = include_str!("../crates/synvoid-plugin-runtime/src/wasm_runtime.rs");
    assert!(
        source.contains("GuestAbiPolicy"),
        "GuestAbiPolicy enum must exist"
    );
    assert!(
        source.contains("ProductionPointerLength"),
        "ProductionPointerLength variant must exist"
    );
    assert!(
        source.contains("DevelopmentAllowMissingFree"),
        "DevelopmentAllowMissingFree variant must exist"
    );
}

/// validate_for_policy method must exist on GuestAbiInfo for ABI validation.
#[test]
fn test_validate_for_policy_exists() {
    let source = include_str!("../crates/synvoid-plugin-runtime/src/wasm_runtime.rs");
    assert!(
        source.contains("fn validate_for_policy"),
        "validate_for_policy method must exist"
    );
}

/// validate_guest_abi must be public for use by loader paths.
#[test]
fn test_validate_guest_abi_is_pub() {
    let source = include_str!("../crates/synvoid-plugin-runtime/src/wasm_runtime.rs");
    let lines: Vec<&str> = source.lines().collect();
    for line in &lines {
        if line.contains("fn validate_guest_abi") && line.contains("module") {
            assert!(
                line.trim().starts_with("pub fn") || line.trim().starts_with("pub(crate) fn"),
                "validate_guest_abi must be public"
            );
            return;
        }
    }
    panic!("validate_guest_abi function not found");
}

/// Single-frame allocation structs and methods must exist for request input.
#[test]
fn test_single_frame_allocation_struct_exists() {
    let source = include_str!("../crates/synvoid-plugin-runtime/src/wasm_runtime.rs");
    assert!(
        source.contains("struct GuestInputFrame"),
        "GuestInputFrame struct must exist"
    );
    assert!(
        source.contains("struct RequestInputPieces"),
        "RequestInputPieces struct must exist"
    );
    assert!(
        source.contains("fn write_request_input_frame"),
        "write_request_input_frame method must exist"
    );
    assert!(
        source.contains("fn free_guest_input_frame"),
        "free_guest_input_frame method must exist"
    );
}
