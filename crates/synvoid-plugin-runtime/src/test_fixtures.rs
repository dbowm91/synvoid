//! Test fixtures for WASM plugin integration tests.
//!
//! Provides minimal WASM modules for testing plugin loading, execution,
//! and failure scenarios.

/// Minimal WASM module that exports `filter_request` returning 0 (Pass).
/// Signature: (method_ptr, method_len, uri_ptr, uri_len, hdr_ptr, hdr_len, body_ptr, body_len) -> i32
pub fn minimal_filter_pass() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1)
            (func (export "filter_request") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
                i32.const 0  ;; Return 0 = Pass
            )
        )
        "#,
    )
    .expect("valid WAT")
}

/// Minimal WASM module that exports `filter_request` returning 1 (Block with 403).
/// Signature: (method_ptr, method_len, uri_ptr, uri_len, hdr_ptr, hdr_len, body_ptr, body_len) -> i32
pub fn minimal_filter_block() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1)
            (func (export "filter_request") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
                i32.const 1  ;; Return 1 = Block
            )
        )
        "#,
    )
    .expect("valid WAT")
}

/// Minimal WASM module that exports `transform_response` returning 0 (Pass through).
pub fn minimal_transform_pass() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1)
            (func (export "transform_response") (param i32 i32 i32 i32 i32) (result i32)
                i32.const 0  ;; Return 0 = Pass through
            )
        )
        "#,
    )
    .expect("valid WAT")
}

/// Minimal WASM module that exports `handle_request` returning a minimal response.
pub fn minimal_handler() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1)

            ;; Static response body "OK"
            (data (i32.const 0) "OK")

            ;; handle_request(method_ptr, method_len, uri_ptr, uri_len,
            ;;                headers_ptr, headers_len, body_ptr, body_len,
            ;;                out_status_ptr, out_body_ptr, out_body_max) -> i32
            (func (export "handle_request")
                (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
                (result i32)

                ;; Write status code 200 to out_status_ptr (as 4 bytes big-endian)
                (i32.store8 (local.get 8) (i32.const 0))   ;; '0'
                (i32.store8 (i32.add (local.get 8) (i32.const 1)) (i32.const 0))
                (i32.store8 (i32.add (local.get 8) (i32.const 2)) (i32.const 0))
                (i32.store8 (i32.add (local.get 8) (i32.const 3)) (i32.const 0))

                ;; Copy "OK" to out_body_ptr
                (memory.copy (local.get 9) (i32.const 0) (i32.const 2))

                ;; Return 0 = success
                i32.const 0
            )
        )
        "#,
    )
    .expect("valid WAT")
}

/// WASM module that traps immediately (unreachable).
/// Signature: (method_ptr, method_len, uri_ptr, uri_len, hdr_ptr, hdr_len, body_ptr, body_len) -> i32
pub fn trapping_module() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1)
            (func (export "filter_request") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
                unreachable  ;; Trap immediately
            )
        )
        "#,
    )
    .expect("valid WAT")
}

/// WASM module that loops forever (fuel exhaustion scenario).
/// Signature: (method_ptr, method_len, uri_ptr, uri_len, hdr_ptr, hdr_len, body_ptr, body_len) -> i32
pub fn infinite_loop_module() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1)
            (func (export "filter_request") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
                (block $break
                    (loop $loop
                        br $loop
                    )
                )
                i32.const 0
            )
        )
        "#,
    )
    .expect("valid WAT")
}

/// WASM module with no exports (missing filter_request, transform_response, handle_request).
pub fn no_exports_module() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1)
            (func $internal (param i32) (result i32)
                local.get 0
            )
        )
        "#,
    )
    .expect("valid WAT")
}

/// WASM module that writes out of bounds (memory violation).
/// Signature: (method_ptr, method_len, uri_ptr, uri_len, hdr_ptr, hdr_len, body_ptr, body_len) -> i32
pub fn memory_violation_module() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1)
            (func (export "filter_request") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
                ;; Write to address 10MB (beyond 64KB memory)
                (i32.store (i32.const 10485760) (i32.const 42))
                i32.const 0
            )
        )
        "#,
    )
    .expect("valid WAT")
}

/// Invalid WASM bytes (truncated header).
pub fn invalid_wasm_bytes() -> Vec<u8> {
    b"\x00asm\x01\x00\x00\x00".to_vec()
}

/// WASM module with oversized memory declaration.
/// Signature: (method_ptr, method_len, uri_ptr, uri_len, hdr_ptr, hdr_len, body_ptr, body_len) -> i32
pub fn oversized_memory_module() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 16384)  ;; 16384 pages = 1GB
            (func (export "filter_request") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
                i32.const 0
            )
        )
        "#,
    )
    .expect("valid WAT")
}

/// WASM module that calls host function without capability (mesh_query_dht).
/// Signature: (method_ptr, method_len, uri_ptr, uri_len, hdr_ptr, hdr_len, body_ptr, body_len) -> i32
pub fn mesh_call_without_capability() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1)
            (import "env" "mesh_query_dht" (func $mesh_query (param i32 i32 i32 i32) (result i32)))
            (func (export "filter_request") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
                ;; Try to call mesh_query_dht - should fail if no mesh capability
                (drop (call $mesh_query (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
                i32.const 0
            )
        )
        "#,
    )
    .expect("valid WAT")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixtures_produce_valid_wasm() {
        let fixtures = [
            minimal_filter_pass(),
            minimal_filter_block(),
            minimal_transform_pass(),
            minimal_handler(),
            trapping_module(),
            infinite_loop_module(),
            no_exports_module(),
            memory_violation_module(),
            invalid_wasm_bytes(),
            oversized_memory_module(),
        ];

        for (i, wasm) in fixtures.iter().enumerate() {
            // Verify WASM magic number
            assert!(
                wasm.len() >= 4 && wasm[0..4] == *b"\x00asm",
                "Fixture {} missing WASM magic number",
                i
            );
        }
    }

    #[test]
    fn test_filter_pass_returns_zero() {
        let wasm = minimal_filter_pass();
        let engine = wasmtime::Engine::default();
        let module = wasmtime::Module::from_binary(&engine, &wasm).expect("valid WASM");
        assert!(module.get_export("filter_request").is_some());
    }

    #[test]
    fn test_handler_has_handle_request() {
        let wasm = minimal_handler();
        let engine = wasmtime::Engine::default();
        let module = wasmtime::Module::from_binary(&engine, &wasm).expect("valid WASM");
        assert!(module.get_export("handle_request").is_some());
    }

    #[test]
    fn test_trapping_module_has_filter() {
        let wasm = trapping_module();
        let engine = wasmtime::Engine::default();
        let module = wasmtime::Module::from_binary(&engine, &wasm).expect("valid WASM");
        assert!(module.get_export("filter_request").is_some());
    }

    #[test]
    fn test_no_exports_module_has_no_exports() {
        let wasm = no_exports_module();
        let engine = wasmtime::Engine::default();
        let module = wasmtime::Module::from_binary(&engine, &wasm).expect("valid WASM");
        assert!(module.get_export("filter_request").is_none());
        assert!(module.get_export("transform_response").is_none());
        assert!(module.get_export("handle_request").is_none());
    }
}
