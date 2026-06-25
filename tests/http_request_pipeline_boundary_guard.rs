//! HTTP request pipeline boundary guard.
//!
//! Enforces that HTTP request dispatch code does not import worker lifecycle state.
//! HTTP/3 and HTTP/1.x request paths consume context structs and narrow capabilities,
//! not worker startup, supervision, or shutdown modules.

fn workspace_root() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let cargo_toml = path.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = std::fs::read_to_string(&cargo_toml).unwrap_or_default();
            if content.contains("[workspace]") {
                return path;
            }
        }
        if !path.pop() {
            break;
        }
    }
    panic!("Could not find workspace root");
}

fn strip_comments(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '/' if chars.peek() == Some(&'/') => {
                while let Some(&next) = chars.peek() {
                    if next == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut depth = 1;
                while depth > 0 {
                    match chars.next() {
                        Some('/') if chars.peek() == Some(&'*') => {
                            chars.next();
                            depth += 1;
                        }
                        Some('*') if chars.peek() == Some(&'/') => {
                            chars.next();
                            depth -= 1;
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            }
            '"' => {
                result.push(ch);
                loop {
                    match chars.next() {
                        Some('\\') => {
                            result.push('\\');
                            if let Some(c) = chars.next() {
                                result.push(c);
                            }
                        }
                        Some('"') => {
                            result.push('"');
                            break;
                        }
                        Some(c) => result.push(c),
                        None => break,
                    }
                }
            }
            _ => result.push(ch),
        }
    }
    result
}

const FORBIDDEN_WORKER_LIFECYCLE_TOKENS: &[&str] = &[
    "UnifiedServerWorkerState",
    "startup_plan",
    "supervision_loop",
    "shutdown_executor",
    "WorkerTaskRegistry",
    "WorkerShutdownCause",
];

fn assert_no_worker_lifecycle_imports(source: &str, file_label: &str) {
    let stripped = strip_comments(source);
    let mut violations = Vec::new();
    for token in FORBIDDEN_WORKER_LIFECYCLE_TOKENS {
        if stripped.contains(token) {
            violations.push(token.to_string());
        }
    }
    if !violations.is_empty() {
        let mut msg = format!("{} imports worker lifecycle modules:\n\n", file_label);
        for token in &violations {
            msg.push_str(&format!("  {}\n", token));
        }
        msg.push_str(
            "\nHTTP request dispatch code must consume context structs and narrow capabilities,\n\
             not worker startup, supervision, or shutdown modules.",
        );
        panic!("{}", msg);
    }
}

#[test]
fn http3_dispatch_must_not_import_worker_lifecycle_modules() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("crates/synvoid-http/src/http3_request_dispatch.rs"))
            .expect("failed to read http3_request_dispatch.rs");
    assert_no_worker_lifecycle_imports(&source, "http3_request_dispatch.rs");
}

#[test]
fn http1_request_flow_must_not_import_worker_lifecycle_modules() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("crates/synvoid-http/src/http_request_flow.rs"))
        .expect("failed to read http_request_flow.rs");
    assert_no_worker_lifecycle_imports(&source, "http_request_flow.rs");
}

#[test]
fn http3_dispatch_uses_context_structs() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("crates/synvoid-http/src/http3_request_dispatch.rs"))
            .expect("failed to read http3_request_dispatch.rs");
    let stripped = strip_comments(&source);

    let missing = ["Http3RequestMetadata", "Http3DispatchDeps"];
    let mut absent = Vec::new();
    for token in &missing {
        if !stripped.contains(token) {
            absent.push(token.to_string());
        }
    }
    if !absent.is_empty() {
        let mut msg = String::from(
            "http3_request_dispatch.rs is missing expected context struct references:\n\n",
        );
        for token in &absent {
            msg.push_str(&format!("  {}\n", token));
        }
        msg.push_str(
            "\nHTTP/3 dispatch must use Http3RequestMetadata and Http3DispatchDeps context structs.",
        );
        panic!("{}", msg);
    }
}

#[test]
fn request_pipeline_stage_vocabulary_is_documented() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("architecture/http_request_pipeline.md"))
        .expect("failed to read http_request_pipeline.md");

    let required_words = [
        "metadata",
        "route",
        "body",
        "WAF",
        "terminal",
        "upstream",
        "accounting",
    ];
    let mut missing = Vec::new();
    for word in &required_words {
        if !source.contains(word) {
            missing.push(word.to_string());
        }
    }
    if !missing.is_empty() {
        let mut msg = String::from(
            "architecture/http_request_pipeline.md is missing required pipeline stage vocabulary:\n\n",
        );
        for word in &missing {
            msg.push_str(&format!("  {}\n", word));
        }
        msg.push_str(
            "\nThe architecture document must document all pipeline stages: metadata, route, body,\n\
             WAF, terminal, upstream, and accounting.",
        );
        panic!("{}", msg);
    }
}

#[test]
fn http3_dispatch_does_not_import_unified_server_worker_state() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("crates/synvoid-http/src/http3_request_dispatch.rs"))
            .expect("failed to read http3_request_dispatch.rs");
    let stripped = strip_comments(&source);
    assert!(
        !stripped.contains("UnifiedServerWorkerState"),
        "http3_request_dispatch.rs must not import UnifiedServerWorkerState"
    );
}

#[test]
fn http_request_flow_does_not_import_unified_server_worker_state() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("crates/synvoid-http/src/http_request_flow.rs"))
        .expect("failed to read http_request_flow.rs");
    let stripped = strip_comments(&source);
    assert!(
        !stripped.contains("UnifiedServerWorkerState"),
        "http_request_flow.rs must not import UnifiedServerWorkerState"
    );
}

#[test]
fn http_request_pipeline_doc_mentions_http3_dispatch_deps() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("architecture/http_request_pipeline.md"))
        .expect("failed to read http_request_pipeline.md");

    assert!(
        source.contains("Http3DispatchDeps"),
        "architecture/http_request_pipeline.md must document Http3DispatchDeps"
    );
    assert!(
        source.contains("Http3RequestMetadata"),
        "architecture/http_request_pipeline.md must document Http3RequestMetadata"
    );
}

#[test]
fn http_request_pipeline_doc_does_not_claim_http3_has_no_deps_struct() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("architecture/http_request_pipeline.md"))
        .expect("failed to read http_request_pipeline.md");

    let forbidden = [
        "There is no separate \"deps\" struct",
        "There is no separate 'deps' struct",
        "all dependencies are passed as function parameters to `handle_http3_request_dispatch()`",
    ];

    for phrase in forbidden {
        assert!(
            !source.contains(phrase),
            "architecture/http_request_pipeline.md contains stale HTTP/3 deps wording: {}",
            phrase
        );
    }
}

#[test]
fn http3_dispatch_signature_uses_context_structs() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("crates/synvoid-http/src/http3_request_dispatch.rs"))
            .expect("failed to read http3_request_dispatch.rs");
    let stripped = strip_comments(&source);

    let fn_start = stripped
        .find("pub async fn handle_http3_request_dispatch")
        .expect("handle_http3_request_dispatch should exist");
    let fn_prefix = &stripped[fn_start..stripped.len().min(fn_start + 600)];

    assert!(fn_prefix.contains("metadata: Http3RequestMetadata"));
    assert!(fn_prefix.contains("deps: Http3DispatchDeps"));
}
