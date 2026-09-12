//! Dedicated WASM jail child binary (Phase 29).
//!
//! Links only the WASM engine (`wasm` feature); it does not link YARA.
//! Parent processes spawn this binary with piped stdio and no payload argv;
//! stdout carries only length-delimited frames, stderr carries logs.
//! An optional `--kind wasm` argument is accepted for explicitness and
//! rejected when mismatched; no other arguments are accepted.

fn main() {
    synvoid_jail_runtime::init_jail_logging_stderr();
    let mut args = std::env::args().skip(1);
    if let Some(first) = args.next() {
        // Diagnostics: version/help report jail runtime identity without
        // touching stdout framing (parent spawns with empty argv).
        if first == "--version" || first == "-V" {
            eprintln!(
                "synvoid-wasm-jail {} (protocol v{})",
                synvoid_jail_runtime::JAIL_RUNTIME_VERSION,
                synvoid_ipc::JAIL_PROTOCOL_VERSION
            );
            std::process::exit(0);
        }
        if first == "--help" || first == "-h" {
            eprintln!(
                "synvoid-wasm-jail {}: supervised WASM jail child (piped stdio, framed IPC on stdout, logs on stderr)",
                synvoid_jail_runtime::JAIL_RUNTIME_VERSION
            );
            std::process::exit(0);
        }
        // Accept explicit `--kind wasm` / `wasm` for supervisor clarity;
        // reject anything else (no payloads/secrets in argv, ever).
        let ok = first == "wasm" || first == "--kind=wasm" || first == "--kind";
        if !ok {
            // Support `--kind wasm` two-word form.
            if first != "--kind" {
                eprintln!("synvoid-wasm-jail: unexpected argument (refusing)");
                std::process::exit(1);
            }
            match args.next().as_deref() {
                Some("wasm") => {}
                _ => {
                    eprintln!("synvoid-wasm-jail: --kind must be `wasm`");
                    std::process::exit(1);
                }
            }
        } else if first == "--kind" {
            match args.next().as_deref() {
                Some("wasm") => {}
                _ => {
                    eprintln!("synvoid-wasm-jail: --kind must be `wasm`");
                    std::process::exit(1);
                }
            }
        }
        if args.next().is_some() {
            eprintln!("synvoid-wasm-jail: unexpected extra arguments (refusing)");
            std::process::exit(1);
        }
    }
    synvoid_jail_runtime::run_wasm_jail_main();
}
