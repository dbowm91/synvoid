//! Dedicated YARA jail child binary (Phase 29).
//!
//! Links only the YARA engine (`yara` feature); it does not link the WASM
//! runtime or unrelated HTTP/mesh/admin stacks. Parent processes spawn this
//! binary with piped stdio and no payload argv; stdout carries only
//! length-delimited frames, stderr carries logs.

fn main() {
    synvoid_jail_runtime::init_jail_logging_stderr();
    let mut args = std::env::args().skip(1);
    if let Some(first) = args.next() {
        if first == "--version" || first == "-V" {
            eprintln!(
                "synvoid-yara-jail {} (protocol v{})",
                synvoid_jail_runtime::JAIL_RUNTIME_VERSION,
                synvoid_ipc::JAIL_PROTOCOL_VERSION
            );
            std::process::exit(0);
        }
        if first == "--help" || first == "-h" {
            eprintln!(
                "synvoid-yara-jail {}: supervised YARA jail child (piped stdio, framed IPC on stdout, logs on stderr)",
                synvoid_jail_runtime::JAIL_RUNTIME_VERSION
            );
            std::process::exit(0);
        }
        let ok = first == "yara" || first == "--kind=yara" || first == "--kind";
        if !ok {
            if first != "--kind" {
                eprintln!("synvoid-yara-jail: unexpected argument (refusing)");
                std::process::exit(1);
            }
            match args.next().as_deref() {
                Some("yara") => {}
                _ => {
                    eprintln!("synvoid-yara-jail: --kind must be `yara`");
                    std::process::exit(1);
                }
            }
        } else if first == "--kind" {
            match args.next().as_deref() {
                Some("yara") => {}
                _ => {
                    eprintln!("synvoid-yara-jail: --kind must be `yara`");
                    std::process::exit(1);
                }
            }
        }
        if args.next().is_some() {
            eprintln!("synvoid-yara-jail: unexpected extra arguments (refusing)");
            std::process::exit(1);
        }
    }
    synvoid_jail_runtime::run_yara_jail_main();
}
