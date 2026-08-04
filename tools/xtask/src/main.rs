mod report;
mod verify;

use std::process;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let dry_run = args.contains(&"--dry-run".to_string());
    let json_output = args.contains(&"--json".to_string());
    let verbose = args.contains(&"--verbose".to_string());
    let allow_dirty = args.contains(&"--allow-dirty".to_string());

    let positional: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
        .collect();

    let result = match positional.first().copied() {
        Some("verify") => verify::run_verify(dry_run, json_output, verbose),
        Some("verify-full") => verify::run_verify_full(dry_run, json_output, verbose),
        Some("verify-release") => {
            verify::run_verify_release(dry_run, json_output, verbose, allow_dirty)
        }
        Some("test") => dispatch_test(&positional[1..], dry_run, json_output, verbose),
        Some("help") | Some("--help") | Some("-h") => {
            print_usage();
            Ok(())
        }
        Some(cmd) => {
            eprintln!("error: unknown command `{cmd}`");
            eprintln!("run `cargo xtask help` for usage");
            process::exit(1);
        }
        None => {
            print_usage();
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn dispatch_test(
    positional: &[&str],
    dry_run: bool,
    json_output: bool,
    verbose: bool,
) -> Result<(), String> {
    match positional.first().copied() {
        Some("package") => {
            let pkg = positional
                .get(1)
                .ok_or("usage: cargo xtask test package <name>")?;
            verify::run_package(pkg, dry_run, json_output, verbose)
        }
        Some("guards") => verify::run_guards(dry_run, json_output, verbose),
        Some(other) => Err(format!(
            "unknown test subcommand `{other}`. Available: package <name>, guards"
        )),
        None => Err("missing test subcommand. Available: package <name>, guards".to_string()),
    }
}

fn print_usage() {
    println!(
        "\
cargo xtask — SynVoid build task runner

USAGE:
    cargo xtask verify              Run the canonical routine verification contract
    cargo xtask verify-full         Run full local verification (broader than routine)
    cargo xtask verify-release      Run release verification (production artifacts)
    cargo xtask test package <name> Test a specific package
    cargo xtask test guards         Run all architectural guard tests

VERIFY (routine):
    Runs the single canonical routine verification contract (formatting, linting,
    compilation, guards, security regression). This is what CI runs on every PR.

VERIFY-FULL (manual):
    Broader than routine: format/lint preflight, feature profile compilation,
    broad deterministic workspace tests, and doctests. Does NOT re-run routine
    test binaries separately.

VERIFY-RELEASE (manual):
    Full verification plus release-profile compilation, all-features clippy,
    package metadata validation, package content inspection, and pre-publication
    package assembly. Fails on dirty tree by default. Does NOT publish.

OPTIONS:
    --dry-run       Print commands without executing
    --json          Machine-readable JSON output
    --verbose       Detailed output for each command
    --allow-dirty   Allow release verification on a dirty working tree
    -h, --help      Show this help message"
    );
}
