mod affected;
mod lanes;
mod report;
mod test;

use std::process;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect(); // skip binary name

    let dry_run = args.contains(&"--dry-run".to_string());
    let json_output = args.contains(&"--json".to_string());
    let verbose = args.contains(&"--verbose".to_string());

    let positional: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
        .collect();

    let flag_args: Vec<&str> = args
        .iter()
        .filter(|a| a.starts_with('-'))
        .map(|s| s.as_str())
        .collect();

    let result = match positional.first().copied() {
        Some("test") => test::dispatch(&positional[1..], &flag_args, dry_run, json_output, verbose),
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

fn print_usage() {
    println!(
        "\
cargo xtask — SynVoid build task runner

USAGE:
    cargo xtask test <lane> [options]

TEST LANES:
    fast            Format, clippy, guards, security, core compile, affected domain tests
    affected        Affected package selection and testing (--base <ref>)
    package <name>  Test a specific package
    guards          Run all guard tests
    security        Run security regression tests
    comprehensive   Full workspace validation
    nightly-plan    Print what nightly qualification would run
    qualification   Print what release qualification would run
    release         Print what release validation would run
    list            List all available lanes and their commands
    explain <lane>  Explain what a lane does

OPTIONS:
    --dry-run       Print commands without executing
    --json          Machine-readable JSON output
    --verbose       Detailed output for each command
    -h, --help      Show this help message"
    );
}
