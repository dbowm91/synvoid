use clap::Parser;
use synvoid_cli::Args;

fn main() {
    // Select the rustls crypto provider once, before any process touches TLS.
    // Several rustls builders (including `WebPkiClientVerifier::builder`) fall
    // back to the process default; when more than one provider feature is in
    // the dependency graph that resolution panics instead of choosing, which
    // killed the unified worker the first time a mesh peer certificate was
    // verified.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let args = Args::parse();

    let plan = match synvoid::commands::plan_command(&args) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let exit_code = synvoid::commands::execute_command(plan);
    std::process::exit(exit_code);
}
