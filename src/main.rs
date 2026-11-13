use clap::Parser;
use synvoid_cli::Args;

fn main() {
    // Select the rustls crypto provider once, before any process touches TLS.
    // Delegated to the tls module: the dependency ledger only entitles rustls
    // to be consumed from there.
    synvoid::tls::install_process_crypto_provider();

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
