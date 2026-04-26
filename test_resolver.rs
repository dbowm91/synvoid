use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioResolver;
fn main() {
    let _ = TokioResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
}
