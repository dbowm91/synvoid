use hickory_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig};
use hickory_resolver::TokioResolver;
use std::net::IpAddr;
fn main() {
    let ips: Vec<IpAddr> = vec![];
    let name_servers = ips.iter().map(|ip| NameServerConfig::udp_and_tcp(*ip)).collect();
    let config = ResolverConfig::from_parts(None, vec![], name_servers);
    let _ = TokioResolver::tokio(config, ResolverOpts::default());
}
