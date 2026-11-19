use std::net::IpAddr;

use async_trait::async_trait;

use super::resolver::{
    CNameRecord, DnsResolver, HickoryResolver, MxRecord, NsRecord, PtrRecord, ResolverError,
    ResolverResult, SoaRecord, SrvRecord, TxtRecord, UpstreamRrset,
};

/// Forwarder that sends queries to mesh-provided global nodes.
///
/// There is no fallback resolver: an operator who wants the host resolver
/// configuration selects `upstream_provider = System` explicitly, so a mesh
/// upstream that fails stays a visible failure instead of silently becoming a
/// query to an unrelated server.
pub struct GlobalNodeResolver {
    primary: HickoryResolver,
    global_node_ips: Vec<IpAddr>,
}

impl GlobalNodeResolver {
    pub fn new(global_node_ips: Vec<IpAddr>) -> Result<Self, ResolverError> {
        if global_node_ips.is_empty() {
            return Err(ResolverError::QueryFailed(
                "no global node upstreams are configured; refusing to fall back to the system \
                 resolver (select upstream_provider = System for that)"
                    .to_string(),
            ));
        }

        let primary = HickoryResolver::with_upstream_servers(&global_node_ips, 5)?;

        Ok(Self {
            primary,
            global_node_ips,
        })
    }

    pub fn global_node_count(&self) -> usize {
        self.global_node_ips.len()
    }
}

impl Clone for GlobalNodeResolver {
    fn clone(&self) -> Self {
        Self {
            primary: self.primary.clone(),
            global_node_ips: self.global_node_ips.clone(),
        }
    }
}

#[async_trait]
impl DnsResolver for GlobalNodeResolver {
    async fn lookup_txt(&self, name: &str) -> ResolverResult<TxtRecord> {
        self.primary.lookup_txt(name).await
    }

    async fn lookup_ns(&self, name: &str) -> ResolverResult<NsRecord> {
        self.primary.lookup_ns(name).await
    }

    async fn lookup_a(&self, name: &str) -> ResolverResult<Vec<IpAddr>> {
        self.primary.lookup_a(name).await
    }

    async fn lookup_ip_with_ttl(&self, name: &str) -> ResolverResult<super::resolver::IpRecord> {
        self.primary.lookup_ip_with_ttl(name).await
    }

    async fn lookup_mx(&self, name: &str) -> ResolverResult<Vec<MxRecord>> {
        self.primary.lookup_mx(name).await
    }

    async fn lookup_soa(&self, name: &str) -> ResolverResult<Option<SoaRecord>> {
        self.primary.lookup_soa(name).await
    }

    async fn lookup_ptr(&self, name: &str) -> ResolverResult<Option<PtrRecord>> {
        self.primary.lookup_ptr(name).await
    }

    async fn lookup_srv(&self, name: &str) -> ResolverResult<Vec<SrvRecord>> {
        self.primary.lookup_srv(name).await
    }

    async fn lookup_cname(&self, name: &str) -> ResolverResult<Option<CNameRecord>> {
        self.primary.lookup_cname(name).await
    }

    async fn lookup_rrset(&self, name: &str, record_type: u16) -> ResolverResult<UpstreamRrset> {
        self.primary.lookup_rrset(name, record_type).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_node_resolver_no_nodes() {
        // An empty node list is an error, not a silent system fallback.
        let error = match GlobalNodeResolver::new(vec![]) {
            Ok(_) => panic!("empty upstream list must fail"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("no global node upstreams"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_global_node_resolver_with_nodes() {
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        let resolver = GlobalNodeResolver::new(ips).unwrap();
        assert_eq!(resolver.global_node_count(), 2);
    }

    #[test]
    fn test_global_node_resolver_clone() {
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let resolver = GlobalNodeResolver::new(ips).unwrap();
        let cloned = resolver.clone();
        assert_eq!(cloned.global_node_count(), 1);
    }
}
