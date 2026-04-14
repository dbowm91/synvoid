use std::net::IpAddr;

use async_trait::async_trait;

use super::resolver::{
    CNameRecord, DnsResolver, HickoryResolver, MxRecord, NsRecord, PtrRecord, ResolverError,
    ResolverResult, SoaRecord, SrvRecord, TxtRecord,
};

pub struct GlobalNodeResolver {
    primary: Option<HickoryResolver>,
    fallback: HickoryResolver,
    global_node_ips: Vec<IpAddr>,
}

impl GlobalNodeResolver {
    pub fn new(global_node_ips: Vec<IpAddr>) -> Result<Self, ResolverError> {
        let fallback = HickoryResolver::from_system_config()?;

        let primary = if !global_node_ips.is_empty() {
            match HickoryResolver::with_upstream_servers(&global_node_ips) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(
                        "Failed to create global node resolver with {} nodes: {}, using fallback only",
                        global_node_ips.len(),
                        e
                    );
                    None
                }
            }
        } else {
            tracing::info!("No global nodes available, using system DNS fallback");
            None
        };

        Ok(Self {
            primary,
            fallback,
            global_node_ips,
        })
    }

    pub fn global_node_count(&self) -> usize {
        self.global_node_ips.len()
    }

    fn resolver(&self) -> &HickoryResolver {
        self.primary.as_ref().unwrap_or(&self.fallback)
    }
}

impl Clone for GlobalNodeResolver {
    fn clone(&self) -> Self {
        Self {
            primary: self.primary.clone(),
            fallback: self.fallback.clone(),
            global_node_ips: self.global_node_ips.clone(),
        }
    }
}

#[async_trait]
impl DnsResolver for GlobalNodeResolver {
    async fn lookup_txt(&self, name: &str) -> ResolverResult<TxtRecord> {
        match self.resolver().lookup_txt(name).await {
            Ok(r) => Ok(r),
            Err(_) if self.primary.is_some() => self.fallback.lookup_txt(name).await,
            Err(e) => Err(e),
        }
    }

    async fn lookup_ns(&self, name: &str) -> ResolverResult<NsRecord> {
        match self.resolver().lookup_ns(name).await {
            Ok(r) => Ok(r),
            Err(_) if self.primary.is_some() => self.fallback.lookup_ns(name).await,
            Err(e) => Err(e),
        }
    }

    async fn lookup_a(&self, name: &str) -> ResolverResult<Vec<IpAddr>> {
        match self.resolver().lookup_a(name).await {
            Ok(r) => Ok(r),
            Err(_) if self.primary.is_some() => self.fallback.lookup_a(name).await,
            Err(e) => Err(e),
        }
    }

    async fn lookup_ip_with_ttl(&self, name: &str) -> ResolverResult<super::resolver::IpRecord> {
        match self.resolver().lookup_ip_with_ttl(name).await {
            Ok(r) => Ok(r),
            Err(_) if self.primary.is_some() => self.fallback.lookup_ip_with_ttl(name).await,
            Err(e) => Err(e),
        }
    }

    async fn lookup_mx(&self, name: &str) -> ResolverResult<Vec<MxRecord>> {
        match self.resolver().lookup_mx(name).await {
            Ok(r) => Ok(r),
            Err(_) if self.primary.is_some() => self.fallback.lookup_mx(name).await,
            Err(e) => Err(e),
        }
    }

    async fn lookup_soa(&self, name: &str) -> ResolverResult<Option<SoaRecord>> {
        match self.resolver().lookup_soa(name).await {
            Ok(r) => Ok(r),
            Err(_) if self.primary.is_some() => self.fallback.lookup_soa(name).await,
            Err(e) => Err(e),
        }
    }

    async fn lookup_ptr(&self, name: &str) -> ResolverResult<Option<PtrRecord>> {
        match self.resolver().lookup_ptr(name).await {
            Ok(r) => Ok(r),
            Err(_) if self.primary.is_some() => self.fallback.lookup_ptr(name).await,
            Err(e) => Err(e),
        }
    }

    async fn lookup_srv(&self, name: &str) -> ResolverResult<Vec<SrvRecord>> {
        match self.resolver().lookup_srv(name).await {
            Ok(r) => Ok(r),
            Err(_) if self.primary.is_some() => self.fallback.lookup_srv(name).await,
            Err(e) => Err(e),
        }
    }

    async fn lookup_cname(&self, name: &str) -> ResolverResult<Option<CNameRecord>> {
        match self.resolver().lookup_cname(name).await {
            Ok(r) => Ok(r),
            Err(_) if self.primary.is_some() => self.fallback.lookup_cname(name).await,
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_node_resolver_no_nodes() {
        let resolver = GlobalNodeResolver::new(vec![]).unwrap();
        assert_eq!(resolver.global_node_count(), 0);
        assert!(resolver.primary.is_none());
    }

    #[test]
    fn test_global_node_resolver_with_nodes() {
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        let resolver = GlobalNodeResolver::new(ips).unwrap();
        assert_eq!(resolver.global_node_count(), 2);
        assert!(resolver.primary.is_some());
    }

    #[test]
    fn test_global_node_resolver_clone() {
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let resolver = GlobalNodeResolver::new(ips).unwrap();
        let cloned = resolver.clone();
        assert_eq!(cloned.global_node_count(), 1);
    }
}
