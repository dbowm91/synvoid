use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use crate::http_client::{
    create_http_client_with_config, create_upstream_client, HttpClient, UpstreamTlsConfig,
};

pub struct UpstreamClientRegistry {
    clients: DashMap<String, Arc<HttpClient>>,
}

impl UpstreamClientRegistry {
    pub fn new() -> Self {
        Self {
            clients: DashMap::new(),
        }
    }

    pub fn get_or_create(
        &self,
        site_id: &str,
        tls_config: Option<&UpstreamTlsConfig>,
    ) -> Arc<HttpClient> {
        let client = self.clients.entry(site_id.to_string()).or_insert_with(|| {
            let client = if let Some(tls) = tls_config {
                create_upstream_client(Duration::from_secs(5), 100, Duration::from_secs(30), tls)
            } else {
                create_http_client_with_config(Duration::from_secs(5), 100, Duration::from_secs(30))
            };
            Arc::new(client)
        });
        Arc::clone(client.value())
    }

    pub fn invalidate(&self, site_id: &str) {
        self.clients.remove(site_id);
    }

    pub fn clear(&self) {
        self.clients.clear();
    }
}

impl Default for UpstreamClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}
