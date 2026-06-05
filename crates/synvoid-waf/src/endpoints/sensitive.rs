use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;

pub struct SensitiveEndpoint {
    exact_matches: HashSet<String>,
    prefix_matches: Vec<String>,
    path_prefix_matches: Vec<String>,
}

#[derive(Clone)]
pub struct SensitiveEndpointManager {
    inner: Arc<RwLock<SensitiveEndpoint>>,
}

impl SensitiveEndpointManager {
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Self {
        let paths = match std::fs::read_to_string(path) {
            Ok(content) => content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect(),
            Err(e) => {
                tracing::warn!("Failed to load honeypot endpoints file: {}", e);
                Vec::new()
            }
        };

        Self::new(paths)
    }

    pub fn new(paths: Vec<String>) -> Self {
        let mut exact_matches = HashSet::new();
        let mut prefix_matches = Vec::new();
        let mut path_prefix_matches = Vec::new();

        for p in paths {
            if p.ends_with("/*") {
                path_prefix_matches.push(p.trim_end_matches("/*").to_string());
            } else if p.contains('*') {
                prefix_matches.push(p.trim_end_matches('*').to_string());
            } else {
                exact_matches.insert(p);
            }
        }

        SensitiveEndpointManager {
            inner: Arc::new(RwLock::new(SensitiveEndpoint {
                exact_matches,
                prefix_matches,
                path_prefix_matches,
            })),
        }
    }

    pub fn check(&self, path: &str) -> Option<String> {
        let guard = self.inner.read();

        if let Some(exact) = guard.exact_matches.get(path) {
            return Some(exact.clone());
        }

        for prefix in &guard.prefix_matches {
            if path.starts_with(prefix) {
                return Some(prefix.clone());
            }
        }

        for path_prefix in &guard.path_prefix_matches {
            if path.starts_with(&format!("{}/", path_prefix)) {
                return Some(format!("{}/*", path_prefix));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_endpoint_exact_match() {
        let manager = SensitiveEndpointManager::new(vec![
            "/admin".to_string(),
            "/.env".to_string(),
            "/wp-login.php".to_string(),
        ]);
        assert_eq!(manager.check("/admin"), Some("/admin".to_string()));
        assert_eq!(manager.check("/.env"), Some("/.env".to_string()));
        assert_eq!(
            manager.check("/wp-login.php"),
            Some("/wp-login.php".to_string())
        );
        assert_eq!(manager.check("/admin/users"), None);
        assert_eq!(manager.check("/public"), None);
    }

    #[test]
    fn test_sensitive_endpoint_prefix_match() {
        let manager =
            SensitiveEndpointManager::new(vec!["/api/v1*".to_string(), "/debug*".to_string()]);
        assert_eq!(manager.check("/api/v1/users"), Some("/api/v1".to_string()));
        assert_eq!(manager.check("/api/v1/config"), Some("/api/v1".to_string()));
        assert_eq!(manager.check("/debuginfo"), Some("/debug".to_string()));
        assert_eq!(manager.check("/api/v2/users"), None);
    }

    #[test]
    fn test_sensitive_endpoint_path_prefix_match() {
        let manager =
            SensitiveEndpointManager::new(vec!["/admin/*".to_string(), "/internal/*".to_string()]);
        assert_eq!(
            manager.check("/admin/dashboard"),
            Some("/admin/*".to_string())
        );
        assert_eq!(
            manager.check("/internal/metrics"),
            Some("/internal/*".to_string())
        );
        assert_eq!(manager.check("/adminx"), None);
        assert_eq!(manager.check("/admin"), None);
    }
}
