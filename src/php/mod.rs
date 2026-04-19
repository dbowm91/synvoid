#![allow(clippy::type_complexity)]

use std::path::PathBuf;
use std::sync::LazyLock;

use bytes::Bytes;
use http::{Method, Uri};

use crate::config::site::{FastCgiConfig, PhpConfig, PhpLocationConfig};

static COMMON_PHP_SOCKETS: LazyLock<Vec<PathBuf>> = LazyLock::new(|| {
    let mut paths = vec![
        PathBuf::from("/run/php/php-fpm.sock"),
        PathBuf::from("/var/run/php-fpm.sock"),
        PathBuf::from("/run/php-fpm.sock"),
        PathBuf::from("/var/run/php/php-fpm.sock"),
        PathBuf::from("/run/php/php8.4-fpm.sock"),
        PathBuf::from("/run/php/php8.3-fpm.sock"),
        PathBuf::from("/run/php/php8.2-fpm.sock"),
        PathBuf::from("/run/php/php8.1-fpm.sock"),
        PathBuf::from("/run/php/php8.0-fpm.sock"),
        PathBuf::from("/run/php/php7.4-fpm.sock"),
        PathBuf::from("/tmp/php-fpm.sock"),
        PathBuf::from("/run/php/php74-fpm.sock"),
        PathBuf::from("/run/php/php80-fpm.sock"),
        PathBuf::from("/run/php/php81-fpm.sock"),
        PathBuf::from("/run/php/php82-fpm.sock"),
        PathBuf::from("/run/php/php83-fpm.sock"),
    ];
    if let Ok(entries) = std::fs::read_dir("/run/php") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with("-fpm.sock") || name.ends_with("-fpm.sock.lock") {
                    if is_unix_socket(&path) && !name.ends_with(".lock") {
                        if !paths.contains(&path) {
                            paths.push(path);
                        }
                    }
                }
            }
        }
    }
    paths
});

fn is_unix_socket(path: &PathBuf) -> bool {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.mode();
        return mode & 0o140000 == 0o140000;
    }
    false
}

pub struct PhpClient {
    config: PhpConfig,
}

impl PhpClient {
    pub fn new(config: PhpConfig) -> Self {
        PhpClient { config }
    }

    fn auto_detect_socket(config: &PhpConfig) -> String {
        if let Some(ref socket) = config.socket {
            return socket.clone();
        }

        if let (Some(ref host), Some(port)) = (&config.host, config.port) {
            return format!("{}:{}", host, port);
        }

        if let Some(ref host) = config.host {
            return format!("{}:9000", host);
        }

        for socket_path in COMMON_PHP_SOCKETS.iter() {
            if socket_path.exists() {
                tracing::debug!("Auto-detected PHP-FPM socket: {}", socket_path.display());
                return socket_path.to_string_lossy().to_string();
            }
        }

        tracing::warn!(
            "Could not auto-detect PHP-FPM socket, falling back to /run/php/php-fpm.sock"
        );
        "/run/php/php-fpm.sock".to_string()
    }

    pub async fn execute(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<crate::fastcgi::FastCgiResponse, crate::fastcgi::FastCgiError> {
        let socket = Self::auto_detect_socket(&self.config);
        let fcgi_config = self.build_fcgi_config();
        let pool = crate::fastcgi::get_pool(&socket, &fcgi_config);
        pool.execute(method, uri, headers, body, &fcgi_config).await
    }

    pub async fn execute_status(
        &self,
        query: Option<&str>,
    ) -> Result<crate::fastcgi::FastCgiResponse, crate::fastcgi::FastCgiError> {
        let socket = Self::auto_detect_socket(&self.config);
        let status_path = self.config.pm_status_path.as_deref().unwrap_or("/status");

        let uri_path = if let Some(q) = query {
            format!("{}?{}", status_path, q)
        } else {
            status_path.to_string()
        };

        let uri: Uri = uri_path.parse().map_err(|_| {
            crate::fastcgi::FastCgiError::RequestFailed("Invalid status URI".to_string())
        })?;

        let method = Method::GET;
        let headers = http::HeaderMap::new();
        let body = Bytes::new();

        let mut fcgi_config = self.build_fcgi_config();
        let mut params = std::collections::HashMap::new();
        params.insert("SCRIPT_FILENAME".to_string(), status_path.to_string());
        params.insert("SCRIPT_NAME".to_string(), status_path.to_string());
        if let Some(ref existing) = fcgi_config.params {
            params.extend(existing.clone());
        }
        fcgi_config.params = Some(params);

        let pool = crate::fastcgi::get_pool(&socket, &fcgi_config);
        pool.execute(&method, &uri, &headers, body, &fcgi_config)
            .await
    }

    fn build_fcgi_config(&self) -> FastCgiConfig {
        let mut fcgi_config = FastCgiConfig::default();

        fcgi_config.socket = self.config.socket.clone();

        if let Some(ref root) = self.config.root {
            fcgi_config.script_filename = Some(format!("{}/{{script}}", root));
        }

        if let Some(ref index) = self.config.index {
            fcgi_config.index = Some(index.clone());
        }

        if let Some(timeout) = self.config.connect_timeout {
            fcgi_config.connect_timeout = Some(timeout);
        }

        if let Some(timeout) = self.config.send_timeout {
            fcgi_config.send_timeout = Some(timeout);
        }

        if let Some(timeout) = self.config.read_timeout {
            fcgi_config.read_timeout = Some(timeout);
        }

        let mut admin_values = Vec::new();
        let mut php_values = Vec::new();

        if let Some(ref disable_funcs) = self.config.disable_functions {
            if !disable_funcs.is_empty() {
                admin_values.push((
                    "disable_functions".to_string(),
                    disable_funcs.join(",").to_string(),
                ));
            }
        }

        if let Some(ref open_basedir) = self.config.open_basedir {
            admin_values.push(("open_basedir".to_string(), open_basedir.clone()));
        }

        if let Some(allow_url_fopen) = self.config.allow_url_fopen {
            php_values.push((
                "allow_url_fopen".to_string(),
                if allow_url_fopen {
                    "1".to_string()
                } else {
                    "0".to_string()
                },
            ));
        }

        if let Some(max_exec_time) = self.config.max_execution_time {
            php_values.push(("max_execution_time".to_string(), max_exec_time.to_string()));
        }

        if let Some(ref memory_limit) = self.config.memory_limit {
            php_values.push(("memory_limit".to_string(), memory_limit.clone()));
        }

        if let Some(ref upload_max_size) = self.config.upload_max_filesize {
            php_values.push(("upload_max_filesize".to_string(), upload_max_size.clone()));
        }

        if let Some(ref post_max_size) = self.config.post_max_size {
            php_values.push(("post_max_size".to_string(), post_max_size.clone()));
        }

        if let Some(ref upload_tmp) = self.config.upload_tmp {
            php_values.push(("upload_tmp_dir".to_string(), upload_tmp.clone()));
        }

        if let Some(ref ini_settings) = self.config.ini_settings {
            for (key, value) in ini_settings {
                php_values.push((key.clone(), value.clone()));
            }
        }

        if !admin_values.is_empty() || !php_values.is_empty() {
            let mut params = std::collections::HashMap::new();
            for (key, value) in admin_values {
                params.insert(format!("PHP_ADMIN_VALUE:{}", key), value);
            }
            for (key, value) in php_values {
                params.insert(format!("PHP_VALUE:{}", key), value);
            }
            fcgi_config.params = Some(params);
        }

        fcgi_config
    }
}

pub fn create_php_client(
    site_config: &crate::config::site::SiteConfig,
    location_config: Option<&PhpLocationConfig>,
) -> Option<PhpClient> {
    let mut php_config = site_config.proxy.php.clone()?;

    if let Some(loc) = location_config {
        merge_php_location_config(&mut php_config, loc);
    }

    if php_config.socket.is_none() && php_config.host.is_none() && !has_available_php_socket() {
        tracing::debug!("No PHP-FPM socket found for site, skipping PHP backend");
        return None;
    }

    Some(PhpClient::new(php_config))
}

fn merge_php_location_config(site: &mut PhpConfig, location: &PhpLocationConfig) {
    if location.socket.is_some() {
        site.socket = location.socket.clone();
    }
    if location.host.is_some() {
        site.host = location.host.clone();
    }
    if location.port.is_some() {
        site.port = location.port;
    }
    if location.root.is_some() {
        site.root = location.root.clone();
    }
    if location.index.is_some() {
        site.index = location.index.clone();
    }
    if location.upload_tmp.is_some() {
        site.upload_tmp = location.upload_tmp.clone();
    }
    if location.connect_timeout.is_some() {
        site.connect_timeout = location.connect_timeout;
    }
    if location.send_timeout.is_some() {
        site.send_timeout = location.send_timeout;
    }
    if location.read_timeout.is_some() {
        site.read_timeout = location.read_timeout;
    }
    if let Some(ref disable_funcs) = location.disable_functions {
        let funcs: Vec<String> = disable_funcs
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !funcs.is_empty() {
            site.disable_functions = Some(funcs);
        }
    }
    if location.open_basedir.is_some() {
        site.open_basedir = location.open_basedir.clone();
    }
    if location.allow_url_fopen.is_some() {
        site.allow_url_fopen = location.allow_url_fopen;
    }
    if location.max_execution_time.is_some() {
        site.max_execution_time = location.max_execution_time;
    }
    if location.memory_limit.is_some() {
        site.memory_limit = location.memory_limit.clone();
    }
    if location.upload_max_filesize.is_some() {
        site.upload_max_filesize = location.upload_max_filesize.clone();
    }
    if location.post_max_size.is_some() {
        site.post_max_size = location.post_max_size.clone();
    }
    if location.pm.is_some() {
        site.pm = location.pm.clone();
    }
    if location.pm_max_children.is_some() {
        site.pm_max_children = location.pm_max_children;
    }
    if location.pm_start_servers.is_some() {
        site.pm_start_servers = location.pm_start_servers;
    }
    if location.pm_min_spare_servers.is_some() {
        site.pm_min_spare_servers = location.pm_min_spare_servers;
    }
    if location.pm_max_spare_servers.is_some() {
        site.pm_max_spare_servers = location.pm_max_spare_servers;
    }
    if location.pm_max_requests.is_some() {
        site.pm_max_requests = location.pm_max_requests;
    }
    if location.pm_status_path.is_some() {
        site.pm_status_path = location.pm_status_path.clone();
    }
}

fn has_available_php_socket() -> bool {
    COMMON_PHP_SOCKETS.iter().any(|p| p.exists())
}
