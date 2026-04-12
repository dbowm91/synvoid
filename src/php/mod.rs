#![allow(clippy::type_complexity)]

use std::path::PathBuf;
use std::sync::LazyLock;

use bytes::Bytes;
use http::{Method, Uri};

use crate::config::site::{FastCgiConfig, PhpConfig};
use crate::fastcgi::FastCgiClient;

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
    client: FastCgiClient,
    config: PhpConfig,
}

impl PhpClient {
    pub fn new(config: PhpConfig) -> Self {
        let socket = Self::auto_detect_socket(&config);
        let client = FastCgiClient::new(socket);
        PhpClient { client, config }
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
        let fcgi_config = self.build_fcgi_config();
        self.client
            .execute(method, uri, headers, body, &fcgi_config)
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

        fcgi_config
    }
}

pub fn create_php_client(site_config: &crate::config::site::SiteConfig) -> Option<PhpClient> {
    let php_config = site_config.proxy.php.clone()?;

    if php_config.socket.is_none() && php_config.host.is_none() && !has_available_php_socket() {
        tracing::debug!("No PHP-FPM socket found for site, skipping PHP backend");
        return None;
    }

    Some(PhpClient::new(php_config))
}

fn has_available_php_socket() -> bool {
    COMMON_PHP_SOCKETS.iter().any(|p| p.exists())
}
