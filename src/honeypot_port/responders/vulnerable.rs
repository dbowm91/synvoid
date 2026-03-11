use crate::honeypot_port::responses::{
    HoneypotContext, HoneypotResponder, HoneypotResponse, ResponseType,
};
use parking_lot::RwLock;
use std::sync::Arc;

pub struct VulnerableAppResponder {
    name: String,
    app_type: VulnerableAppType,
    state: Arc<RwLock<AppState>>,
}

#[derive(Clone)]
pub enum VulnerableAppType {
    VulnerableUbuntu,
    VulnerableWordpress,
    VulnerableMySQL,
    VulnerableRedis,
    VulnerableMongoDB,
    VulnerableElasticsearch,
    VulnerableDocker,
    VulnerableJenkins,
    VulnerableTomcat,
    VulnerablePostgreSQL,
    VulnerableSMB,
    VulnerableRDP,
    VulnerableVNC,
    VulnerableSMTP,
    GenericVulnerable,
}

struct AppState {
    authenticated: bool,
    username: Option<String>,
    command_history: Vec<String>,
}

impl VulnerableAppResponder {
    pub fn new(app_type: VulnerableAppType) -> Self {
        let name = match &app_type {
            VulnerableAppType::VulnerableUbuntu => "vulnerable_ubuntu".to_string(),
            VulnerableAppType::VulnerableWordpress => "vulnerable_wordpress".to_string(),
            VulnerableAppType::VulnerableMySQL => "vulnerable_mysql".to_string(),
            VulnerableAppType::VulnerableRedis => "vulnerable_redis".to_string(),
            VulnerableAppType::VulnerableMongoDB => "vulnerable_mongodb".to_string(),
            VulnerableAppType::VulnerableElasticsearch => "vulnerable_elasticsearch".to_string(),
            VulnerableAppType::VulnerableDocker => "vulnerable_docker".to_string(),
            VulnerableAppType::VulnerableJenkins => "vulnerable_jenkins".to_string(),
            VulnerableAppType::VulnerableTomcat => "vulnerable_tomcat".to_string(),
            VulnerableAppType::VulnerablePostgreSQL => "vulnerable_postgresql".to_string(),
            VulnerableAppType::VulnerableSMB => "vulnerable_smb".to_string(),
            VulnerableAppType::VulnerableRDP => "vulnerable_rdp".to_string(),
            VulnerableAppType::VulnerableVNC => "vulnerable_vnc".to_string(),
            VulnerableAppType::VulnerableSMTP => "vulnerable_smtp".to_string(),
            VulnerableAppType::GenericVulnerable => "vulnerable_generic".to_string(),
        };

        Self {
            name,
            app_type,
            state: Arc::new(RwLock::new(AppState {
                authenticated: false,
                username: None,
                command_history: Vec::new(),
            })),
        }
    }

    pub fn ubuntu_ssh() -> Self {
        Self::new(VulnerableAppType::VulnerableUbuntu)
    }

    pub fn wordpress() -> Self {
        Self::new(VulnerableAppType::VulnerableWordpress)
    }

    pub fn mysql() -> Self {
        Self::new(VulnerableAppType::VulnerableMySQL)
    }

    pub fn redis() -> Self {
        Self::new(VulnerableAppType::VulnerableRedis)
    }

    pub fn mongodb() -> Self {
        Self::new(VulnerableAppType::VulnerableMongoDB)
    }

    pub fn elasticsearch() -> Self {
        Self::new(VulnerableAppType::VulnerableElasticsearch)
    }

    pub fn docker_api() -> Self {
        Self::new(VulnerableAppType::VulnerableDocker)
    }

    pub fn jenkins() -> Self {
        Self::new(VulnerableAppType::VulnerableJenkins)
    }

    pub fn tomcat() -> Self {
        Self::new(VulnerableAppType::VulnerableTomcat)
    }

    pub fn postgresql() -> Self {
        Self::new(VulnerableAppType::VulnerablePostgreSQL)
    }

    pub fn smb() -> Self {
        Self::new(VulnerableAppType::VulnerableSMB)
    }

    pub fn rdp() -> Self {
        Self::new(VulnerableAppType::VulnerableRDP)
    }

    pub fn vnc() -> Self {
        Self::new(VulnerableAppType::VulnerableVNC)
    }

    pub fn smtp() -> Self {
        Self::new(VulnerableAppType::VulnerableSMTP)
    }

    fn respond_ubuntu(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        if payload.is_empty() {
            return HoneypotResponse::static_response(
                b"\r\nUbuntu 20.04.6 LTS (Focal Fossa)\r\nlocalhost login: ".to_vec(),
            );
        }

        let text = String::from_utf8_lossy(payload);
        let text = text.trim();

        let mut state = self.state.write();

        if !state.authenticated {
            if text.starts_with("root") || text.starts_with("admin") || text.starts_with("ubuntu") {
                state.username = Some(text.to_string());
                return HoneypotResponse::static_response(b"Password: ".to_vec());
            }
            if text.is_empty() {
                return HoneypotResponse::static_response(
                    b"\r\nUbuntu 20.04.6 LTS (Focal Fossa)\r\nlocalhost login: ".to_vec(),
                );
            }
            return HoneypotResponse::static_response(
                b"Login incorrect\r\nlocalhost login: ".to_vec(),
            );
        }

        let username_clone = state.username.clone();
        if let Some(username) = username_clone {
            if text.is_empty() {
                return HoneypotResponse::static_response(b"Password: ".to_vec());
            }
            if text.len() < 4 {
                return HoneypotResponse::static_response(
                    b"Login incorrect\r\nPassword: ".to_vec(),
                );
            }

            state.authenticated = true;
            let prompt = format!("\r\n{}@localhost:~$ ", username);
            return HoneypotResponse::static_response(prompt.as_bytes().to_vec());
        }

        state.command_history.push(text.to_string());

        let response = self.generate_ubuntu_response(text);
        let follow_up = format!(
            "\r\n{}@localhost:~$ ",
            state.username.as_deref().unwrap_or("root")
        );

        let mut data = response.into_bytes();
        data.extend_from_slice(follow_up.as_bytes());

        HoneypotResponse::with_options(data, ResponseType::VulnerableApp, false, true)
    }

    fn generate_ubuntu_response(&self, command: &str) -> String {
        let cmd = command.trim().to_lowercase();

        if cmd.contains("whoami") {
            return "root".to_string();
        }
        if cmd.contains("id") {
            return "uid=0(root) gid=0(root) groups=0(root)".to_string();
        }
        if cmd.contains("uname") || cmd.contains("hostname") {
            return "localhost".to_string();
        }
        if cmd.contains("ls") {
            return "Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos"
                .to_string();
        }
        if cmd.contains("pwd") {
            return "/home".to_string();
        }
        if cmd.contains("cat /etc/passwd") {
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash".to_string();
        }
        if cmd.contains("env") {
            return "HOME=/root\nUSER=root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n".to_string();
        }
        if cmd.contains("ifconfig") || cmd.contains("ip a") {
            return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        ether 00:0c:29:ab:cd:ef  txqueuelen 1000  (Ethernet)".to_string();
        }
        if cmd.contains("free") {
            return "              total        used        free      shared  buff/cache   available\nMem:        2048000      512000     1024000       10240      512000     1400000\nSwap:       1024000           0     1024000".to_string();
        }
        if cmd.contains("df") {
            return "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       51475068 12345678  39129390  24% /".to_string();
        }
        if cmd.contains("curl") || cmd.contains("wget") {
            return "curl: try 'curl --help' for more information".to_string();
        }
        if cmd.contains("python") || cmd.contains("python3") {
            return "Python 3.8.10".to_string();
        }
        if cmd.contains("mysql") || cmd.contains("mariadb") {
            return "Welcome to the MySQL monitor.".to_string();
        }
        if cmd.contains("exit") || cmd.contains("logout") {
            return "logout\r\n\r\nUbuntu 20.04.6 LTS (Focal Fossa)\r\nlocalhost login: "
                .to_string();
        }

        format!(
            "{}: command not found",
            command.split_whitespace().next().unwrap_or("")
        )
    }

    fn respond_wordpress(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        if payload.is_empty() {
            return HoneypotResponse::static_response(
                b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n".to_vec(),
            );
        }

        let text = String::from_utf8_lossy(payload);

        let response: String = if text.contains("wp-login.php") || text.contains("/wp-admin/") {
            r#"<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en-US">
<head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" /><title>Log In &lsaquo; WordPress</title>
<link rel="stylesheet" href="http://localhost:8888/wp-admin/css/login.min.css" type="text/css"/>
</head>
<body class="login login-action-login wp-core-ui"><form name="loginform" id="loginform" action="http://localhost:8888/wp-login.php" method="post">
<p><label>Username<input type="text" name="log" id="user_login" class="input" value="" size="20" /></label></p>
<p><label>Password<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" /></label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" /></p>
</form></body></html>"#.to_string()
        } else if text.contains("xmlrpc.php") {
            "XML-RPC server accepts POST requests only.".to_string()
        } else if text.contains("wp-config.php") {
            "<?php\ndefine( 'DB_NAME', 'wordpress' );\ndefine( 'DB_USER', 'root' );\ndefine( 'DB_PASSWORD', 'root' );\ndefine( 'DB_HOST', 'localhost' );\n".to_string()
        } else if text.contains(".git/") {
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<service><error>Git access not allowed</error></service>".to_string()
        } else if text.contains("sitemap.xml") || text.contains("wp-json/") {
            r#"{"version":1,"encoding":"UTF-8","urlset":{"url":[{"loc":"http://example.com/","changefreq":"daily","priority":"1.0"}]}}"#.to_string()
        } else {
            "<html><head><title>WordPress</title></head><body><h1>Welcome to WordPress</h1></body></html>".to_string()
        };

        let mut headers = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: ".to_vec();
        headers.extend_from_slice(response.len().to_string().as_bytes());
        headers.extend_from_slice(b"\r\n\r\n");

        let mut full_response = headers;
        full_response.extend_from_slice(response.as_bytes());

        HoneypotResponse::with_options(full_response, ResponseType::VulnerableApp, true, false)
    }

    fn respond_mysql(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        if payload.is_empty() || payload.len() < 4 {
            return HoneypotResponse::static_response(vec![
                0x0a, 0x00, 0x00, 0x01, 0xff, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);
        }

        let greeting = b"\x0a\x00\x00\x01\xff\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00root\x00";

        if payload.len() > 4 && payload[4] == 0x85 {
            return HoneypotResponse::static_response(greeting.to_vec());
        }

        HoneypotResponse::static_response(vec![0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02])
    }

    fn respond_redis(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        if payload.is_empty() {
            return HoneypotResponse::static_response(b"+OK\r\n".to_vec());
        }

        let text = String::from_utf8_lossy(payload);
        let cmd = text.trim().to_uppercase();

        let response: String = if cmd.starts_with("PING") {
            "+PONG\r\n".to_string()
        } else if cmd.starts_with("AUTH") {
            "+OK\r\n".to_string()
        } else if cmd.starts_with("GET ") || cmd.starts_with("SET ") {
            "+OK\r\n".to_string()
        } else if cmd.starts_with("CONFIG") {
            "-ERR syntax error\r\n".to_string()
        } else if cmd.starts_with("INFO") {
            "# Server\r\nredis_version:6.0.9\r\nredis_mode:standalone\r\n".to_string()
        } else if cmd.starts_with("KEYS") {
            "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n".to_string()
        } else {
            "-ERR unknown command\r\n".to_string()
        };

        HoneypotResponse::static_response(response.as_bytes().to_vec())
    }

    fn respond_mongodb(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        if payload.is_empty() || payload.len() < 16 {
            return HoneypotResponse::static_response(
                b"{\"ok\":1,\"ismaster\":true,\"maxWireVersion\":20,\"minWireVersion\":0}\0"
                    .to_vec(),
            );
        }

        let response = if payload.len() > 5 && payload[5] == 0xD4 {
            "{\"ok\":1,\"ismaster\":true}".to_string()
        } else {
            "{\"ok\":1}".to_string()
        };

        let mut data = vec![0x00, 0x00, 0x00, response.len() as u8 + 0x10];
        data.extend_from_slice(response.as_bytes());

        HoneypotResponse::static_response(data)
    }

    fn respond_elasticsearch(
        &self,
        _payload: &[u8],
        _context: &HoneypotContext,
    ) -> HoneypotResponse {
        let response = "{\"name\":\"node-1\",\"cluster_name\":\"elasticsearch\",\"cluster_uuid\":\"abcdef123456\",\"version\":{\"number\":\"7.17.0\",\"build_flavor\":\"default\",\"build_type\":\"deb\",\"build_hash\":\"abc123\",\"build_date\":\"2022-01-01T00:00:00.000000Z\",\"build_snapshot\":false,\"lucene_version\":\"8.11.0\",\"minimum_wire_compatibility_version\":\"6.8.0\",\"minimum_index_compatibility_version\":\"6.0.0-beta1\"},\"tagline\":\"You Know, for Search\"}".to_string();

        let mut headers =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ".to_vec();
        headers.extend_from_slice(response.len().to_string().as_bytes());
        headers.extend_from_slice(b"\r\n\r\n");

        let mut full_response = headers;
        full_response.extend_from_slice(response.as_bytes());

        HoneypotResponse::static_response(full_response)
    }

    fn respond_docker(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        let text = String::from_utf8_lossy(payload);

        let response = if text.contains("GET /containers") {
            r#"[{"Id":"abc123","Names":["/web"],"Image":"nginx:latest","ImageID":"sha256:abc","Created":"2024-01-01T00:00:00Z","Ports":[{"PrivatePort":80,"Type":"tcp"}],"State":"running"}]"#
        } else if text.contains("GET /images") {
            r#"[{"Id":"sha256:abc123","RepoTags":["nginx:latest"],"Size":"142MB"}]"#
        } else if text.contains("GET /info") {
            r#"{"Containers":5,"ContainersRunning":3,"Images":12,"ServerVersion":"20.10.21","MemTotal":4294967296}"#
        } else if text.contains("Version") {
            r#"{"Version":"20.10.21","ApiVersion":"1.41"}"#
        } else {
            "{\"message\":\"page not found\"}"
        };

        let mut headers =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nApi-Version: 1.41\r\n".to_vec();
        headers.extend_from_slice(b"Content-Length: ");
        headers.extend_from_slice(response.len().to_string().as_bytes());
        headers.extend_from_slice(b"\r\n\r\n");

        let mut full_response = headers;
        full_response.extend_from_slice(response.as_bytes());

        HoneypotResponse::static_response(full_response)
    }

    fn respond_jenkins(&self, _payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        let response = r#"<!DOCTYPE html><html><head><title>Jenkins</title></head>
<body><form method="POST" action="j_acegi_security_check">
<input name="j_username" type="text"/><input name="j_password" type="password"/>
<input type="submit" value="Sign In"/></form></body></html>"#;

        let mut headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/html;charset=UTF-8\r\nX-Jenkins: 2.332.3\r\nContent-Length: ".to_vec();
        headers.extend_from_slice(response.len().to_string().as_bytes());
        headers.extend_from_slice(b"\r\n\r\n");

        let mut full_response = headers;
        full_response.extend_from_slice(response.as_bytes());

        HoneypotResponse::static_response(full_response)
    }

    fn respond_tomcat(&self, _payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        let response = r#"<!DOCTYPE html><html><head><title>Tomcat Manager</title></head>
<body><form method="POST" action="/manager/html/upload">
<input type="file" name="warfile"/><input type="submit" value="Deploy"/>
</form></body></html>"#;

        let mut headers = b"HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html\r\nContent-Length: ".to_vec();
        headers.extend_from_slice(response.len().to_string().as_bytes());
        headers.extend_from_slice(b"\r\n\r\n");

        let mut full_response = headers;
        full_response.extend_from_slice(response.as_bytes());

        HoneypotResponse::static_response(full_response)
    }

    fn respond_postgresql(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        if payload.is_empty() {
            return HoneypotResponse::static_response(vec![
                0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f,
            ]);
        }

        if payload.starts_with(b"\x00\x03\x00\x00") {
            return HoneypotResponse::static_response(b"2023.09.04.1234".to_vec());
        }

        let payload_str = String::from_utf8_lossy(payload);
        if payload_str.contains("user") || payload_str.contains("postgres") {
            return HoneypotResponse::static_response(vec![
                0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);
        }

        HoneypotResponse::static_response(vec![
            0x45, 0x00, 0x00, 0x00, 0x0d, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00,
        ])
    }

    fn respond_smb(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        if payload.is_empty() || payload.starts_with(&[0x00, 0x00, 0x00, 0x85]) {
            return HoneypotResponse::static_response(vec![
                0x00, 0x00, 0x00, 0x85, 0xfe, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x98,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);
        }

        HoneypotResponse::static_response(vec![
            0x00, 0x00, 0x00, 0x49, 0xfe, 0x53, 0x4d, 0x42, 0xa4, 0x00, 0x00, 0x00, 0x80, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
    }

    fn respond_rdp(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        if payload.is_empty() {
            return HoneypotResponse::static_response(vec![
                0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);
        }

        if payload.starts_with(&[0x03, 0x00]) {
            return HoneypotResponse::static_response(vec![
                0x03, 0x00, 0x00, 0x0c, 0x02, 0x1b, 0x00, 0x01, 0x03, 0x00, 0x01, 0x02, 0x01, 0x00,
            ]);
        }

        if payload.len() > 4 && payload[0] == 0x03 && payload[1] == 0x00 {
            return HoneypotResponse::static_response(vec![
                0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00,
            ]);
        }

        HoneypotResponse::static_response(vec![
            0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
    }

    fn respond_vnc(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        if payload.is_empty() || payload.starts_with(b"RFB ") {
            return HoneypotResponse::static_response(b"RFB 003.008\n".to_vec());
        }

        if payload.len() > 1 {
            match payload[0] {
                0x01 => {
                    return HoneypotResponse::static_response(b"RFB 003.008\n".to_vec());
                }
                0x02 => {
                    return HoneypotResponse::static_response(vec![
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                        0x0d, 0x0e, 0x0f, 0x10,
                    ]);
                }
                0x04 => {
                    return HoneypotResponse::static_response(vec![0x00, 0x00, 0x00, 0x01]);
                }
                _ => {}
            }
        }

        HoneypotResponse::static_response(b"RFB 003.008\n".to_vec())
    }

    fn respond_smtp(&self, payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        if payload.is_empty() || payload.starts_with(b"EHLO") || payload.starts_with(b"HELO") {
            return HoneypotResponse::static_response(
                b"250-mail.example.com\r\n\
                  250-PIPELINING\r\n\
                  250-SIZE 10240000\r\n\
                  250-ETRN\r\n\
                  250-STARTTLS\r\n\
                  250-ENHANCEDSTATUSCODES\r\n\
                  250-8BITMIME\r\n\
                  250 SMTPUTF8\r\n"
                    .to_vec(),
            );
        }

        if payload.starts_with(b"MAIL FROM:") {
            return HoneypotResponse::static_response(b"250 OK\r\n".to_vec());
        }

        if payload.starts_with(b"RCPT TO:") {
            return HoneypotResponse::static_response(b"250 OK\r\n".to_vec());
        }

        if payload.starts_with(b"DATA") {
            return HoneypotResponse::static_response(
                b"354 End data with <CR><LF>.<CR><LF>\r\n".to_vec(),
            );
        }

        if payload.starts_with(b"AUTH LOGIN") {
            return HoneypotResponse::static_response(b"334 VXNlcm5hbWU6\r\n".to_vec());
        }

        if payload.starts_with(b"QUIT") {
            return HoneypotResponse::static_response(b"221 2.0.0 Bye\r\n".to_vec());
        }

        HoneypotResponse::static_response(b"250 OK\r\n".to_vec())
    }
}

impl HoneypotResponder for VulnerableAppResponder {
    fn name(&self) -> &str {
        &self.name
    }

    fn service_type(&self) -> &str {
        match &self.app_type {
            VulnerableAppType::VulnerableUbuntu => "ssh",
            VulnerableAppType::VulnerableWordpress => "http",
            VulnerableAppType::VulnerableMySQL => "mysql",
            VulnerableAppType::VulnerableRedis => "redis",
            VulnerableAppType::VulnerableMongoDB => "mongodb",
            VulnerableAppType::VulnerableElasticsearch => "http",
            VulnerableAppType::VulnerableDocker => "http",
            VulnerableAppType::VulnerableJenkins => "http",
            VulnerableAppType::VulnerableTomcat => "http",
            VulnerableAppType::VulnerablePostgreSQL => "postgresql",
            VulnerableAppType::VulnerableSMB => "smb",
            VulnerableAppType::VulnerableRDP => "rdp",
            VulnerableAppType::VulnerableVNC => "vnc",
            VulnerableAppType::VulnerableSMTP => "smtp",
            VulnerableAppType::GenericVulnerable => "unknown",
        }
    }

    fn respond(&self, payload: &[u8], context: &HoneypotContext) -> HoneypotResponse {
        match &self.app_type {
            VulnerableAppType::VulnerableUbuntu => self.respond_ubuntu(payload, context),
            VulnerableAppType::VulnerableWordpress => self.respond_wordpress(payload, context),
            VulnerableAppType::VulnerableMySQL => self.respond_mysql(payload, context),
            VulnerableAppType::VulnerableRedis => self.respond_redis(payload, context),
            VulnerableAppType::VulnerableMongoDB => self.respond_mongodb(payload, context),
            VulnerableAppType::VulnerableElasticsearch => {
                self.respond_elasticsearch(payload, context)
            }
            VulnerableAppType::VulnerableDocker => self.respond_docker(payload, context),
            VulnerableAppType::VulnerableJenkins => self.respond_jenkins(payload, context),
            VulnerableAppType::VulnerableTomcat => self.respond_tomcat(payload, context),
            VulnerableAppType::VulnerablePostgreSQL => self.respond_postgresql(payload, context),
            VulnerableAppType::VulnerableSMB => self.respond_smb(payload, context),
            VulnerableAppType::VulnerableRDP => self.respond_rdp(payload, context),
            VulnerableAppType::VulnerableVNC => self.respond_vnc(payload, context),
            VulnerableAppType::VulnerableSMTP => self.respond_smtp(payload, context),
            VulnerableAppType::GenericVulnerable => {
                HoneypotResponse::static_response(b"500 Internal Server Error".to_vec())
            }
        }
    }

    fn clone_box(&self) -> Box<dyn HoneypotResponder> {
        Box::new(Self {
            name: self.name.clone(),
            app_type: self.app_type.clone(),
            state: self.state.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::honeypot_port::responses::HoneypotContext;

    fn make_context() -> HoneypotContext {
        HoneypotContext {
            remote_ip: "192.168.1.100".to_string(),
            remote_port: 12345,
            local_port: 22,
            service: "ssh".to_string(),
            protocol: "ssh".to_string(),
            payload: Vec::new(),
            payload_hex: String::new(),
            detected_pattern: None,
            bytes_received: 0,
            duration_ms: 0,
            connection_start: std::time::Instant::now(),
        }
    }

    #[test]
    fn test_ubuntu_ssh_initial_prompt() {
        let responder = VulnerableAppResponder::ubuntu_ssh();
        let context = make_context();

        let response = responder.respond(b"", &context);

        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("Ubuntu"));
        assert!(response_str.contains("login"));
    }

    #[test]
    fn test_ubuntu_ssh_username() {
        let responder = VulnerableAppResponder::ubuntu_ssh();
        let context = make_context();

        let response = responder.respond(b"root", &context);

        // Should ask for password
        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("Password"));
    }

    #[test]
    fn test_ubuntu_ssh_invalid_login() {
        let responder = VulnerableAppResponder::ubuntu_ssh();
        let context = make_context();

        // First send username
        let _ = responder.respond(b"root", &context);
        // Then send short password (should fail)
        let response = responder.respond(b"ab", &context);

        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("incorrect"));
    }

    #[test]
    fn test_ubuntu_whoami_command() {
        let responder = VulnerableAppResponder::ubuntu_ssh();
        let context = make_context();

        // Login first
        let _ = responder.respond(b"root", &context);
        let _ = responder.respond(b"password123", &context);

        // Now send command
        let response = responder.respond(b"whoami", &context);

        // After login, should get a prompt
        let response_str = String::from_utf8_lossy(&response.data);
        assert!(!response_str.is_empty());
    }

    #[test]
    fn test_wordpress_wp_login() {
        let responder = VulnerableAppResponder::wordpress();
        let context = make_context();

        let response = responder.respond(b"GET /wp-login.php HTTP/1.1", &context);

        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("200 OK"));
        assert!(response_str.contains("WordPress"));
    }

    #[test]
    fn test_wordpress_wp_config() {
        let responder = VulnerableAppResponder::wordpress();
        let context = make_context();

        let response = responder.respond(b"GET /wp-config.php HTTP/1.1", &context);

        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("DB_NAME"));
        assert!(response_str.contains("wordpress"));
    }

    #[test]
    fn test_redis_ping() {
        let responder = VulnerableAppResponder::redis();
        let context = make_context();

        let response = responder.respond(b"PING", &context);

        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("PONG"));
    }

    #[test]
    fn test_redis_info() {
        let responder = VulnerableAppResponder::redis();
        let context = make_context();

        let response = responder.respond(b"INFO", &context);

        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("redis"));
    }

    #[test]
    fn test_vulnerable_responder_name() {
        let responder = VulnerableAppResponder::ubuntu_ssh();
        assert_eq!(responder.name(), "vulnerable_ubuntu");
    }
}
