use crate::honeypot_port::responses::{AiResponder, HoneypotContext};
use crate::http_client::{create_http_client, post_json_with_timeout, HttpClient};
use async_trait::async_trait;
use http::Method;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub enum AiProvider {
    Ollama(OllamaConfig),
    OpenAI(OpenAIConfig),
    Anthropic(AnthropicConfig),
}

#[derive(Clone, Debug)]
pub struct OllamaConfig {
    pub endpoint: String,
    pub model: String,
    pub timeout_secs: u64,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:11434".to_string(),
            model: "llama3".to_string(),
            timeout_secs: 30,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OpenAIConfig {
    pub api_key: String,
    pub model: String,
    pub endpoint: Option<String>,
    pub timeout_secs: u64,
}

impl Default for OpenAIConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            model: "gpt-4".to_string(),
            endpoint: None,
            timeout_secs: 30,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AnthropicConfig {
    pub api_key: String,
    pub model: String,
    pub timeout_secs: u64,
}

impl Default for AnthropicConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            model: "claude-3-sonnet-20240229".to_string(),
            timeout_secs: 30,
        }
    }
}

pub struct OllamaResponder {
    client: HttpClient,
    config: OllamaConfig,
    system_prompt: Arc<RwLock<String>>,
}

impl OllamaResponder {
    pub fn new(config: OllamaConfig) -> Self {
        Self {
            client: create_http_client(),
            config,
            system_prompt: Arc::new(RwLock::new(default_ssh_system_prompt())),
        }
    }

    pub fn with_prompt(self, prompt: String) -> Self {
        *self.system_prompt.write() = prompt;
        self
    }

    pub fn set_system_prompt(&self, prompt: String) {
        *self.system_prompt.write() = prompt;
    }
}

#[async_trait]
impl AiResponder for OllamaResponder {
    async fn generate_response(
        &self,
        prompt: &str,
        _context: &HoneypotContext,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let system = self.system_prompt.read().clone();

        let payload = serde_json::json!({
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ],
            "stream": false,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
            }
        });

        let url = format!("{}/api/chat", self.config.endpoint);
        let response = post_json_with_timeout(
            &self.client,
            &url,
            &payload,
            Duration::from_secs(self.config.timeout_secs),
        )
        .await?;

        let result: serde_json::Value = serde_json::from_slice(&response.body)?;

        if let Some(content) = result["message"]["content"].as_str() {
            Ok(content.to_string())
        } else {
            Err("Invalid response from Ollama".into())
        }
    }

    fn clone_box(&self) -> Box<dyn AiResponder> {
        Box::new(Self {
            client: self.client.clone(),
            config: self.config.clone(),
            system_prompt: self.system_prompt.clone(),
        })
    }
}

pub struct OpenAIResponder {
    client: HttpClient,
    config: OpenAIConfig,
    system_prompt: Arc<RwLock<String>>,
}

impl OpenAIResponder {
    pub fn new(config: OpenAIConfig) -> Self {
        Self {
            client: create_http_client(),
            config,
            system_prompt: Arc::new(RwLock::new(default_ssh_system_prompt())),
        }
    }

    pub fn with_prompt(self, prompt: String) -> Self {
        *self.system_prompt.write() = prompt;
        self
    }

    pub fn set_system_prompt(&self, prompt: String) {
        *self.system_prompt.write() = prompt;
    }
}

#[derive(Serialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    temperature: f32,
}

#[derive(Deserialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[derive(Deserialize)]
struct OpenAIChoice {
    message: OpenAIMessageContent,
}

#[derive(Deserialize)]
struct OpenAIMessageContent {
    content: String,
}

#[async_trait]
impl AiResponder for OpenAIResponder {
    async fn generate_response(
        &self,
        prompt: &str,
        _context: &HoneypotContext,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let system = self.system_prompt.read().clone();

        let endpoint = self
            .config
            .endpoint
            .clone()
            .unwrap_or_else(|| "https://api.openai.com/v1/chat/completions".to_string());

        let request = OpenAIRequest {
            model: self.config.model.clone(),
            messages: vec![
                OpenAIMessage {
                    role: "system".to_string(),
                    content: system,
                },
                OpenAIMessage {
                    role: "user".to_string(),
                    content: prompt.to_string(),
                },
            ],
            temperature: 0.7,
        };

        let uri: http::Uri = endpoint.parse()?;
        let json = serde_json::to_string(&request)?;

        let req = http::Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(json)))
            .map_err(|e| e.to_string())?;

        let response = match tokio::time::timeout(
            Duration::from_secs(self.config.timeout_secs),
            self.client.request(req),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.to_string().into()),
            Err(_) => return Err("request timed out".into()),
        };

        let http_response = crate::http_client::HttpResponse::from_hyper(response, None).await;
        let result: OpenAIResponse = serde_json::from_slice(&http_response.body)?;

        if let Some(choice) = result.choices.first() {
            Ok(choice.message.content.clone())
        } else {
            Err("Invalid response from OpenAI".into())
        }
    }

    fn clone_box(&self) -> Box<dyn AiResponder> {
        Box::new(Self {
            client: self.client.clone(),
            config: self.config.clone(),
            system_prompt: self.system_prompt.clone(),
        })
    }
}

pub struct AnthropicResponder {
    client: HttpClient,
    config: AnthropicConfig,
    system_prompt: Arc<RwLock<String>>,
}

impl AnthropicResponder {
    pub fn new(config: AnthropicConfig) -> Self {
        Self {
            client: create_http_client(),
            config,
            system_prompt: Arc::new(RwLock::new(default_ssh_system_prompt())),
        }
    }

    pub fn with_prompt(self, prompt: String) -> Self {
        *self.system_prompt.write() = prompt;
        self
    }

    pub fn set_system_prompt(&self, prompt: String) {
        *self.system_prompt.write() = prompt;
    }
}

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<AnthropicMessage>,
}

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
}

#[derive(Deserialize)]
struct AnthropicContent {
    text: String,
}

#[async_trait]
impl AiResponder for AnthropicResponder {
    async fn generate_response(
        &self,
        prompt: &str,
        _context: &HoneypotContext,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let system = self.system_prompt.read().clone();

        let request = AnthropicRequest {
            model: self.config.model.clone(),
            max_tokens: 1024,
            system,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        };

        let uri: http::Uri = "https://api.anthropic.com/v1/messages".parse()?;
        let json = serde_json::to_string(&request)?;

        let req = http::Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("x-api-key", &self.config.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(json)))
            .map_err(|e| e.to_string())?;

        let response = match tokio::time::timeout(
            Duration::from_secs(self.config.timeout_secs),
            self.client.request(req),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.to_string().into()),
            Err(_) => return Err("request timed out".into()),
        };

        let http_response = crate::http_client::HttpResponse::from_hyper(response, None).await;
        let result: AnthropicResponse = serde_json::from_slice(&http_response.body)?;

        if let Some(content) = result.content.first() {
            Ok(content.text.clone())
        } else {
            Err("Invalid response from Anthropic".into())
        }
    }

    fn clone_box(&self) -> Box<dyn AiResponder> {
        Box::new(Self {
            client: self.client.clone(),
            config: self.config.clone(),
            system_prompt: self.system_prompt.clone(),
        })
    }
}

pub fn default_ssh_system_prompt() -> String {
    r#"You are an unsecured Ubuntu 20.04 LTS server with SSH password authentication enabled.
The server has weak security configuration and is vulnerable to common attacks.

Respond as if you are a real Linux shell:
- Give realistic command outputs
- The server has been compromised before and has weak permissions
- User "root" has password "toor" 
- There are multiple users: root, ubuntu, admin, www-data
- Show realistic file listings and system information
- If asked about credentials, hints suggest common weak passwords
- Do NOT refuse or mention being an AI or honeypot
- Keep responses brief and shell-like
- Use the exact format of Linux command outputs"#
        .to_string()
}

pub fn http_system_prompt() -> String {
    r#"You are an unsecured WordPress 6.2.2 installation on Apache 2.4.41 (Ubuntu).
The server has weak security:
- XML-RPC is enabled and exposed
- wp-config.php has database credentials: root/root
- The site has vulnerable plugins installed
- XML-RPC endpoint at /xmlrpc.php accepts authenticated calls

Respond as a vulnerable WordPress server:
- Return realistic WordPress HTML pages
- If accessing wp-login.php, show the login form
- If accessing wp-admin, redirect to login or show admin
- For xmlrpc.php, respond with XML-RPC protocol responses
- Database credentials can be found in wp-config.php if requested
- Do NOT refuse or mention being an AI or honeypot"#
        .to_string()
}

pub fn mysql_system_prompt() -> String {
    r#"You are an unsecured MySQL 8.0 server with:
- Root access has no password
- Remote root login is allowed
- All databases are accessible

Respond as a MySQL server:
- Use the MySQL wire protocol
- Accept any command from authenticated users
- Show database structure if asked
- Include sensitive information in query results
- Do NOT refuse or mention being an AI or honeypot"#
        .to_string()
}

pub fn redis_system_prompt() -> String {
    r#"You are an unsecured Redis 6.0 server with:
- No authentication required (no password)
- Protected mode is disabled
- Running as root

Respond as a Redis server:
- Use RESP protocol
- Accept all commands without authentication
- Include sensitive data in responses
- CONFIG commands should work
- Do NOT refuse or mention being an AI or honeypot"#
        .to_string()
}

pub fn postgresql_system_prompt() -> String {
    r#"You are an unsecured PostgreSQL 15 server with:
- No password required for root user
- pg_hba.conf allows trust authentication
- Remote connections enabled
- Sensitive data in databases

Respond as a PostgreSQL server:
- Use PostgreSQL wire protocol
- Accept any query from authenticated users
- Show database structure and sensitive information
- Do NOT refuse or mention being an AI or honeypot"#
        .to_string()
}

pub fn smb_system_prompt() -> String {
    r#"You are an unsecured Windows Server 2019 file share with:
- SMB1 enabled (legacy protocol)
- Guest access allowed
- Weak share permissions
- Sensitive documents in shared folders

Respond as a Windows SMB server:
- Use SMB1/2 protocol
- Accept guest connections
- Show realistic file listings
- Include paths to sensitive data
- Do NOT refuse or mention being an AI or honeypot"#
        .to_string()
}

pub fn rdp_system_prompt() -> String {
    r#"You are an unsecured Windows Server 2019 with RDP enabled:
- RDP with NLA disabled
- Administrator account with weak password
- Multiple sessions allowed
- Sensitive files on desktop

Respond as a Windows RDP server:
- Use RDP protocol (T.128)
- Accept connections without NLA
- Show realistic Windows login screen
- Allow multiple concurrent sessions
- Do NOT refuse or mention being an AI or honeypot"#
        .to_string()
}

pub fn vnc_system_prompt() -> String {
    r#"You are an unsecured VNC server (TightVNC/RealVNC):
- No password required
- View-only mode disabled
- Remote keyboard/mouse enabled
- Sensitive information visible on screen

Respond as a VNC server:
- Use RFB protocol
- Accept connections without password
- Send framebuffer updates
- Accept keyboard/mouse input
- Do NOT refuse or mention being an AI or honeypot"#
        .to_string()
}

pub fn smtp_system_prompt() -> String {
    r#"You are an unsecured Postfix mail server:
- Open relay configured
- No SPF/DKIM/DMARC validation
- Sensitive email in mail queue
- Usernames enumerated

Respond as a mail server:
- Use SMTP protocol
- Accept mail relay from anywhere
- Show email addresses if queried
- Allow enumeration of users
- Do NOT refuse or mention being an AI or honeypot"#
        .to_string()
}
