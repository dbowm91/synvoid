use gloo::net::http::{Request, Response};
use serde::{de::DeserializeOwned, Serialize};
use serde_json;

pub struct ApiService {
    base_url: String,
    token: Option<String>,
}

impl Default for ApiService {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiService {
    pub fn new() -> Self {
        Self {
            base_url: "/api".to_string(),
            token: None,
        }
    }
    
    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }
    
    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }
    
    async fn request(&self, method: &str, path: &str) -> Result<Response, String> {
        let url = format!("{}{}", self.base_url, path);
        
        let mut builder = match method {
            "GET" => Request::get(&url),
            "POST" => Request::post(&url),
            "PUT" => Request::put(&url),
            "DELETE" => Request::delete(&url),
            _ => return Err(format!("Unsupported HTTP method: {}", method)),
        };
        
        if let Some(token) = &self.token {
            builder = builder.header("Authorization", &format!("Bearer {}", token));
        }
        
        builder
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))
    }
    
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let response = self.request("GET", path).await?;
        
        if !response.ok() {
            return Err(format!("HTTP error: {}", response.status()));
        }
        
        response
            .json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))
    }
    
    pub async fn get_text(&self, path: &str) -> Result<String, String> {
        let response = self.request("GET", path).await?;
        
        if !response.ok() {
            return Err(format!("HTTP error: {}", response.status()));
        }
        
        response
            .text()
            .await
            .map_err(|e| format!("Text parse error: {}", e))
    }
    
    pub async fn health_check(&self) -> Result<bool, String> {
        match self.get_text("/health").await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T, String> {
        let url = format!("{}{}", self.base_url, path);
        
        let body_str = serde_json::to_string(body).map_err(|e| format!("Serialization error: {}", e))?;
        
        let mut builder = Request::post(&url);
        
        if let Some(token) = &self.token {
            builder = builder.header("Authorization", &format!("Bearer {}", token));
        }
        
        builder = builder.header("Content-Type", "application/json");
        
        let response = builder
            .body(body_str)
            .map_err(|e| format!("Request failed: {}", e))?
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        
        if !response.ok() {
            return Err(format!("HTTP error: {}", response.status()));
        }
        
        response
            .json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))
    }
}
