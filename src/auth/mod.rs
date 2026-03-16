use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs as tokio_fs;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration as TokioDuration};
use uuid::Uuid;

use crate::DrainFlag;

pub mod basic;
pub use basic::{BasicAuthManager, BasicAuthResult};

async fn verify_dummy_password(password: &str) {
    let dummy_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzS.xJ5mW6";
    let start = std::time::Instant::now();
    let _ = verify(password, dummy_hash);
    let elapsed = start.elapsed();
    if elapsed < std::time::Duration::from_millis(200) {
        sleep(TokioDuration::from_millis(200) - TokioDuration::from(elapsed)).await;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub sites: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub failed_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}

impl Default for UserRole {
    fn default() -> Self {
        UserRole::User
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub csrf_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthStore {
    pub users: HashMap<String, User>,
    pub sessions: HashMap<String, Session>,
    pub login_logs: Vec<LoginLog>,
}

impl Default for AuthStore {
    fn default() -> Self {
        Self {
            users: HashMap::new(),
            sessions: HashMap::new(),
            login_logs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginLog {
    pub id: String,
    pub username: String,
    pub success: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub reason: Option<String>,
}

pub struct AuthManager {
    data_dir: PathBuf,
    store: Arc<RwLock<AuthStore>>,
    session_duration_secs: u64,
    max_failed_attempts: u32,
    lockout_duration_secs: u64,
    min_password_length: usize,
    session_refresh_threshold: f64,
    write_tx: mpsc::Sender<(AuthStore, Option<mpsc::Sender<()>>)>,
    flush_requested: DrainFlag,
}

impl AuthManager {
    pub fn new(
        data_dir: PathBuf,
        session_duration_secs: u64,
        max_failed_attempts: u32,
        lockout_duration_secs: u64,
    ) -> Self {
        let store = Self::load_store(&data_dir);
        let store_clone = store.clone();
        
        let (write_tx, mut write_rx) = mpsc::channel::<(AuthStore, Option<mpsc::Sender<()>>)>(100);
        
        let data_dir_clone = data_dir.clone();
        let flush_flag = DrainFlag::new();
        let flush_flag_clone = flush_flag.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(TokioDuration::from_secs(5));
            let mut pending_stores: Vec<AuthStore> = Vec::new();
            let mut flush_completion_tx: Option<mpsc::Sender<()>> = None;
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if !pending_stores.is_empty() {
                            let store = pending_stores.pop().unwrap();
                            Self::write_store_to_disk(&data_dir_clone, &store).await;
                            pending_stores.clear();
                        }
                        if flush_flag_clone.is_draining() {
                            if !pending_stores.is_empty() {
                                let store = pending_stores.pop().unwrap();
                                Self::write_store_to_disk(&data_dir_clone, &store).await;
                                pending_stores.clear();
                            }
                            if let Some(tx) = flush_completion_tx.take() {
                                let _ = tx.send(()).await;
                            }
                            flush_flag_clone.end_drain();
                        }
                    }
                    Some((store, flush_tx)) = write_rx.recv() => {
                        pending_stores.push(store);
                        flush_completion_tx = flush_tx;
                    }
                }
            }
        });
        
        Self {
            data_dir,
            store: Arc::new(RwLock::new(store_clone)),
            session_duration_secs,
            max_failed_attempts,
            lockout_duration_secs,
            min_password_length: 8,
            session_refresh_threshold: 0.5,
            write_tx,
            flush_requested: flush_flag,
        }
    }

    fn load_store(data_dir: &PathBuf) -> AuthStore {
        let auth_dir = data_dir.join("auth");
        let store_path = auth_dir.join("store.json");
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if auth_dir.exists() {
                let _ = std::fs::set_permissions(&auth_dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        
        if store_path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o600));
            }
            
            match fs::read_to_string(&store_path) {
                Ok(content) => {
                    match serde_json::from_str(&content) {
                        Ok(store) => return store,
                        Err(e) => {
                            tracing::warn!("Failed to parse auth store: {}, creating new", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read auth store: {}, creating new", e);
                }
            }
        }
        
        AuthStore::default()
    }

    async fn save_store(&self, store: &AuthStore) {
        let store_clone = store.clone();
        let _ = self.write_tx.send((store_clone, None)).await;
    }

    async fn write_store_to_disk(data_dir: &PathBuf, store: &AuthStore) {
        let auth_dir = data_dir.join("auth");
        let store_path = auth_dir.join("store.json");
        
        if let Some(parent) = store_path.parent() {
            if let Err(e) = tokio_fs::create_dir_all(parent).await {
                tracing::error!("Failed to create auth directory: {}", e);
                return;
            }
        }
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = tokio_fs::set_permissions(&auth_dir, std::fs::Permissions::from_mode(0o700)).await {
                tracing::warn!("Failed to set auth directory permissions: {}", e);
            }
        }
        
        match serde_json::to_string_pretty(store) {
            Ok(content) => {
                if let Err(e) = tokio_fs::write(&store_path, content).await {
                    tracing::error!("Failed to write auth store: {}", e);
                } else {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Err(e) = tokio_fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o600)).await {
                            tracing::warn!("Failed to set store file permissions: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to serialize auth store: {}", e);
            }
        }
    }

    pub async fn flush(&self) {
        let (tx, mut rx) = mpsc::channel::<()>(1);
        let store = self.store.read().await;
        let store_clone = store.clone();
        drop(store);
        
        self.flush_requested.start_drain();
        let _ = self.write_tx.send((store_clone, Some(tx))).await;
        
        let _ = rx.recv().await;
    }

    pub async fn create_user(
        &self,
        username: String,
        password: String,
        role: UserRole,
        sites: Vec<String>,
    ) -> Result<User, AuthError> {
        if password.len() < self.min_password_length {
            return Err(AuthError::PasswordTooShort(self.min_password_length));
        }
        
        if username.is_empty() {
            return Err(AuthError::InvalidUsername);
        }

        let password_hash = hash(&password, DEFAULT_COST)
            .map_err(|_| AuthError::HashingError)?;

        let mut store = self.store.write().await;

        if store.users.contains_key(&username.to_lowercase()) {
            return Err(AuthError::UserAlreadyExists);
        }

        let user = User {
            id: Uuid::new_v4().to_string(),
            username: username.clone(),
            password_hash,
            role,
            sites,
            created_at: Utc::now(),
            last_login: None,
            failed_attempts: 0,
            locked_until: None,
        };

        store.users.insert(username.to_lowercase(), user.clone());
        self.save_store(&store).await;

        Ok(user)
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<(), AuthError> {
        let mut store = self.store.write().await;
        
        let username_to_remove = store.users.iter()
            .find(|(_, u)| u.id == user_id)
            .map(|(k, _)| k.clone());
        
        if let Some(username) = username_to_remove {
            store.users.remove(&username);
            
            store.sessions.retain(|_, s| s.user_id != user_id);
            
            self.save_store(&store).await;
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
    }

    pub async fn update_user_sites(&self, user_id: &str, sites: Vec<String>) -> Result<(), AuthError> {
        let mut store = self.store.write().await;
        
        let user_id_to_find = user_id.to_string();
        
        if let Some(user) = store.users.values_mut().find(|u| u.id == user_id_to_find) {
            user.sites = sites;
            self.save_store(&store).await;
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
    }

    pub async fn list_users(&self) -> Vec<UserInfo> {
        let store = self.store.read().await;
        
        store.users.values()
            .map(|u| UserInfo {
                id: u.id.clone(),
                username: u.username.clone(),
                role: u.role,
                sites: u.sites.clone(),
                created_at: u.created_at,
                last_login: u.last_login,
                failed_attempts: u.failed_attempts,
                locked_until: u.locked_until,
            })
            .collect()
    }

    pub async fn verify_login(
        &self,
        username: &str,
        password: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Session, AuthError> {
        let username_key = username.to_lowercase();
        
        let mut store = self.store.write().await;
        
        let user = match store.users.get_mut(&username_key) {
            Some(user) => user,
            None => {
                drop(store);
                verify_dummy_password(password).await;
                return Err(AuthError::InvalidCredentials);
            }
        };
        
        if let Some(locked_until) = user.locked_until {
            if locked_until > Utc::now() {
                drop(store);
                verify_dummy_password(password).await;
                return Err(AuthError::AccountLocked(locked_until));
            } else {
                user.locked_until = None;
                user.failed_attempts = 0;
            }
        }
        
        let stored_hash = user.password_hash.clone();
        let user_id = user.id.clone();
        
        let password_valid = verify(password, &stored_hash)
            .unwrap_or(false);
        
        let ip_str = ip_address.map(|s| s.to_string());
        let ua_str = user_agent.map(|s| s.to_string());
        
        if !password_valid {
            user.failed_attempts += 1;
            
            let lock_user = user.failed_attempts >= self.max_failed_attempts;
            let reason = if lock_user {
                user.locked_until = Some(Utc::now() + chrono::Duration::seconds(self.lockout_duration_secs as i64));
                Some("Too many failed attempts".to_string())
            } else {
                None
            };
            
            store.login_logs.push(LoginLog {
                id: Uuid::new_v4().to_string(),
                username: username.to_string(),
                success: false,
                ip_address: ip_str,
                user_agent: ua_str,
                timestamp: Utc::now(),
                reason,
            });
            self.save_store(&store).await;
            
            return Err(AuthError::InvalidCredentials);
        }
        
        user.last_login = Some(Utc::now());
        user.failed_attempts = 0;
        user.locked_until = None;
        
        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id,
            username: username.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(self.session_duration_secs as i64),
            ip_address: ip_str.clone(),
            user_agent: ua_str.clone(),
            csrf_token: Some(Uuid::new_v4().to_string()),
        };
        
        store.sessions.insert(session.id.clone(), session.clone());
        
        store.login_logs.push(LoginLog {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            success: true,
            ip_address: ip_str,
            user_agent: ua_str,
            timestamp: Utc::now(),
            reason: None,
        });
        
        self.save_store(&store).await;
        
        Ok(session)
    }

    pub async fn validate_session(&self, session_id: &str) -> Option<SessionInfo> {
        let mut store = self.store.write().await;
        
        let session_data = store.sessions.get(session_id).map(|s| {
            if s.expires_at > Utc::now() {
                Some(SessionData {
                    user_id: s.user_id.clone(),
                    username: s.username.clone(),
                    expires_at: s.expires_at,
                    created_at: s.created_at,
                    ip_address: s.ip_address.clone(),
                    user_agent: s.user_agent.clone(),
                })
            } else {
                None
            }
        }).flatten();

        if let Some(data) = session_data {
            let now = Utc::now();
            let remaining = data.expires_at.signed_duration_since(now);
            let total_duration = data.expires_at.signed_duration_since(data.created_at);
            let elapsed_ratio = 1.0 - (remaining.num_seconds() as f64 / total_duration.num_seconds() as f64);
            
            if elapsed_ratio > self.session_refresh_threshold {
                let new_session_id = Uuid::new_v4().to_string();
                let expires_at = Utc::now() + chrono::Duration::seconds(self.session_duration_secs as i64);
                let new_csrf_token = Uuid::new_v4().to_string();
                
                store.sessions.remove(session_id);
                
                let new_session = Session {
                    id: new_session_id.clone(),
                    user_id: data.user_id.clone(),
                    username: data.username.clone(),
                    created_at: now,
                    expires_at,
                    ip_address: data.ip_address.clone(),
                    user_agent: data.user_agent.clone(),
                    csrf_token: Some(new_csrf_token),
                };
                
                store.sessions.insert(new_session_id.clone(), new_session);
                
                self.save_store(&store).await;
                
                return Some(SessionInfo {
                    id: new_session_id,
                    user_id: data.user_id,
                    username: data.username,
                    expires_at,
                });
            }
            
            return Some(SessionInfo {
                id: session_id.to_string(),
                user_id: data.user_id,
                username: data.username,
                expires_at: data.expires_at,
            });
        } else {
            if store.sessions.contains_key(session_id) {
                store.sessions.remove(session_id);
                self.save_store(&store).await;
            }
        }
        
        None
    }

    pub async fn validate_session_with_ip(&self, session_id: &str, client_ip: &str) -> Option<SessionInfo> {
        let mut store = self.store.write().await;
        
        let session_data = store.sessions.get(session_id).map(|s| {
            if s.expires_at > Utc::now() {
                Some(SessionData {
                    user_id: s.user_id.clone(),
                    username: s.username.clone(),
                    expires_at: s.expires_at,
                    created_at: s.created_at,
                    ip_address: s.ip_address.clone(),
                    user_agent: s.user_agent.clone(),
                })
            } else {
                None
            }
        }).flatten();

        if let Some(data) = session_data {
            if data.ip_address.as_deref() != Some(client_ip) {
                tracing::warn!("Session {} used from IP {} but was created from IP {:?} - possible session hijacking", 
                    session_id, client_ip, data.ip_address);
                store.sessions.remove(session_id);
                self.save_store(&store).await;
                return None;
            }

            let now = Utc::now();
            let remaining = data.expires_at.signed_duration_since(now);
            let total_duration = data.expires_at.signed_duration_since(data.created_at);
            let elapsed_ratio = 1.0 - (remaining.num_seconds() as f64 / total_duration.num_seconds() as f64);
            
            if elapsed_ratio > self.session_refresh_threshold {
                let new_session_id = Uuid::new_v4().to_string();
                let expires_at = Utc::now() + chrono::Duration::seconds(self.session_duration_secs as i64);
                let new_csrf_token = Uuid::new_v4().to_string();
                
                store.sessions.remove(session_id);
                
                let new_session = Session {
                    id: new_session_id.clone(),
                    user_id: data.user_id.clone(),
                    username: data.username.clone(),
                    created_at: now,
                    expires_at,
                    ip_address: data.ip_address.clone(),
                    user_agent: data.user_agent.clone(),
                    csrf_token: Some(new_csrf_token),
                };
                
                store.sessions.insert(new_session_id.clone(), new_session);
                
                self.save_store(&store).await;
                
                return Some(SessionInfo {
                    id: new_session_id,
                    user_id: data.user_id,
                    username: data.username,
                    expires_at,
                });
            }
            
            return Some(SessionInfo {
                id: session_id.to_string(),
                user_id: data.user_id,
                username: data.username,
                expires_at: data.expires_at,
            });
        } else {
            if store.sessions.contains_key(session_id) {
                store.sessions.remove(session_id);
                self.save_store(&store).await;
            }
        }
        
        None
    }

    pub async fn destroy_session(&self, session_id: &str) {
        let mut store = self.store.write().await;
        store.sessions.remove(session_id);
        self.save_store(&store).await;
    }

    pub async fn get_login_logs(&self, limit: usize) -> Vec<LoginLog> {
        let store = self.store.read().await;
        store.login_logs.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    pub async fn get_active_sessions(&self) -> Vec<SessionInfo> {
        let store = self.store.read().await;
        
        let now = Utc::now();
        store.sessions.values()
            .filter(|s| s.expires_at > now)
            .map(|s| SessionInfo {
                id: s.id.clone(),
                user_id: s.user_id.clone(),
                username: s.username.clone(),
                expires_at: s.expires_at,
            })
            .collect()
    }

    pub async fn cleanup_expired_sessions(&self) {
        let mut store = self.store.write().await;
        
        store.sessions.retain(|_, s| s.expires_at > Utc::now());
        
        for user in store.users.values_mut() {
            if let Some(locked_until) = user.locked_until {
                if locked_until < Utc::now() {
                    user.locked_until = None;
                    user.failed_attempts = 0;
                }
            }
        }
        
        self.save_store(&store).await;
    }

    pub fn max_failed_attempts(&self) -> u32 {
        self.max_failed_attempts
    }

    pub fn lockout_duration_secs(&self) -> u64 {
        self.lockout_duration_secs
    }

    pub async fn validate_csrf_token(&self, session_id: &str, csrf_token: &str) -> bool {
        let store = self.store.read().await;
        
        if let Some(session) = store.sessions.get(session_id) {
            if session.expires_at > Utc::now() {
                return session.csrf_token.as_deref() == Some(csrf_token);
            }
        }
        
        false
    }

    pub async fn get_csrf_token(&self, session_id: &str) -> Option<String> {
        let store = self.store.read().await;
        store.sessions.get(session_id).and_then(|s| s.csrf_token.clone())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: UserRole,
    pub sites: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub failed_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub expires_at: DateTime<Utc>,
}

struct SessionData {
    user_id: String,
    username: String,
    expires_at: chrono::DateTime<Utc>,
    created_at: chrono::DateTime<Utc>,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    InvalidCredentials,
    UserAlreadyExists,
    UserNotFound,
    InvalidUsername,
    PasswordTooShort(usize),
    AccountLocked(DateTime<Utc>),
    HashingError,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "Invalid username or password"),
            AuthError::UserAlreadyExists => write!(f, "User already exists"),
            AuthError::UserNotFound => write!(f, "User not found"),
            AuthError::InvalidUsername => write!(f, "Invalid username"),
            AuthError::PasswordTooShort(len) => write!(f, "Password must be at least {} characters", len),
            AuthError::AccountLocked(until) => write!(f, "Account locked until {}", until),
            AuthError::HashingError => write!(f, "Password hashing error"),
        }
    }
}
