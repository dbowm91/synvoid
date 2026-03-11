use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub mod basic;
pub use basic::{BasicAuthManager, BasicAuthResult};

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
}

impl AuthManager {
    pub fn new(
        data_dir: PathBuf,
        session_duration_secs: u64,
        max_failed_attempts: u32,
        lockout_duration_secs: u64,
    ) -> Self {
        let store = Self::load_store(&data_dir);
        
        Self {
            data_dir,
            store: Arc::new(RwLock::new(store)),
            session_duration_secs,
            max_failed_attempts,
            lockout_duration_secs,
            min_password_length: 8,
        }
    }

    fn load_store(data_dir: &PathBuf) -> AuthStore {
        let store_path = data_dir.join("auth").join("store.json");
        
        if store_path.exists() {
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
        let store_path = self.data_dir.join("auth").join("store.json");
        
        if let Some(parent) = store_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        
        match serde_json::to_string_pretty(store) {
            Ok(content) => {
                if let Err(e) = fs::write(&store_path, content) {
                    tracing::error!("Failed to write auth store: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to serialize auth store: {}", e);
            }
        }
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
        
        let check_result = {
            let mut store = self.store.write().await;
            
            let user = store.users.get_mut(&username_key)
                .ok_or(AuthError::InvalidCredentials)?;
            
            if let Some(locked_until) = user.locked_until {
                if locked_until > Utc::now() {
                    return Err(AuthError::AccountLocked(locked_until));
                } else {
                    user.locked_until = None;
                    user.failed_attempts = 0;
                }
            }
            
            let stored_hash = user.password_hash.clone();
            let user_id = user.id.clone();
            (stored_hash, user_id)
        };
        
        let password_valid = verify(password, &check_result.0)
            .map_err(|_| AuthError::HashingError)?;
        
        if !password_valid {
            let ip_str = ip_address.map(|s| s.to_string());
            let ua_str = user_agent.map(|s| s.to_string());
            
            let mut store = self.store.write().await;
            
            if let Some(user) = store.users.get_mut(&username_key) {
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
            }
            
            return Err(AuthError::InvalidCredentials);
        }
        
        let ip_str = ip_address.map(|s| s.to_string());
        let ua_str = user_agent.map(|s| s.to_string());
        
        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id: check_result.1,
            username: username.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(self.session_duration_secs as i64),
            ip_address: ip_str.clone(),
            user_agent: ua_str.clone(),
        };
        
        let mut store = self.store.write().await;
        
        if let Some(user) = store.users.get_mut(&username_key) {
            user.last_login = Some(Utc::now());
            user.failed_attempts = 0;
            user.locked_until = None;
        }
        
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
        let session_result = {
            let mut store = self.store.write().await;
            
            if let Some(session) = store.sessions.get_mut(session_id) {
                if session.expires_at > Utc::now() {
                    let info = SessionInfo {
                        id: session.id.clone(),
                        user_id: session.user_id.clone(),
                        username: session.username.clone(),
                        expires_at: session.expires_at,
                    };
                    session.expires_at = Utc::now() + chrono::Duration::seconds(self.session_duration_secs as i64);
                    self.save_store(&store).await;
                    return Some(info);
                } else {
                    store.sessions.remove(session_id);
                    self.save_store(&store).await;
                }
            }
            
            None
        };
        
        session_result
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
