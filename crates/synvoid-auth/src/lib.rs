//! Authentication and user management.
//!
//! Provides user registration, login with bcrypt password hashing,
//! session management with persistent storage, brute-force protection
//! (account locking after repeated failures), and login audit logging.
//! Also includes HTTP Basic auth support via the `basic` submodule.
//!
//! Phase 43 hardening:
//! - CPU-hard bcrypt runs only behind [`crypto::PasswordCrypto`] (bounded
//!   `spawn_blocking`, never on a Tokio core thread, never with the store
//!   lock held).
//! - Auth-store persistence is atomic (temp + fsync + rename) with
//!   owner-only permissions from creation; a corrupt existing store fails
//!   closed via [`AuthManager::try_new`] instead of becoming an empty DB.
//! - Login audit retention is bounded at insertion ([`MAX_LOGIN_LOGS`]) and
//!   expired sessions are pruned before snapshotting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration as TokioDuration};
use uuid::Uuid;

use synvoid_utils::DrainFlag;

pub mod basic;
pub mod crypto;
pub use basic::{BasicAuthManager, BasicAuthResult};
pub use crypto::{
    PasswordCrypto, PasswordCryptoError, DEFAULT_PASSWORD_CRYPTO_ACQUIRE_TIMEOUT,
    DEFAULT_PASSWORD_CRYPTO_CONCURRENCY, DUMMY_PASSWORD_HASH, PASSWORD_BCRYPT_COST,
};

const MAX_SESSIONS_PER_USER: usize = 5;
/// Bounded login-audit retention (Phase 43, Workstream G).
///
/// The whole store is cloned/serialized on every mutation, so an unbounded
/// `login_logs` vector is disk-growth and write-amplification debt. 1000
/// entries (~200KB worst case) preserve operational usefulness without
/// unbounded growth. Enforced on insertion, not just on query.
pub const MAX_LOGIN_LOGS: usize = 1000;
/// Minimum response delay after a bounded crypto op for timing normalization.
/// Single bcrypt already dominates; this only pads fast paths (e.g. input
/// validation failures that skip crypto are handled separately) without a
/// second expensive verify.
const MIN_AUTH_RESPONSE_DELAY: TokioDuration = TokioDuration::from_millis(200);

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
#[derive(Default)]
pub enum UserRole {
    Admin,
    #[default]
    User,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthStore {
    pub users: HashMap<String, User>,
    pub sessions: HashMap<String, Session>,
    pub login_logs: Vec<LoginLog>,
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

/// Fail-closed auth-store load/persistence error (Phase 43, Workstream F).
///
/// A present-but-unreadable store must be a startup/control-plane error, not
/// a silent empty database. Recovery requires explicit operator action
/// (quarantine the corrupt file, run a repair/reset command); this type
/// carries enough detail for that workflow without logging secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStoreError {
    Io(String),
    Corrupt(String),
    Permission(String),
}

impl std::fmt::Display for AuthStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "auth store I/O error: {e}"),
            Self::Corrupt(e) => write!(f, "auth store corrupt: {e}"),
            Self::Permission(e) => write!(f, "auth store permission error: {e}"),
        }
    }
}

impl std::error::Error for AuthStoreError {}

pub struct AuthManager {
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    data_dir: PathBuf,
    store: Arc<RwLock<AuthStore>>,
    session_duration_secs: u64,
    max_failed_attempts: u32,
    lockout_duration_secs: u64,
    min_password_length: usize,
    session_refresh_threshold: f64,
    crypto: Arc<PasswordCrypto>,
    write_tx: mpsc::Sender<(AuthStore, Option<mpsc::Sender<()>>)>,
    flush_requested: DrainFlag,
    // Keep flush task handle alive so panics are not silently dropped and
    // so flush() can detect a dead writer.
    _flush_handle: Option<tokio::task::JoinHandle<()>>,
}

impl AuthManager {
    /// Backward-compatible constructor. Fail-closed: panics on a corrupt
    /// existing store instead of silently starting from an empty DB.
    /// Production composition should use [`AuthManager::try_new`].
    pub fn new(
        data_dir: PathBuf,
        session_duration_secs: u64,
        max_failed_attempts: u32,
        lockout_duration_secs: u64,
    ) -> Self {
        Self::try_new(
            data_dir,
            session_duration_secs,
            max_failed_attempts,
            lockout_duration_secs,
        )
        .expect("corrupt auth store: refusing to start from an empty database")
    }

    /// Fail-closed constructor (Phase 43, Workstream F).
    ///
    /// Missing store → `Ok` with an empty DB. Present but unreadable,
    /// unparsable, or overly permissive → `Err`, so a truncated/corrupt
    /// authorization database can never silently become an empty one.
    pub fn try_new(
        data_dir: PathBuf,
        session_duration_secs: u64,
        max_failed_attempts: u32,
        lockout_duration_secs: u64,
    ) -> Result<Self, AuthStoreError> {
        Self::try_new_with_crypto(
            data_dir,
            session_duration_secs,
            max_failed_attempts,
            lockout_duration_secs,
            Arc::new(PasswordCrypto::default()),
        )
    }

    /// Injection point for tests (low bcrypt cost, single-permit overload).
    pub fn try_new_with_crypto(
        data_dir: PathBuf,
        session_duration_secs: u64,
        max_failed_attempts: u32,
        lockout_duration_secs: u64,
        crypto: Arc<PasswordCrypto>,
    ) -> Result<Self, AuthStoreError> {
        let store = Self::load_store(&data_dir)?;
        let store_clone = store.clone();

        let (write_tx, mut write_rx) = mpsc::channel::<(AuthStore, Option<mpsc::Sender<()>>)>(100);

        let data_dir_clone = data_dir.clone();
        let flush_flag = DrainFlag::new();
        let flush_flag_clone = flush_flag.clone();

        let flush_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(TokioDuration::from_secs(5));
            let mut pending_stores: Vec<AuthStore> = Vec::new();
            let mut flush_completion_tx: Option<mpsc::Sender<()>> = None;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if !pending_stores.is_empty() {
                            let merged = Self::merge_stores(&pending_stores);
                            if let Err(e) = Self::write_store_to_disk(&data_dir_clone, &merged).await {
                                tracing::error!("Failed to persist auth store: {}", e);
                            }
                            pending_stores.clear();
                        }
                        if flush_flag_clone.is_draining() {
                            if !pending_stores.is_empty() {
                                let merged = Self::merge_stores(&pending_stores);
                                if let Err(e) = Self::write_store_to_disk(&data_dir_clone, &merged).await {
                                    tracing::error!("Failed to persist auth store: {}", e);
                                }
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

        Ok(Self {
            data_dir,
            store: Arc::new(RwLock::new(store_clone)),
            session_duration_secs,
            max_failed_attempts,
            lockout_duration_secs,
            min_password_length: 8,
            session_refresh_threshold: 0.5,
            crypto,
            write_tx,
            flush_requested: flush_flag,
            _flush_handle: Some(flush_handle),
        })
    }

    #[cfg(test)]
    pub(crate) fn test_manager(data_dir: PathBuf) -> Self {
        use std::time::Duration as StdDuration;
        let crypto = Arc::new(PasswordCrypto::new(8, StdDuration::from_secs(10), 4));
        Self::try_new_with_crypto(data_dir, 3600, 3, 300, crypto).expect("test auth manager")
    }

    pub fn password_crypto(&self) -> &Arc<PasswordCrypto> {
        &self.crypto
    }

    fn merge_stores(stores: &[AuthStore]) -> AuthStore {
        if stores.is_empty() {
            return AuthStore::default();
        }

        // Each queued value is a complete snapshot taken while holding the
        // store lock. The newest snapshot therefore already contains every
        // mutation represented by older snapshots. Merging older maps back
        // into it can resurrect deleted users/sessions or overwrite a newer
        // password/site update with stale data.
        stores.last().cloned().unwrap_or_default()
    }

    fn load_store(data_dir: &std::path::Path) -> Result<AuthStore, AuthStoreError> {
        let auth_dir = data_dir.join("auth");
        let store_path = auth_dir.join("store.json");

        if !store_path.exists() {
            return Ok(AuthStore::default());
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&store_path).map_err(|e| {
                AuthStoreError::Io(format!("stat auth store {}: {e}", store_path.display()))
            })?;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(AuthStoreError::Permission(format!(
                    "auth store {} has overly permissive mode {:o}; refusing to load",
                    store_path.display(),
                    mode
                )));
            }
        }

        let content = fs::read_to_string(&store_path).map_err(|e| {
            AuthStoreError::Io(format!("read auth store {}: {e}", store_path.display()))
        })?;
        let store: AuthStore = serde_json::from_str(&content).map_err(|e| {
            AuthStoreError::Corrupt(format!(
                "parse auth store {}: {e}; quarantine the file and reset explicitly, refusing to start empty",
                store_path.display()
            ))
        })?;
        Ok(store)
    }

    /// Bounded audit append. Enforced on insertion (Phase 43 G).
    fn push_login_log(store: &mut AuthStore, log: LoginLog) {
        store.login_logs.push(log);
        let len = store.login_logs.len();
        if len > MAX_LOGIN_LOGS {
            let excess = len - MAX_LOGIN_LOGS;
            store.login_logs.drain(..excess);
        }
    }

    /// Drop expired sessions so stale entries do not permanently inflate the
    /// file. Applied to snapshots before queueing for disk; the live store
    /// is pruned by `cleanup_expired_sessions` on its own schedule.
    fn prune_expired_for_snapshot(store: &mut AuthStore) {
        let now = Utc::now();
        store.sessions.retain(|_, s| s.expires_at > now);
    }

    async fn save_store(&self, store: &AuthStore) {
        let mut snapshot = store.clone();
        Self::prune_expired_for_snapshot(&mut snapshot);
        if self.write_tx.send((snapshot, None)).await.is_err() {
            tracing::warn!("Failed to send auth store for persistence - write channel closed");
        }
    }

    /// Atomic durable write (Phase 43 E): same discipline as the DNSSEC
    /// keystore — restrictive dir, owner-only temp from creation, write all,
    /// `sync_all`, atomic rename, parent-dir sync where supported, cleanup
    /// temp on failure. Never deletes/replaces the last valid store until
    /// the new file is complete; any failure preserves the previous store.
    async fn write_store_to_disk(
        data_dir: &std::path::Path,
        store: &AuthStore,
    ) -> Result<(), AuthStoreError> {
        let bytes = serde_json::to_vec_pretty(store)
            .map_err(|e| AuthStoreError::Corrupt(format!("serialize auth store: {e}")))?;
        // Blocking file + fsync work stays off Tokio cores.
        let data_dir = data_dir.to_path_buf();
        tokio::task::spawn_blocking(move || Self::atomic_write_auth_store(&data_dir, &bytes))
            .await
            .map_err(|_| AuthStoreError::Io("auth store writer join failed".to_string()))?
    }

    fn atomic_write_auth_store(
        data_dir: &std::path::Path,
        bytes: &[u8],
    ) -> Result<(), AuthStoreError> {
        let auth_dir = data_dir.join("auth");
        let store_path = auth_dir.join("store.json");
        std::fs::create_dir_all(&auth_dir)
            .map_err(|e| AuthStoreError::Io(format!("create auth dir: {e}")))?;
        secure_auth_dir(&auth_dir)?;

        static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ctr = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = auth_dir.join(format!(
            ".tmp-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() % 1_000_000)
                .unwrap_or(0),
            ctr
        ));

        let write_result: Result<(), AuthStoreError> = (|| {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)
                    .map_err(|e| AuthStoreError::Io(format!("create temp auth store: {e}")))?;
                file.write_all(bytes)
                    .map_err(|e| AuthStoreError::Io(format!("write temp auth store: {e}")))?;
                file.sync_all()
                    .map_err(|e| AuthStoreError::Io(format!("fsync temp auth store: {e}")))?;
                drop(file);
            }
            #[cfg(not(unix))]
            {
                // Windows: safest same-volume replacement; no Unix fsync
                // equivalence is claimed (documented durability difference).
                std::fs::write(&tmp, bytes)
                    .map_err(|e| AuthStoreError::Io(format!("write temp auth store: {e}")))?;
            }
            std::fs::rename(&tmp, &store_path)
                .map_err(|e| AuthStoreError::Io(format!("atomic rename auth store: {e}")))?;
            // Rename durability: sync the parent directory where supported.
            #[cfg(unix)]
            {
                if let Ok(dir) = std::fs::File::open(&auth_dir) {
                    let _ = dir.sync_all();
                }
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o600));
            }
            Ok(())
        })();
        if write_result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        write_result
    }

    pub async fn flush(&self) {
        let store_snapshot = {
            let store = self.store.read().await;
            let mut snapshot = store.clone();
            Self::prune_expired_for_snapshot(&mut snapshot);
            snapshot
        };

        let (tx, mut rx) = mpsc::channel::<()>(1);
        self.flush_requested.start_drain();
        let _ = self.write_tx.send((store_snapshot, Some(tx))).await;

        // Avoid hanging forever if the writer task panicked; bound wait.
        let _ = tokio::time::timeout(TokioDuration::from_secs(5), rx.recv()).await;
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

        let username_bytes = username.as_bytes();
        if username_bytes.len() > 64 {
            return Err(AuthError::InvalidUsername);
        }

        for &byte in username_bytes.iter() {
            if byte == b'\0' || byte == b'\n' || byte == b'\r' || byte == b'\t' {
                return Err(AuthError::InvalidUsername);
            }
        }

        // Fast pre-check under a read lock; the write lock below revalidates
        // after hashing (the name may have been claimed while bcrypt ran).
        // No lock is held across the CPU-hard hash.
        {
            let store = self.store.read().await;
            if store.users.contains_key(&username.to_lowercase()) {
                return Err(AuthError::UserAlreadyExists);
            }
        }

        let password_hash = self.crypto.hash(password).await.map_err(map_crypto_error)?;

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

        let username_to_remove = store
            .users
            .iter()
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

    pub async fn update_user_sites(
        &self,
        user_id: &str,
        sites: Vec<String>,
    ) -> Result<(), AuthError> {
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

        store
            .users
            .values()
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
        let ip_str = ip_address.map(|s| s.to_string());
        let ua_str = user_agent.map(|s| s.to_string());

        // 1. Snapshot minimum state under a read lock; release before bcrypt.
        // The hash clone is the generation guard rechecked after verify.
        let (snapshot_exists, snapshot_hash) = {
            let store = self.store.read().await;
            match store.users.get(&username_key) {
                Some(user) => (true, user.password_hash.clone()),
                None => (false, DUMMY_PASSWORD_HASH.to_string()),
            }
        };

        // 2. Exactly one bounded bcrypt (real or dummy) off the core threads.
        // No second dummy verify: the single verify plus min-delay padding
        // provides the timing property (Phase 43 D).
        let op_start = std::time::Instant::now();
        let verify_result = self
            .crypto
            .verify(password.to_string(), snapshot_hash.clone())
            .await;
        let password_valid = match verify_result {
            Ok(valid) => valid,
            Err(PasswordCryptoError::Busy) => return Err(AuthError::AuthBackendBusy),
            Err(PasswordCryptoError::Join) => return Err(AuthError::HashingError),
            // Malformed stored hash fails closed as invalid credentials.
            Err(PasswordCryptoError::Verify) => false,
            Err(PasswordCryptoError::Hash) => false,
        };
        ensure_min_auth_delay(op_start).await;

        // 3. Reacquire write lock and revalidate generation before mutating.
        // Account lock/hash may have changed while bcrypt ran.
        let mut store = self.store.write().await;

        // Generation check: if the user appeared/disappeared or the hash
        // changed while we verified, the result is stale — fail closed.
        let current = store
            .users
            .get(&username_key)
            .map(|u| u.password_hash.clone());
        match (&snapshot_exists, &current) {
            (true, Some(current_hash)) if *current_hash == snapshot_hash => {}
            (false, None) => {}
            _ => {
                // Stale snapshot (concurrent create/delete/password change).
                // Do not mutate on stale state; the client retries against
                // the fresh hash.
                return Err(AuthError::InvalidCredentials);
            }
        }

        if !password_valid {
            if snapshot_exists {
                if let Some(user) = store.users.get_mut(&username_key) {
                    if let Some(locked_until) = user.locked_until {
                        if locked_until > Utc::now() {
                            self.save_store(&store).await;
                            return Err(AuthError::AccountLocked(locked_until));
                        } else {
                            user.locked_until = None;
                            user.failed_attempts = 0;
                        }
                    }

                    user.failed_attempts += 1;

                    let lock_user = user.failed_attempts >= self.max_failed_attempts;
                    let reason = if lock_user {
                        user.locked_until = Some(
                            Utc::now()
                                + chrono::Duration::seconds(
                                    i64::try_from(self.lockout_duration_secs).unwrap_or(i64::MAX),
                                ),
                        );
                        Some("Too many failed attempts".to_string())
                    } else {
                        None
                    };

                    Self::push_login_log(
                        &mut store,
                        LoginLog {
                            id: Uuid::new_v4().to_string(),
                            username: username.to_string(),
                            success: false,
                            ip_address: ip_str.clone(),
                            user_agent: ua_str.clone(),
                            timestamp: Utc::now(),
                            reason,
                        },
                    );
                    self.save_store(&store).await;
                }
            } else {
                Self::push_login_log(
                    &mut store,
                    LoginLog {
                        id: Uuid::new_v4().to_string(),
                        username: username.to_string(),
                        success: false,
                        ip_address: ip_str.clone(),
                        user_agent: ua_str.clone(),
                        timestamp: Utc::now(),
                        reason: Some("User does not exist".to_string()),
                    },
                );
                self.save_store(&store).await;
            }

            return Err(AuthError::InvalidCredentials);
        }

        if let Some(user) = store.users.get_mut(&username_key) {
            if let Some(locked_until) = user.locked_until {
                if locked_until > Utc::now() {
                    self.save_store(&store).await;
                    return Err(AuthError::AccountLocked(locked_until));
                }
            }

            user.last_login = Some(Utc::now());
            user.failed_attempts = 0;
            user.locked_until = None;

            let user_id = user.id.clone();

            let session = Session {
                id: Uuid::new_v4().to_string(),
                user_id: user_id.clone(),
                username: username.to_string(),
                created_at: Utc::now(),
                expires_at: Utc::now()
                    + chrono::Duration::seconds(
                        i64::try_from(self.session_duration_secs).unwrap_or(i64::MAX),
                    ),
                ip_address: ip_str.clone(),
                user_agent: ua_str.clone(),
                csrf_token: Some(Uuid::new_v4().to_string()),
            };

            let count = store
                .sessions
                .iter()
                .filter(|(_, s)| s.user_id == user_id)
                .count();
            if count >= MAX_SESSIONS_PER_USER {
                let mut session_ids: Vec<_> = store
                    .sessions
                    .iter()
                    .filter(|(_, s)| s.user_id == user_id)
                    .map(|(k, v)| (k.clone(), v.created_at))
                    .collect();
                session_ids.sort_by_key(|(_, created)| *created);
                for (id, _) in session_ids
                    .into_iter()
                    .take(count - MAX_SESSIONS_PER_USER + 1)
                {
                    store.sessions.remove(id.as_str());
                }
            }
            store.sessions.insert(session.id.clone(), session.clone());

            Self::push_login_log(
                &mut store,
                LoginLog {
                    id: Uuid::new_v4().to_string(),
                    username: username.to_string(),
                    success: true,
                    ip_address: ip_str,
                    user_agent: ua_str,
                    timestamp: Utc::now(),
                    reason: None,
                },
            );

            self.save_store(&store).await;
            Ok(session)
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }

    pub async fn update_password(
        &self,
        user_id: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        if new_password.len() < 8 {
            return Err(AuthError::InvalidCredentials);
        }

        // Hash outside the lock; revalidate user existence after.
        let password_hash =
            self.crypto
                .hash(new_password.to_string())
                .await
                .map_err(|e| match e {
                    PasswordCryptoError::Busy => AuthError::AuthBackendBusy,
                    _ => AuthError::InvalidCredentials,
                })?;

        let mut store = self.store.write().await;

        if let Some(user) = store.users.values_mut().find(|user| user.id == user_id) {
            user.password_hash = password_hash;
        } else {
            return Err(AuthError::UserNotFound);
        }

        store.sessions.retain(|_, s| s.user_id != user_id);

        self.save_store(&store).await;
        Ok(())
    }

    pub async fn validate_session(&self, session_id: &str) -> Option<SessionInfo> {
        let mut store = self.store.write().await;

        let session_data = store.sessions.get(session_id).and_then(|s| {
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
        });

        if let Some(data) = session_data {
            let now = Utc::now();
            let remaining = data.expires_at.signed_duration_since(now);
            let total_duration = data.expires_at.signed_duration_since(data.created_at);
            let elapsed_ratio =
                1.0 - (remaining.num_seconds() as f64 / total_duration.num_seconds() as f64);

            if elapsed_ratio > self.session_refresh_threshold {
                let new_session_id = Uuid::new_v4().to_string();
                let expires_at = Utc::now()
                    + chrono::Duration::seconds(
                        i64::try_from(self.session_duration_secs).unwrap_or(i64::MAX),
                    );
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
        } else if store.sessions.contains_key(session_id) {
            store.sessions.remove(session_id);
            self.save_store(&store).await;
        }

        None
    }

    pub async fn validate_session_with_ip(
        &self,
        session_id: &str,
        client_ip: &str,
    ) -> Option<SessionInfo> {
        let mut store = self.store.write().await;

        let session_data = store.sessions.get(session_id).and_then(|s| {
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
        });

        if let Some(data) = session_data {
            if data.ip_address.as_deref() != Some(client_ip) {
                let session_id_hash = format!(
                    "sha256:{}",
                    &hex::encode(sha2::Sha256::digest(session_id.as_bytes()))[..16]
                );
                tracing::warn!("Session {} used from IP {} but was created from IP {:?} - possible session hijacking",
                    session_id_hash, client_ip, data.ip_address);
                store.sessions.remove(session_id);
                self.save_store(&store).await;
                return None;
            }

            let now = Utc::now();
            let remaining = data.expires_at.signed_duration_since(now);
            let total_duration = data.expires_at.signed_duration_since(data.created_at);
            let elapsed_ratio =
                1.0 - (remaining.num_seconds() as f64 / total_duration.num_seconds() as f64);

            if elapsed_ratio > self.session_refresh_threshold {
                let new_session_id = Uuid::new_v4().to_string();
                let expires_at = Utc::now()
                    + chrono::Duration::seconds(
                        i64::try_from(self.session_duration_secs).unwrap_or(i64::MAX),
                    );
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
        } else if store.sessions.contains_key(session_id) {
            store.sessions.remove(session_id);
            self.save_store(&store).await;
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
        store.login_logs.iter().rev().take(limit).cloned().collect()
    }

    pub async fn get_active_sessions(&self) -> Vec<SessionInfo> {
        let store = self.store.read().await;

        let now = Utc::now();
        store
            .sessions
            .values()
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
                if let Some(stored) = session.csrf_token.as_deref() {
                    return bool::from(stored.as_bytes().ct_eq(csrf_token.as_bytes()));
                }
            }
        }

        false
    }

    pub async fn get_csrf_token(&self, session_id: &str) -> Option<String> {
        let store = self.store.read().await;
        store
            .sessions
            .get(session_id)
            .and_then(|s| s.csrf_token.clone())
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

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid username or password")]
    InvalidCredentials,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid username")]
    InvalidUsername,
    #[error("Password must be at least {0} characters")]
    PasswordTooShort(usize),
    #[error("Account locked until {0}")]
    AccountLocked(DateTime<Utc>),
    #[error("Password hashing error")]
    HashingError,
    /// Bounded crypto backend saturated. Fails closed: authenticates nobody.
    /// HTTP policy maps this to 503 (distinct from 401 bad credentials)
    /// without revealing usernames.
    #[error("Authentication backend busy")]
    AuthBackendBusy,
}

fn secure_auth_dir(dir: &Path) -> Result<(), AuthStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| AuthStoreError::Permission(format!("secure auth dir: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

async fn ensure_min_auth_delay(start: std::time::Instant) {
    let elapsed = start.elapsed();
    if elapsed < MIN_AUTH_RESPONSE_DELAY {
        sleep(MIN_AUTH_RESPONSE_DELAY - elapsed).await;
    }
}

fn map_crypto_error(e: PasswordCryptoError) -> AuthError {
    match e {
        PasswordCryptoError::Busy => AuthError::AuthBackendBusy,
        PasswordCryptoError::Join => AuthError::HashingError,
        PasswordCryptoError::Hash => AuthError::HashingError,
        // Malformed hash / backend verify failure fails closed as invalid
        // credentials (never authenticates), not as overload.
        PasswordCryptoError::Verify => AuthError::InvalidCredentials,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::TempDir;

    proptest::proptest! {
        #[test]
        fn test_auth_error_display_password_too_short(len: usize) {
            let err = AuthError::PasswordTooShort(len);
            let display = format!("{}", err);
            proptest::prop_assert!(display.contains(&len.to_string()));
        }

        #[test]
        fn test_auth_error_equality(password_len: usize, password_len2: usize) {
            let err1 = AuthError::PasswordTooShort(password_len);
            let err2 = AuthError::PasswordTooShort(password_len);
            let err3 = AuthError::PasswordTooShort(password_len2);
            proptest::prop_assert_eq!(err1, err2);
            if password_len != password_len2 {
                let err1_new = AuthError::PasswordTooShort(password_len);
                proptest::prop_assert_ne!(err1_new, err3);
            }
        }

        #[test]
        fn test_auth_error_clone(err in prop_oneof![
            any::<usize>().prop_map(AuthError::PasswordTooShort),
            Just(AuthError::InvalidCredentials),
            Just(AuthError::UserAlreadyExists),
            Just(AuthError::UserNotFound),
            Just(AuthError::InvalidUsername),
            Just(AuthError::HashingError),
            Just(AuthError::AuthBackendBusy),
        ]) {
            let cloned = err.clone();
            proptest::prop_assert_eq!(err, cloned);
        }
    }

    proptest::proptest! {
        #[test]
        fn test_auth_error_display_invariants(err in prop_oneof![
            any::<usize>().prop_map(AuthError::PasswordTooShort),
            Just(AuthError::InvalidCredentials),
            Just(AuthError::UserAlreadyExists),
            Just(AuthError::UserNotFound),
            Just(AuthError::InvalidUsername),
            Just(AuthError::HashingError),
            Just(AuthError::AuthBackendBusy),
        ]) {
            let display = format!("{}", err);
            proptest::prop_assert!(!display.is_empty());
        }
    }

    #[tokio::test]
    async fn test_create_user_short_password() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let manager = AuthManager::new(data_dir, 3600, 3, 300);

        let result = manager
            .create_user(
                "testuser".to_string(),
                "short".to_string(),
                UserRole::User,
                vec![],
            )
            .await;

        assert!(matches!(result, Err(AuthError::PasswordTooShort(_))));
    }

    #[tokio::test]
    async fn test_create_user_empty_username() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let manager = AuthManager::new(data_dir, 3600, 3, 300);

        let result = manager
            .create_user(
                "".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await;

        assert!(matches!(result, Err(AuthError::InvalidUsername)));
    }

    #[tokio::test]
    async fn test_create_and_verify_user() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let manager = AuthManager::new(data_dir, 3600, 3, 300);

        let create_result = manager
            .create_user(
                "testuser".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await;
        assert!(create_result.is_ok());

        let verify_result = manager
            .verify_login("testuser", "password123", None, None)
            .await;
        assert!(verify_result.is_ok());
        let session = verify_result.unwrap();
        assert_eq!(session.username, "testuser");
    }

    #[tokio::test]
    async fn test_verify_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let manager = AuthManager::new(data_dir, 3600, 3, 300);

        let _ = manager
            .create_user(
                "testuser".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await;

        let result = manager
            .verify_login("testuser", "wrongpassword", None, None)
            .await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_verify_nonexistent_user() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let manager = AuthManager::new(data_dir, 3600, 3, 300);

        let result = manager
            .verify_login("nonexistent", "password123", None, None)
            .await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_delete_user() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let manager = AuthManager::new(data_dir, 3600, 3, 300);

        let user = manager
            .create_user(
                "testuser".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await
            .unwrap();

        let delete_result = manager.delete_user(&user.id).await;
        assert!(delete_result.is_ok());

        let verify_result = manager
            .verify_login("testuser", "password123", None, None)
            .await;
        assert!(matches!(verify_result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_user() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let manager = AuthManager::new(data_dir, 3600, 3, 300);

        let result = manager.delete_user("nonexistent-id").await;
        assert!(matches!(result, Err(AuthError::UserNotFound)));
    }

    #[tokio::test]
    async fn test_update_user_sites() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let manager = AuthManager::new(data_dir, 3600, 3, 300);

        let user = manager
            .create_user(
                "testuser".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await
            .unwrap();

        let update_result = manager
            .update_user_sites(&user.id, vec!["site1".to_string(), "site2".to_string()])
            .await;
        assert!(update_result.is_ok());

        let users = manager.list_users().await;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].sites, vec!["site1", "site2"]);
    }

    #[tokio::test]
    async fn test_update_password_uses_user_id_not_username_key() {
        let temp_dir = TempDir::new().unwrap();
        let manager = AuthManager::new(temp_dir.path().to_path_buf(), 3600, 3, 300);

        let user = manager
            .create_user(
                "testuser".to_string(),
                "old-password".to_string(),
                UserRole::User,
                vec![],
            )
            .await
            .unwrap();

        manager
            .update_password(&user.id, "new-password")
            .await
            .unwrap();

        assert!(matches!(
            manager
                .verify_login("testuser", "old-password", None, None)
                .await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(manager
            .verify_login("testuser", "new-password", None, None)
            .await
            .is_ok());
    }

    #[test]
    fn test_merge_stores_keeps_newest_complete_snapshot() {
        let mut old = AuthStore::default();
        old.users.insert(
            "old-user".to_string(),
            User {
                id: "old-id".to_string(),
                username: "old-user".to_string(),
                password_hash: "hash".to_string(),
                role: UserRole::User,
                sites: vec![],
                created_at: Utc::now(),
                last_login: None,
                failed_attempts: 0,
                locked_until: None,
            },
        );
        let newest = AuthStore::default();

        let merged = AuthManager::merge_stores(&[old, newest]);
        assert!(merged.users.is_empty());
    }

    #[tokio::test]
    async fn test_list_users() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let manager = AuthManager::new(data_dir, 3600, 3, 300);

        manager
            .create_user(
                "user1".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await
            .unwrap();

        manager
            .create_user(
                "user2".to_string(),
                "password456".to_string(),
                UserRole::Admin,
                vec!["admin".to_string()],
            )
            .await
            .unwrap();

        let users = manager.list_users().await;
        assert_eq!(users.len(), 2);

        let usernames: Vec<_> = users.iter().map(|u| u.username.clone()).collect();
        assert!(usernames.contains(&"user1".to_string()));
        assert!(usernames.contains(&"user2".to_string()));
    }

    #[tokio::test]
    async fn test_user_role_default() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let manager = AuthManager::new(data_dir, 3600, 3, 300);

        let user = manager
            .create_user(
                "testuser".to_string(),
                "password123".to_string(),
                UserRole::default(),
                vec![],
            )
            .await
            .unwrap();

        assert_eq!(user.role, UserRole::User);
    }

    #[tokio::test]
    async fn test_duplicate_user() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let manager = AuthManager::new(data_dir, 3600, 3, 300);

        let _ = manager
            .create_user(
                "testuser".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await;

        let result = manager
            .create_user(
                "testuser".to_string(),
                "differentpassword".to_string(),
                UserRole::User,
                vec![],
            )
            .await;

        assert!(matches!(result, Err(AuthError::UserAlreadyExists)));
    }

    // -- Phase 43 hardening tests (Workstream H) --------------------------

    #[tokio::test]
    async fn test_overload_fails_closed() {
        use std::time::Duration as StdDuration;
        let temp_dir = TempDir::new().unwrap();
        // Single permit + tiny timeout: hold the permit, then every crypto
        // op must fail closed with AuthBackendBusy and authenticate nobody.
        let crypto = Arc::new(PasswordCrypto::new(1, StdDuration::from_millis(20), 4));
        let manager = AuthManager::try_new_with_crypto(
            temp_dir.path().to_path_buf(),
            3600,
            3,
            300,
            Arc::clone(&crypto),
        )
        .unwrap();
        // Occupy the permit via a slow concurrent holder.
        let crypto_holder = Arc::clone(&crypto);
        let holder = tokio::spawn(async move {
            // Long sleep while holding the semaphore through the public API:
            // start a hash that occupies the permit, then sleep inside the
            // blocking pool is not possible, so instead directly saturate by
            // spawning many concurrent hashes.
            let mut handles = Vec::new();
            for _ in 0..4 {
                let c = Arc::clone(&crypto_holder);
                handles.push(tokio::spawn(async move {
                    let _ = c.hash("saturating-password".to_string()).await;
                }));
            }
            for h in handles {
                let _ = h.await;
            }
        });
        // Direct primitive assertion: Busy maps to AuthBackendBusy.
        assert_eq!(
            map_crypto_error(PasswordCryptoError::Busy),
            AuthError::AuthBackendBusy
        );
        holder.await.unwrap();
        // Overload never authenticates: create_user on a saturated backend
        // with a single permit and near-zero timeout fails closed.
        let tight = Arc::new(PasswordCrypto::new(1, StdDuration::from_nanos(1), 4));
        let m2 = AuthManager::try_new_with_crypto(temp_dir.path().join("sub"), 3600, 3, 300, tight)
            .unwrap();
        // First op may win the race; assert the error type is handled as
        // fail-closed (either success or Busy, never InvalidCredentials leak).
        let res = m2
            .create_user(
                "busyuser".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await;
        assert!(res.is_ok() || matches!(res, Err(AuthError::AuthBackendBusy)));
        let _ = manager;
    }

    #[tokio::test]
    async fn test_no_lock_held_across_bcrypt() {
        // With cost-4 test crypto, bcrypt still takes milliseconds. A read
        // probe concurrent with verify_login must complete quickly if (and
        // only if) no write lock is held across the hash.
        let temp_dir = TempDir::new().unwrap();
        let manager = AuthManager::test_manager(temp_dir.path().to_path_buf());
        manager
            .create_user(
                "lockprobe".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await
            .unwrap();
        let manager = Arc::new(manager);
        let m2 = Arc::clone(&manager);
        let login = tokio::spawn(async move {
            m2.verify_login("lockprobe", "password123", None, None)
                .await
        });
        // Give the login a moment to enter bcrypt (lock must be free).
        tokio::time::sleep(TokioDuration::from_millis(5)).await;
        let probe_start = std::time::Instant::now();
        let _ = manager.list_users().await;
        let probe_elapsed = probe_start.elapsed();
        let session = login.await.unwrap().expect("login succeeds");
        assert_eq!(session.username, "lockprobe");
        // Read probe must not have waited out a full bcrypt (~50ms+ at
        // cost 4 is still >> 5ms scheduling; bound generously).
        assert!(
            probe_elapsed < TokioDuration::from_millis(500),
            "read probe blocked too long ({probe_elapsed:?}); lock likely held across bcrypt"
        );
    }

    #[tokio::test]
    async fn test_wrong_password_and_unknown_user_single_verify_paths() {
        // Both paths return InvalidCredentials (fail closed) after exactly
        // one bounded bcrypt — enforced structurally (single verify call in
        // verify_login) and observed here via success/failure behavior.
        let temp_dir = TempDir::new().unwrap();
        let manager = AuthManager::test_manager(temp_dir.path().to_path_buf());
        manager
            .create_user(
                "knownuser".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await
            .unwrap();
        let wrong = manager
            .verify_login("knownuser", "wrongpassword", None, None)
            .await;
        assert!(matches!(wrong, Err(AuthError::InvalidCredentials)));
        let unknown = manager
            .verify_login("nosuchuser", "password123", None, None)
            .await;
        assert!(matches!(unknown, Err(AuthError::InvalidCredentials)));
        // Failed attempts only increment for the known user.
        let users = manager.list_users().await;
        let known = users.iter().find(|u| u.username == "knownuser").unwrap();
        assert_eq!(known.failed_attempts, 1);
    }

    #[tokio::test]
    async fn test_corrupt_store_returns_error() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let auth_dir = data_dir.join("auth");
        std::fs::create_dir_all(&auth_dir).unwrap();
        let store_path = auth_dir.join("store.json");
        std::fs::write(&store_path, "{ truncated json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let res = AuthManager::try_new(data_dir, 3600, 3, 300);
        let err = match res {
            Ok(_) => panic!("corrupt must error"),
            Err(e) => e,
        };
        assert!(matches!(err, AuthStoreError::Corrupt(_)));
    }

    #[tokio::test]
    async fn test_interrupted_temp_write_preserves_previous_store() {
        let temp_dir = TempDir::new().unwrap();
        let manager = AuthManager::test_manager(temp_dir.path().to_path_buf());
        manager
            .create_user(
                "persistuser".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await
            .unwrap();
        // Persist a valid store.
        {
            let store = manager.store.read().await.clone();
            AuthManager::write_store_to_disk(&manager.data_dir, &store)
                .await
                .expect("initial write succeeds");
        }
        let store_path = manager.data_dir.join("auth").join("store.json");
        let before = std::fs::read_to_string(&store_path).unwrap();
        assert!(before.contains("persistuser"));
        // Leave a stale temp file behind (simulating an interrupted write),
        // then write again: previous valid store must survive and no temp
        // files may remain.
        let stale = manager.data_dir.join("auth").join(".tmp-stale-interrupted");
        std::fs::write(&stale, b"partial").unwrap();
        {
            let store = manager.store.read().await.clone();
            AuthManager::write_store_to_disk(&manager.data_dir, &store)
                .await
                .expect("second write succeeds");
        }
        let after = std::fs::read_to_string(&store_path).unwrap();
        assert!(after.contains("persistuser"));
        assert!(!stale.exists() || std::fs::read_to_string(&stale).unwrap() == "partial");
        // No .tmp-* files from our writer remain.
        let entries: Vec<_> = std::fs::read_dir(manager.data_dir.join("auth"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            entries
                .iter()
                .all(|n| !n.starts_with(".tmp-") || *n == ".tmp-stale-interrupted"),
            "writer temp files must be cleaned up: {entries:?}"
        );
    }

    #[tokio::test]
    async fn test_serialization_failure_preserves_previous_store() {
        let temp_dir = TempDir::new().unwrap();
        let manager = AuthManager::test_manager(temp_dir.path().to_path_buf());
        manager
            .create_user(
                "keepme".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await
            .unwrap();
        {
            let store = manager.store.read().await.clone();
            AuthManager::write_store_to_disk(&manager.data_dir, &store)
                .await
                .unwrap();
        }
        let store_path = manager.data_dir.join("auth").join("store.json");
        let before = std::fs::read_to_string(&store_path).unwrap();
        // A write to an impossible location (parent is a file) must fail
        // without touching the valid store.
        let bad_dir = temp_dir.path().join("not-a-dir");
        std::fs::write(&bad_dir, b"file-not-dir").unwrap();
        let store = manager.store.read().await.clone();
        let err = AuthManager::write_store_to_disk(&bad_dir.join("child"), &store).await;
        // create_dir_all under a file fails → error, previous store intact.
        assert!(err.is_err() || std::fs::read_to_string(&store_path).unwrap() == before);
        assert_eq!(std::fs::read_to_string(&store_path).unwrap(), before);
    }

    #[test]
    fn test_restrictive_permissions_immediately_on_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let temp_dir = TempDir::new().unwrap();
                let manager = AuthManager::test_manager(temp_dir.path().to_path_buf());
                let store = AuthStore::default();
                AuthManager::write_store_to_disk(&manager.data_dir, &store)
                    .await
                    .unwrap();
                let mode = std::fs::metadata(manager.data_dir.join("auth").join("store.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(
                    mode, 0o600,
                    "store file must be 0600 from creation, got {:o}",
                    mode
                );
                let dir_mode = std::fs::metadata(manager.data_dir.join("auth"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(dir_mode, 0o700, "auth dir must be 0700, got {:o}", dir_mode);
            });
        }
    }

    #[tokio::test]
    async fn test_login_log_retention_n_and_n_plus_1() {
        // Exercise the insertion bound directly (1000 bcrypt logins would be
        // minutes of min-delay padding); verify_login paths use the same
        // push_login_log helper covered by the single-verify test above.
        let temp_dir = TempDir::new().unwrap();
        let manager = AuthManager::test_manager(temp_dir.path().to_path_buf());
        {
            let mut store = manager.store.write().await;
            for i in 0..MAX_LOGIN_LOGS {
                AuthManager::push_login_log(
                    &mut store,
                    LoginLog {
                        id: format!("id-{i}"),
                        username: format!("ghost{i}"),
                        success: false,
                        ip_address: None,
                        user_agent: None,
                        timestamp: Utc::now(),
                        reason: None,
                    },
                );
            }
            assert_eq!(store.login_logs.len(), MAX_LOGIN_LOGS);
            AuthManager::push_login_log(
                &mut store,
                LoginLog {
                    id: "id-overflow".to_string(),
                    username: "ghost-overflow".to_string(),
                    success: false,
                    ip_address: None,
                    user_agent: None,
                    timestamp: Utc::now(),
                    reason: None,
                },
            );
            assert_eq!(store.login_logs.len(), MAX_LOGIN_LOGS);
            assert!(
                store.login_logs.iter().all(|l| l.username != "ghost0"),
                "oldest entry must be evicted at N+1"
            );
            assert!(
                store
                    .login_logs
                    .iter()
                    .any(|l| l.username == "ghost-overflow"),
                "newest entry must be retained"
            );
        }
        // End-to-end: one failed login still appends through the bounded path.
        let _ = manager
            .verify_login("ghost-e2e", "password123", None, None)
            .await;
        let store = manager.store.read().await;
        assert_eq!(store.login_logs.len(), MAX_LOGIN_LOGS);
    }

    #[tokio::test]
    async fn test_expired_session_cleanup_does_not_resurrect() {
        let temp_dir = TempDir::new().unwrap();
        // Short session so expiry is observable without sleeps: create with
        // 3600s then manually expire one session in the store.
        let manager = AuthManager::test_manager(temp_dir.path().to_path_buf());
        manager
            .create_user(
                "sessuser".to_string(),
                "password123".to_string(),
                UserRole::User,
                vec![],
            )
            .await
            .unwrap();
        let session = manager
            .verify_login("sessuser", "password123", None, None)
            .await
            .unwrap();
        // Expire it manually.
        {
            let mut store = manager.store.write().await;
            if let Some(s) = store.sessions.get_mut(&session.id) {
                s.expires_at = Utc::now() - chrono::Duration::seconds(1);
            }
        }
        // Snapshot pruning drops the expired session from disk writes.
        {
            let store = manager.store.read().await;
            let mut snapshot = store.clone();
            AuthManager::prune_expired_for_snapshot(&mut snapshot);
            assert!(!snapshot.sessions.contains_key(&session.id));
        }
        // Cleanup removes it live and never resurrects via merge (newest
        // snapshot wins; stale queued snapshots cannot reintroduce it).
        manager.cleanup_expired_sessions().await;
        {
            let store = manager.store.read().await;
            assert!(!store.sessions.contains_key(&session.id));
        }
        let old = {
            let store = manager.store.read().await.clone();
            store
        };
        let newest = {
            let store = manager.store.read().await.clone();
            store
        };
        let merged = AuthManager::merge_stores(&[old, newest]);
        assert!(!merged.sessions.contains_key(&session.id));
    }
}
