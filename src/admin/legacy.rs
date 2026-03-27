use crate::auth::{AuthManager, LoginLog, SessionInfo, UserInfo};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[derive(Clone)]
pub struct AdminManager {
    auth_manager: Arc<AuthManager>,
}

impl AdminManager {
    pub fn new(auth_manager: Arc<AuthManager>) -> Self {
        Self { auth_manager }
    }

    pub async fn list_users(&self) -> Vec<UserInfo> {
        self.auth_manager.list_users().await
    }

    pub async fn create_user(
        &self,
        username: String,
        password: String,
        role: String,
        sites: Vec<String>,
    ) -> Result<UserInfo, String> {
        let role = match role.to_lowercase().as_str() {
            "admin" => crate::auth::UserRole::Admin,
            _ => crate::auth::UserRole::User,
        };

        match self
            .auth_manager
            .create_user(username, password, role, sites)
            .await
        {
            Ok(user) => Ok(UserInfo {
                id: user.id,
                username: user.username,
                role: user.role,
                sites: user.sites,
                created_at: user.created_at,
                last_login: user.last_login,
                failed_attempts: user.failed_attempts,
                locked_until: user.locked_until,
            }),
            Err(e) => Err(e.to_string()),
        }
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<(), String> {
        self.auth_manager
            .delete_user(user_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_user_sites(&self, user_id: &str, sites: Vec<String>) -> Result<(), String> {
        self.auth_manager
            .update_user_sites(user_id, sites)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_login_logs(&self, limit: usize) -> Vec<LoginLog> {
        self.auth_manager.get_login_logs(limit).await
    }

    pub async fn get_active_sessions(&self) -> Vec<SessionInfo> {
        self.auth_manager.get_active_sessions().await
    }

    pub async fn destroy_session(&self, session_id: &str) {
        self.auth_manager.destroy_session(session_id).await;
    }

    pub fn max_failed_attempts(&self) -> u32 {
        self.auth_manager.max_failed_attempts()
    }

    pub fn lockout_duration_secs(&self) -> u64 {
        self.auth_manager.lockout_duration_secs()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminConfigLegacy {
    pub enabled: bool,
    pub port: u16,
    pub data_dir: String,
    pub session_duration_secs: u64,
    pub max_login_attempts: u32,
    pub lockout_duration_secs: u64,
}

impl Default for AdminConfigLegacy {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 8081,
            data_dir: "data".to_string(),
            session_duration_secs: 86400,
            max_login_attempts: 3,
            lockout_duration_secs: 3600,
        }
    }
}

pub fn generate_dashboard_html(
    users: &[UserInfo],
    sessions: &[SessionInfo],
    logs: &[LoginLog],
    max_attempts: u32,
    lockout_duration: u64,
) -> String {
    let users_html = users.iter().map(|u| {
        let role = match u.role {
            crate::auth::UserRole::Admin => "Admin",
            crate::auth::UserRole::User => "User",
        };
        let sites = escape_html(&u.sites.join(", "));
        let last_login = u.last_login.map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "Never".to_string());
        let locked = u.locked_until.map(|t| {
            if t > chrono::Utc::now() {
                format!("<span class=\"badge badge-danger\">Locked until {}</span>", escape_html(&t.format("%H:%M").to_string()))
            } else {
                String::new()
            }
        }).unwrap_or_default();

        format!(r#"
            <tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>
                    <form method="POST" action="/_waf_admin/users/{}/delete" style="display:inline;">
                        <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Delete user?')">Delete</button>
                    </form>
                </td>
            </tr>
        "#, escape_html(&u.username), escape_html(role), sites, escape_html(&last_login), u.failed_attempts, locked, escape_html(&u.id))
    }).collect::<Vec<_>>().join("\n");

    let sessions_html = sessions.iter().map(|s| {
        format!(r#"
            <tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>
                    <form method="POST" action="/_waf_admin/sessions/{}/revoke" style="display:inline;">
                        <button type="submit" class="btn btn-sm btn-warning">Revoke</button>
                    </form>
                </td>
            </tr>
        "#, escape_html(&s.username), escape_html(&s.expires_at.format("%Y-%m-%d %H:%M").to_string()), escape_html(s.id.split('-').next().unwrap_or(&s.id)), escape_html(&s.id))
    }).collect::<Vec<_>>().join("\n");

    let logs_html = logs
        .iter()
        .map(|l| {
            let status = if l.success {
                "<span class=\"badge badge-success\">Success</span>"
            } else {
                "<span class=\"badge badge-danger\">Failed</span>"
            };
            let reason = escape_html(l.reason.as_deref().unwrap_or("-"));

            format!(
                r#"
            <tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>
        "#,
                escape_html(&l.timestamp.format("%Y-%m-%d %H:%M").to_string()),
                escape_html(&l.username),
                status,
                escape_html(l.ip_address.as_deref().unwrap_or("-")),
                reason
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RustWAF Admin Dashboard</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #2c3e50; margin-bottom: 20px; }}
        h2 {{ color: #34495e; margin: 30px 0 15px; font-size: 1.3rem; }}
        .card {{ background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }}
        .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #555; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.85rem; }}
        .badge-success {{ background: #d4edda; color: #155724; }}
        .badge-danger {{ background: #f8d7da; color: #721c24; }}
        .btn {{ padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9rem; }}
        .btn-primary {{ background: #3498db; color: white; }}
        .btn-danger {{ background: #e74c3c; color: white; }}
        .btn-warning {{ background: #f39c12; color: white; }}
        .btn:hover {{ opacity: 0.9; }}
        .form-group {{ margin-bottom: 15px; }}
        .form-group label {{ display: block; margin-bottom: 5px; font-weight: 500; }}
        .form-group input, .form-group select {{ width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
        .form-row {{ display: flex; gap: 10px; }}
        .form-row > * {{ flex: 1; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-card h3 {{ font-size: 0.9rem; color: #777; margin-bottom: 5px; }}
        .stat-card .value {{ font-size: 1.8rem; font-weight: 600; color: #2c3e50; }}
        .alert {{ padding: 12px; border-radius: 4px; margin-bottom: 15px; }}
        .alert-success {{ background: #d4edda; color: #155724; }}
        .alert-error {{ background: #f8d7da; color: #721c24; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>RustWAF Admin Dashboard</h1>

        <div class="stats">
            <div class="stat-card">
                <h3>Total Users</h3>
                <div class="value">{}</div>
            </div>
            <div class="stat-card">
                <h3>Active Sessions</h3>
                <div class="value">{}</div>
            </div>
            <div class="stat-card">
                <h3>Failed Attempt Lockout</h3>
                <div class="value">{} attempts</div>
            </div>
            <div class="stat-card">
                <h3>Lockout Duration</h3>
                <div class="value">{} min</div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h2>Create User</h2>
            </div>
            <form method="POST" action="/_waf_admin/users">
                <div class="form-row">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" name="username" required minlength="3">
                    </div>
                    <div class="form-group">
                        <label>Password (min 8 chars)</label>
                        <input type="password" name="password" required minlength="8">
                    </div>
                    <div class="form-group">
                        <label>Role</label>
                        <select name="role">
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Site Access (comma separated, or "all")</label>
                        <input type="text" name="sites" placeholder="example.com, api.example.com">
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">Create User</button>
            </form>
        </div>

        <div class="card">
            <div class="card-header">
                <h2>Users</h2>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Site Access</th>
                        <th>Last Login</th>
                        <th>Failed Attempts</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <div class="card">
            <div class="card-header">
                <h2>Active Sessions</h2>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Expires</th>
                        <th>Session ID</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <div class="card">
            <div class="card-header">
                <h2>Login Logs (Recent 20)</h2>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Username</th>
                        <th>Status</th>
                        <th>IP Address</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"#,
        users.len(),
        sessions.len(),
        max_attempts,
        lockout_duration / 60,
        users_html,
        sessions_html,
        logs_html
    )
}

pub fn generate_login_page(error: Option<&str>) -> String {
    let error_html = error
        .map(|e| format!(r#"<div class="alert alert-error">{}</div>"#, escape_html(e)))
        .unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - RustWAF</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }}
        .login-box {{ background: white; padding: 2rem; border-radius: 1rem; box-shadow: 0 10px 40px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }}
        h1 {{ color: #333; margin-bottom: 1.5rem; text-align: center; }}
        .form-group {{ margin-bottom: 1rem; }}
        .form-group label {{ display: block; margin-bottom: 0.5rem; color: #555; font-weight: 500; }}
        .form-group input {{ width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 0.5rem; font-size: 1rem; }}
        .form-group input:focus {{ outline: none; border-color: #667eea; }}
        .btn {{ width: 100%; padding: 0.75rem; background: #667eea; color: white; border: none; border-radius: 0.5rem; font-size: 1rem; cursor: pointer; }}
        .btn:hover {{ background: #5568d3; }}
        .alert {{ padding: 0.75rem; border-radius: 0.5rem; margin-bottom: 1rem; }}
        .alert-error {{ background: #f8d7da; color: #721c24; }}
    </style>
</head>
<body>
    <div class="login-box">
        <h1>RustWAF Admin</h1>
        {}
        <form method="POST" action="/_waf_admin/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
    </div>
</body>
</html>"#,
        error_html
    )
}
