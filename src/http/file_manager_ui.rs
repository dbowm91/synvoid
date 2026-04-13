use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::get,
    Router,
};
use std::sync::Arc;
use tokio::sync::RwLock as TokioRwLock;

use crate::admin::verify_admin_token;
use crate::config::ConfigManager;
use crate::theme::{ThemeConfig, ThemeRenderer};

#[derive(Clone)]
struct FileManagerUiState {
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    config: Arc<TokioRwLock<ConfigManager>>,
    admin_token_hash: String,
}

unsafe impl Send for FileManagerUiState {}
unsafe impl Sync for FileManagerUiState {}

fn require_auth(state: &FileManagerUiState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !verify_admin_token(token, &state.admin_token_hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

async fn ui_handler(
    State(state): State<Arc<FileManagerUiState>>,
    headers: HeaderMap,
) -> Result<Html<String>, StatusCode> {
    require_auth(&state, &headers)?;

    let theme_config = ThemeConfig::default();
    let renderer = ThemeRenderer::new(theme_config);

    let css = renderer.generate_css();
    let theme_toggle_script = renderer.generate_theme_toggle_script();
    let theme_toggle_button = renderer.generate_theme_toggle_button();
    let logo_svg = renderer.generate_logo_svg();

    let html = render_file_manager_ui(&css, &theme_toggle_script, &theme_toggle_button, &logo_svg);

    Ok(Html(html))
}

fn render_file_manager_ui(
    css: &str,
    theme_toggle_script: &str,
    theme_toggle_button: &str,
    logo_svg: &str,
) -> String {
    let ui_js = include_str!("file_manager_ui.js");
    let ui_css = r#"
.waf-fm-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 1rem;
}

.waf-fm-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    background: var(--waf-surface);
    border: 1px solid var(--waf-border);
    border-radius: var(--waf-border-radius);
    margin-bottom: 1rem;
}

.waf-fm-title {
    font-size: 1.25rem;
    font-weight: 500;
    color: var(--waf-primary);
}

.waf-fm-actions {
    display: flex;
    gap: 0.5rem;
}

.waf-fm-btn {
    padding: 0.5rem 1rem;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.875rem;
    transition: background 0.2s;
}

.waf-fm-btn-primary {
    background: var(--waf-primary);
    color: white;
}

.waf-fm-btn-secondary {
    background: var(--waf-accent);
    color: var(--waf-text);
}

.waf-fm-btn:hover {
    opacity: 0.9;
}

.waf-fm-toolbar {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
}

#breadcrumb {
    padding: 0.75rem 1rem;
    background: var(--waf-surface);
    border: 1px solid var(--waf-border);
    border-radius: var(--waf-border-radius);
    margin-bottom: 1rem;
    font-size: 0.875rem;
}

#breadcrumb a {
    color: var(--waf-primary);
    text-decoration: none;
}

#breadcrumb a:hover {
    text-decoration: underline;
}

.file-container {
    background: var(--waf-surface);
    border: 1px solid var(--waf-border);
    border-radius: var(--waf-border-radius);
    min-height: 400px;
    padding: 1rem;
}

.file-list {
    list-style: none;
    padding: 0;
    margin: 0;
}

.file-list-item {
    display: flex;
    align-items: center;
    padding: 0.75rem;
    border-bottom: 1px solid var(--waf-border);
    cursor: pointer;
}

.file-list-item:last-child {
    border-bottom: none;
}

.file-list-item:hover {
    background: var(--waf-accent);
}

.file-icon {
    font-size: 1.5rem;
    margin-right: 1rem;
}

.file-name {
    flex: 1;
    color: var(--waf-text);
}

.file-meta {
    font-size: 0.75rem;
    color: var(--waf-text);
    opacity: 0.7;
}

.empty-state {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 300px;
    color: var(--waf-text);
    opacity: 0.6;
}

.modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    align-items: center;
    justify-content: center;
    z-index: 1000;
}

.modal-content {
    background: var(--waf-surface);
    padding: 2rem;
    border-radius: var(--waf-border-radius);
    max-width: 400px;
    width: 100%;
}

.modal-title {
    font-size: 1.25rem;
    margin-bottom: 1rem;
    color: var(--waf-primary);
}

.modal-input {
    width: 100%;
    padding: 0.75rem;
    margin-bottom: 1rem;
    border: 1px solid var(--waf-border);
    border-radius: 4px;
    background: var(--waf-background);
    color: var(--waf-text);
}

.modal-actions {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
}

#login-screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
}

.login-form {
    background: var(--waf-surface);
    padding: 2rem;
    border-radius: var(--waf-border-radius);
    width: 100%;
    max-width: 400px;
}

.login-title {
    font-size: 1.5rem;
    margin-bottom: 1.5rem;
    text-align: center;
    color: var(--waf-primary);
}
"#;

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Manager</title>
    <style>{}{}</style>
</head>
<body>
    {}{}
    <div class="waf-container waf-pixel-border">
        <div id="login-screen" style="display: none;">
            <form class="login-form" id="login-form">
                <h2 class="login-title">File Manager</h2>
                <input type="password" id="token-input" class="modal-input" placeholder="Admin Token" required>
                <div class="modal-actions">
                    <button type="submit" class="waf-fm-btn waf-fm-btn-primary">Login</button>
                </div>
            </form>
        </div>
        
        <div id="main-ui" style="display: none;">
            <div class="waf-fm-container">
                <div class="waf-fm-header">
                    <h1 class="waf-fm-title">File Manager</h1>
                    <div class="waf-fm-actions">
                        <button class="waf-fm-btn waf-fm-btn-secondary" id="logout-btn">Logout</button>
                    </div>
                </div>
                
                <div class="waf-fm-toolbar">
                    <button class="waf-fm-btn waf-fm-btn-primary" id="new-folder-btn">New Folder</button>
                    <button class="waf-fm-btn waf-fm-btn-primary" id="upload-btn">Upload</button>
                    <button class="waf-fm-btn waf-fm-btn-secondary" id="refresh-btn">Refresh</button>
                </div>
                
                <div id="breadcrumb"></div>
                
                <div id="file-container" class="file-container">
                    <div class="empty-state">Loading...</div>
                </div>
            </div>
        </div>
    </div>
    
    <div id="upload-modal" class="modal">
        <div class="modal-content">
            <h2 class="modal-title">Upload File</h2>
            <input type="file" id="file-input" class="modal-input">
            <div class="modal-actions">
                <button class="waf-fm-btn waf-fm-btn-secondary" id="upload-cancel-btn">Cancel</button>
                <button class="waf-fm-btn waf-fm-btn-primary" id="upload-confirm-btn">Upload</button>
            </div>
        </div>
    </div>
    
    <div id="newfolder-modal" class="modal">
        <div class="modal-content">
            <h2 class="modal-title">New Folder</h2>
            <input type="text" id="newfolder-name" class="modal-input" placeholder="Folder name">
            <div class="modal-actions">
                <button class="waf-fm-btn waf-fm-btn-secondary" id="newfolder-cancel-btn">Cancel</button>
                <button class="waf-fm-btn waf-fm-btn-primary" id="newfolder-create-btn">Create</button>
            </div>
        </div>
    </div>
    
    <script>{}</script>
    {}
</body>
</html>"#,
        css, ui_css, theme_toggle_button, logo_svg, ui_js, theme_toggle_script
    )
}

pub fn create_file_manager_ui_router(
    config: Arc<TokioRwLock<ConfigManager>>,
    admin_token_hash: String,
) -> Router {
    let state = FileManagerUiState {
        config,
        admin_token_hash,
    };

    Router::new()
        .route("/", get(ui_handler))
        .with_state(Arc::new(state))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_file_manager_ui_renders() {
        let html = super::render_file_manager_ui("body { }", "", "", "<svg></svg>");
        assert!(html.contains("File Manager"));
        assert!(html.contains("login-screen"));
        assert!(html.contains("main-ui"));
    }
}
