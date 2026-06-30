use std::fs;
use std::path::Path;

use synvoid_theme::{DirectoryEntry, DirectoryListingTemplate, ThemeConfig};

fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                } else {
                    result.push('%');
                    result.push_str(&hex);
                }
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub fn load_directory_template(template_path: &str) -> Result<String, super::StaticError> {
    let path = Path::new(template_path);

    if path.is_absolute() {
        return Err(super::StaticError::Internal(format!(
            "Absolute template paths are not allowed: {}",
            template_path
        )));
    }

    let path_str = template_path.replace('\\', "/");
    if path_str.contains("..") {
        return Err(super::StaticError::Internal(format!(
            "Template path traversal attempt detected: {}",
            template_path
        )));
    }

    let canonical = fs::canonicalize(path).map_err(|e| {
        super::StaticError::Internal(format!(
            "Failed to resolve template path {}: {}",
            template_path, e
        ))
    })?;

    if !canonical.starts_with(std::path::PathBuf::from("/etc/synvoid/").as_path())
        && !canonical.starts_with(std::path::PathBuf::from("/var/lib/synvoid/").as_path())
        && !canonical.starts_with(std::path::PathBuf::from("/var/www/").as_path())
    {
        return Err(super::StaticError::Internal(format!(
            "Template path must be within allowed directories (/etc/synvoid, /var/lib/synvoid, /var/www): {}",
            template_path
        )));
    }

    fs::read_to_string(&canonical).map_err(|e| {
        super::StaticError::Internal(format!(
            "Failed to load directory template from {}: {}",
            template_path, e
        ))
    })
}

const FOLDER_ICON: &str = r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>"#;
const FILE_ICON: &str = r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/></svg>"#;

fn get_file_type_icon(filename: &str) -> &'static str {
    let ext = filename.split('.').next_back().map(|e| e.to_lowercase());
    match ext.as_deref() {
        Some("js") => {
            r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9v6M15 9v6M9 15h6"/></svg>"#
        }
        Some("ts") | Some("tsx") | Some("jsx") => {
            r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9v6M15 9v6M9 15h6"/></svg>"#
        }
        Some("py") => {
            r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>"#
        }
        Some("rs") => {
            r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>"#
        }
        Some("html") | Some("htm") => {
            r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16,18 22,12 16,6"/><polyline points="8,6 2,12 8,18"/></svg>"#
        }
        Some("css") | Some("scss") | Some("sass") | Some("less") => {
            r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>"#
        }
        Some("json") | Some("yaml") | Some("yml") | Some("toml") => {
            r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8M8 17h8"/></svg>"#
        }
        Some("md") | Some("txt") => {
            r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>"#
        }
        Some("png") | Some("jpg") | Some("jpeg") | Some("gif") | Some("svg") | Some("webp")
        | Some("ico") => {
            r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21,15 16,10 5,21"/></svg>"#
        }
        Some("pdf") => {
            r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/><path d="M9 15v-2h2a1 1 0 010 2H9zM9 11h2"/></svg>"#
        }
        Some("zip") | Some("tar") | Some("gz") | Some("bz2") | Some("xz") | Some("7z")
        | Some("rar") => {
            r#"<svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/><path d="M12 11v6M9 14h6"/></svg>"#
        }
        _ => FILE_ICON,
    }
}

pub fn render_custom_template(
    template: &str,
    url_path: &str,
    entries: &[DirectoryEntry],
) -> Result<String, super::StaticError> {
    let mut html = template.to_string();

    html = html.replace("{{url_path}}", url_path);

    let parent_link = if url_path != "/" {
        let parent = std::path::Path::new(url_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/".to_string());
        let parent_href = if parent.is_empty() || parent == "/" {
            "/".to_string()
        } else {
            parent
        };
        format!(
            r#"<tr><td colspan="3"><a href="{}">..</a></td></tr>"#,
            parent_href
        )
    } else {
        String::new()
    };
    html = html.replace("{{parent_link}}", &parent_link);

    let rows: String = entries
        .iter()
        .map(|entry| {
            let icon = if entry.is_dir {
                FOLDER_ICON
            } else {
                get_file_type_icon(&entry.name)
            };
            let escaped_name = escape_html(&entry.name);
            format!(
                r#"<tr>
                    <td><a href="{}">{} {}</a></td>
                    <td>{}</td>
                    <td class="size">{}</td>
                </tr>"#,
                entry.href, icon, escaped_name, entry.modified, entry.size
            )
        })
        .collect();
    html = html.replace("{{rows}}", &rows);

    html = html.replace("{{site_name}}", "SynVoid");
    html = html.replace("{{title}}", &format!("Index of {}", url_path));

    Ok(html)
}

pub fn collect_directory_entries(
    dir_path: &Path,
) -> Result<Vec<DirectoryEntry>, super::StaticError> {
    let entries =
        fs::read_dir(dir_path).map_err(|e| super::StaticError::Internal(e.to_string()))?;

    let mut items: Vec<DirEntry> = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        let is_dir = path.is_dir();

        let metadata = entry.metadata().ok();
        let modified = metadata
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let size = metadata
            .as_ref()
            .map(|m| if is_dir { 0 } else { m.len() })
            .unwrap_or(0);

        items.push(DirEntry {
            name,
            is_dir,
            modified,
            size,
        });
    }

    items.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    let binding = dir_path.to_string_lossy();
    let base_path = binding.trim_end_matches('/');
    let url_path = format!("/{}", base_path);

    let mut result: Vec<DirectoryEntry> = Vec::new();

    for entry in items {
        let href = if entry.is_dir {
            format!("{}/{}/", url_path, entry.name)
        } else {
            format!("{}/{}", url_path, entry.name)
        };

        result.push(DirectoryEntry {
            name: entry.name.clone(),
            href,
            is_dir: entry.is_dir,
            modified: format_modified(entry.modified),
            size: if entry.is_dir {
                "-".to_string()
            } else {
                format_size(entry.size)
            },
            modified_timestamp: entry.modified,
            size_bytes: entry.size,
        });
    }

    Ok(result)
}

#[derive(Debug)]
pub struct DirectoryListingParams {
    pub sort_by: String,
    pub sort_order: String,
    pub page: usize,
    pub limit: usize,
    pub filter: Option<String>,
}

impl Default for DirectoryListingParams {
    fn default() -> Self {
        Self {
            sort_by: "name".to_string(),
            sort_order: "asc".to_string(),
            page: 1,
            limit: 100,
            filter: None,
        }
    }
}

pub fn parse_directory_params(query_string: Option<&str>) -> DirectoryListingParams {
    let Some(qs) = query_string else {
        return DirectoryListingParams::default();
    };

    let mut params = DirectoryListingParams::default();

    for pair in qs.split('&') {
        let parts: Vec<&str> = pair.splitn(2, '=').collect();
        if parts.len() != 2 {
            continue;
        }
        let key = parts[0];
        let value = percent_decode(parts[1]);

        match key {
            "sort" if ["name", "date", "size"].contains(&value.as_str()) => {
                params.sort_by = value;
            }
            "order" if ["asc", "desc"].contains(&value.as_str()) => {
                params.sort_order = value;
            }
            "page" => {
                if let Ok(p) = value.parse::<usize>() {
                    params.page = p.max(1);
                }
            }
            "limit" => {
                if let Ok(l) = value.parse::<usize>() {
                    params.limit = l.clamp(10, 1000);
                }
            }
            "filter" if !value.is_empty() => {
                params.filter = Some(value);
            }
            _ => {}
        }
    }

    params
}

pub fn render_directory_listing(
    dir_path: &Path,
    url_path: &str,
    format: &str,
    theme_config: &ThemeConfig,
    params: &DirectoryListingParams,
) -> Result<String, super::StaticError> {
    let entries =
        fs::read_dir(dir_path).map_err(|e| super::StaticError::Internal(e.to_string()))?;

    let mut items: Vec<DirEntry> = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        let is_dir = path.is_dir();

        let metadata = entry.metadata().ok();
        let modified = metadata
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let size = metadata
            .as_ref()
            .map(|m| if is_dir { 0 } else { m.len() })
            .unwrap_or(0);

        items.push(DirEntry {
            name,
            is_dir,
            modified,
            size,
        });
    }

    items.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    match format {
        "json" => render_json(url_path, &items),
        _ => render_html(url_path, &items, theme_config, params),
    }
}

#[derive(Debug)]
struct DirEntry {
    name: String,
    is_dir: bool,
    modified: u64,
    size: u64,
}

fn render_html(
    url_path: &str,
    entries: &[DirEntry],
    theme_config: &ThemeConfig,
    params: &DirectoryListingParams,
) -> Result<String, super::StaticError> {
    let base_path = url_path.trim_end_matches('/');

    let template_entries: Vec<DirectoryEntry> = entries
        .iter()
        .map(|entry| {
            let href = if entry.is_dir {
                format!("{}/{}/", base_path, entry.name)
            } else {
                format!("{}/{}", base_path, entry.name)
            };

            DirectoryEntry {
                name: entry.name.clone(),
                href,
                is_dir: entry.is_dir,
                modified: format_modified(entry.modified),
                size: if entry.is_dir {
                    "-".to_string()
                } else {
                    format_size(entry.size)
                },
                modified_timestamp: entry.modified,
                size_bytes: entry.size,
            }
        })
        .collect();

    let template = DirectoryListingTemplate::new(theme_config.clone())
        .url_path(url_path)
        .entries(template_entries)
        .sort_by(&params.sort_by)
        .sort_order(&params.sort_order)
        .page(params.page)
        .limit(params.limit)
        .filter(params.filter.as_deref());

    Ok(template.render())
}

fn render_json(url_path: &str, entries: &[DirEntry]) -> Result<String, super::StaticError> {
    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "name": e.name,
                "is_directory": e.is_dir,
                "modified": e.modified,
                "size": e.size,
            })
        })
        .collect();

    let json = serde_json::json!({
        "path": url_path,
        "entries": items,
    });

    Ok(json.to_string())
}

fn format_modified(timestamp: u64) -> String {
    if timestamp == 0 {
        return "-".to_string();
    }

    let now = synvoid_utils::safe_unix_timestamp();

    let diff = now.saturating_sub(timestamp);

    if diff < 60 {
        return "Just now".to_string();
    }
    if diff < 3600 {
        return format!("{} minutes ago", diff / 60);
    }
    if diff < 86400 {
        return format!("{} hours ago", diff / 3600);
    }

    let days = diff / 86400;
    if days < 30 {
        return format!("{} days ago", days);
    }
    if days < 365 {
        return format!("{} months ago", days / 30);
    }
    format!("{} years ago", days / 365)
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        let val = bytes as f64 / GB as f64;
        return format!("{:.1}G", val);
    }
    if bytes >= MB {
        let val = bytes as f64 / MB as f64;
        return format!("{:.1}M", val);
    }
    if bytes >= KB {
        let val = bytes as f64 / KB as f64;
        return format!("{:.1}K", val);
    }
    format!("{}B", bytes)
}
