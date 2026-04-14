use std::fs;
use std::path::Path;

use crate::theme::{DirectoryEntry, DirectoryListingTemplate, ThemeConfig};

pub fn load_directory_template(template_path: &str) -> Result<String, super::StaticError> {
    fs::read_to_string(template_path).map_err(|e| {
        super::StaticError::Internal(format!(
            "Failed to load directory template from {}: {}",
            template_path, e
        ))
    })
}

pub fn render_custom_template(
    template: &str,
    url_path: &str,
    entries: &[DirectoryEntry],
) -> Result<String, super::StaticError> {
    let mut html = template.to_string();

    html = html.replace("{{url_path}}", url_path);

    let parent_link = if url_path != "/" {
        let parent = Path::new(url_path)
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
            let icon = if entry.is_dir { "📁" } else { "📄" };
            format!(
                r#"<tr>
                    <td><a href="{}">{} {}</a></td>
                    <td>{}</td>
                    <td class="size">{}</td>
                </tr>"#,
                entry.href, icon, entry.name, entry.modified, entry.size
            )
        })
        .collect();
    html = html.replace("{{rows}}", &rows);

    html = html.replace("{{site_name}}", "RustWAF");
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
        });
    }

    Ok(result)
}

pub fn render_directory_listing(
    dir_path: &Path,
    url_path: &str,
    format: &str,
    theme_config: &ThemeConfig,
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
        _ => render_html(url_path, &items, theme_config),
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
) -> Result<String, super::StaticError> {
    let base_path = url_path.trim_end_matches('/');
    let _parent_link = if url_path != "/" {
        let parent = Path::new(url_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/".to_string());
        let parent_href = if parent.is_empty() || parent == "/" {
            "/".to_string()
        } else {
            parent
        };
        Some(DirectoryEntry {
            name: "..".to_string(),
            href: parent_href,
            is_dir: true,
            modified: "-".to_string(),
            size: "-".to_string(),
        })
    } else {
        None
    };

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
            }
        })
        .collect();

    let template = DirectoryListingTemplate::new(theme_config.clone())
        .url_path(url_path)
        .entries(template_entries);

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

    let now = crate::utils::safe_unix_timestamp();

    let diff = now.saturating_sub(timestamp);

    if diff < 60 {
        return "Just now".to_string();
    }
    if diff < 3600 {
        return format!("{} min ago", diff / 60);
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
