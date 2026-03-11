use std::fs;
use std::path::Path;

pub fn render_directory_listing(
    dir_path: &Path,
    url_path: &str,
    format: &str,
) -> Result<String, super::StaticError> {
    let entries =
        fs::read_dir(dir_path).map_err(|e| super::StaticError::Internal(e.to_string()))?;

    let mut items: Vec<DirEntry> = Vec::new();

    for entry in entries {
        if let Ok(entry) = entry {
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
    }

    items.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    match format {
        "json" => render_json(url_path, &items),
        _ => render_html(url_path, &items),
    }
}

#[derive(Debug)]
struct DirEntry {
    name: String,
    is_dir: bool,
    modified: u64,
    size: u64,
}

fn render_html(url_path: &str, entries: &[DirEntry]) -> Result<String, super::StaticError> {
    let parent_link = if url_path != "/" {
        let parent = Path::new(url_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/".to_string());
        format!(
            r#"<tr><td colspan="3"><a href="{}">..</a></td></tr>"#,
            parent
        )
    } else {
        String::new()
    };

    let mut rows = String::new();
    for entry in entries {
        let href = if entry.is_dir {
            format!("{}/", url_path.trim_end_matches('/'))
        } else {
            entry.name.clone()
        };

        let modified_str = format_modified(entry.modified);
        let size_str = if entry.is_dir {
            "-".to_string()
        } else {
            format_size(entry.size)
        };

        rows.push_str(&format!(
            r#"<tr>
                <td><a href="{}">{}{}</a></td>
                <td>{}</td>
                <td class="size">{}</td>
            </tr>"#,
            href,
            entry.name,
            if entry.is_dir { "/" } else { "" },
            modified_str,
            size_str
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Index of {url_path}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #e0e0e0;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
        }}
        h1 {{
            color: #00d4ff;
            border-bottom: 1px solid #333;
            padding-bottom: 0.5rem;
            margin-bottom: 1rem;
            font-weight: 400;
            font-size: 1.5rem;
        }}
        .breadcrumbs {{
            color: #888;
            margin-bottom: 1rem;
            font-size: 0.875rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            text-align: left;
            padding: 0.75rem 1rem;
            background: rgba(0, 212, 255, 0.1);
            color: #00d4ff;
            font-weight: 500;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid #333;
            font-size: 0.9375rem;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        tr:hover td {{
            background: rgba(255, 255, 255, 0.03);
        }}
        a {{
            color: #00d4ff;
            text-decoration: none;
            transition: color 0.2s;
        }}
        a:hover {{
            color: #fff;
            text-decoration: underline;
        }}
        .size {{
            text-align: right;
            color: #888;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.875rem;
        }}
        .icon {{
            margin-right: 0.5rem;
            opacity: 0.7;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Index of {url_path}</h1>
        <div class="breadcrumbs">{url_path}</div>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Modified</th>
                    <th class="size">Size</th>
                </tr>
            </thead>
            <tbody>
                {parent_link}
                {rows}
            </tbody>
        </table>
    </div>
</body>
</html>"#
    );

    Ok(html)
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

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

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
