use super::config::ThemeConfig;
use super::renderer::ThemeRenderer;

pub struct DirectoryListingTemplate {
    renderer: ThemeRenderer,
    url_path: String,
    entries: Vec<DirectoryEntry>,
}

pub struct DirectoryEntry {
    pub name: String,
    pub href: String,
    pub is_dir: bool,
    pub modified: String,
    pub size: String,
}

impl DirectoryListingTemplate {
    pub fn new(config: ThemeConfig) -> Self {
        Self {
            renderer: ThemeRenderer::new(config),
            url_path: String::new(),
            entries: Vec::new(),
        }
    }

    pub fn from_renderer(renderer: ThemeRenderer) -> Self {
        Self {
            renderer,
            url_path: String::new(),
            entries: Vec::new(),
        }
    }

    pub fn url_path(mut self, path: &str) -> Self {
        self.url_path = path.to_string();
        self
    }

    pub fn entries(mut self, entries: Vec<DirectoryEntry>) -> Self {
        self.entries = entries;
        self
    }

    pub fn render(self) -> String {
        let css = self.renderer.generate_css();
        let theme_toggle_script = self.renderer.generate_theme_toggle_script();
        let theme_toggle_button = self.renderer.generate_theme_toggle_button();

        let logo_html = if self.renderer.config().branding.show_logo {
            format!(
                r#"<div class="waf-logo">{}</div>"#,
                self.renderer.generate_logo_svg()
            )
        } else {
            String::new()
        };

        let parent_link = if self.url_path != "/" {
            let parent = std::path::Path::new(&self.url_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "/".to_string());
            let parent_href = if parent.is_empty() || parent == "/" {
                "/".to_string()
            } else {
                parent
            };
            format!(
                r#"<tr><td colspan="3"><a href="{href}">..</a></td></tr>"#,
                href = parent_href
            )
        } else {
            String::new()
        };

        let mut rows = String::new();
        for entry in &self.entries {
            let icon = if entry.is_dir { "📁" } else { "📄" };
            rows.push_str(&format!(
                r#"<tr>
                    <td><a href="{href}">{icon} {name}</a></td>
                    <td>{modified}</td>
                    <td class="size">{size}</td>
                </tr>"#,
                href = entry.href,
                icon = icon,
                name = entry.name,
                modified = entry.modified,
                size = entry.size
            ));
        }

        let dir_css = r#"
/* Directory Listing Styles */
.waf-dir-container {
    max-width: 900px;
    margin: 0 auto;
    padding: 2rem;
}

.waf-dir-title {
    color: var(--waf-primary);
    border-bottom: 1px solid var(--waf-border);
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
    font-weight: 400;
    font-size: 1.5rem;
    margin-top: 0;
}

.waf-dir-breadcrumbs {
    color: var(--waf-text);
    opacity: 0.7;
    margin-bottom: 1rem;
    font-size: 0.875rem;
}

.waf-dir-table {
    width: 100%;
    border-collapse: collapse;
    background: var(--waf-surface);
    border-radius: var(--waf-border-radius);
    overflow: hidden;
    border: 1px solid var(--waf-border);
}

.waf-dir-table th {
    text-align: left;
    padding: 0.75rem 1rem;
    background: var(--waf-accent);
    color: var(--waf-primary);
    font-weight: 500;
    font-size: 0.875rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.waf-dir-table td {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--waf-border);
    font-size: 0.9375rem;
}

.waf-dir-table tr:last-child td {
    border-bottom: none;
}

.waf-dir-table tr:hover td {
    background: var(--waf-accent);
}

.waf-dir-table a {
    color: var(--waf-primary);
    text-decoration: none;
    transition: color 0.2s;
}

.waf-dir-table a:hover {
    text-decoration: underline;
}

.waf-dir-size {
    text-align: right;
    color: var(--waf-text);
    opacity: 0.7;
    font-family: var(--waf-font-family);
    font-size: 0.875rem;
}"#;

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Index of {url_path}</title>
    <style>{css}{dir_css}</style>
</head>
<body>
    {theme_toggle_button}
    <div class="waf-container waf-pixel-border">
        {logo_html}
        <h1 class="waf-dir-title">Index of {url_path}</h1>
        <div class="waf-dir-breadcrumbs">{url_path}</div>
        <table class="waf-dir-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Modified</th>
                    <th class="waf-dir-size">Size</th>
                </tr>
            </thead>
            <tbody>
                {parent_link}
                {rows}
            </tbody>
        </table>
    </div>
    {theme_script}
</body>
</html>"#,
            url_path = self.url_path,
            css = css,
            dir_css = dir_css,
            theme_toggle_button = theme_toggle_button,
            logo_html = logo_html,
            parent_link = parent_link,
            rows = rows,
            theme_script = theme_toggle_script,
        )
    }
}
