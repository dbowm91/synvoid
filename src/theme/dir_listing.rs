use std::collections::HashMap;

use super::config::ThemeConfig;
use super::renderer::ThemeRenderer;

fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub name: String,
    pub href: String,
    pub is_dir: bool,
    pub modified: String,
    pub size: String,
    pub modified_timestamp: u64,
    pub size_bytes: u64,
}

pub struct DirectoryListingTemplate {
    renderer: ThemeRenderer,
    url_path: String,
    entries: Vec<DirectoryEntry>,
    sort_by: String,
    sort_order: String,
    page: usize,
    limit: usize,
    total_entries: usize,
    filter_pattern: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PaginationInfo {
    pub page: usize,
    pub limit: usize,
    pub total: usize,
    pub total_pages: usize,
    pub has_prev: bool,
    pub has_next: bool,
    pub prev_page: usize,
    pub next_page: usize,
}

impl PaginationInfo {
    pub fn new(page: usize, limit: usize, total: usize) -> Self {
        let total_pages = total.div_ceil(limit);
        Self {
            page,
            limit,
            total,
            total_pages,
            has_prev: page > 1,
            has_next: page < total_pages,
            prev_page: page.saturating_sub(1),
            next_page: (page + 1).min(total_pages),
        }
    }

    pub fn offset(&self) -> usize {
        (self.page - 1) * self.limit
    }
}

impl DirectoryListingTemplate {
    pub fn new(config: ThemeConfig) -> Self {
        Self {
            renderer: ThemeRenderer::new(config),
            url_path: String::new(),
            entries: Vec::new(),
            sort_by: "name".to_string(),
            sort_order: "asc".to_string(),
            page: 1,
            limit: 100,
            total_entries: 0,
            filter_pattern: None,
        }
    }

    pub fn from_renderer(renderer: ThemeRenderer) -> Self {
        Self {
            renderer,
            url_path: String::new(),
            entries: Vec::new(),
            sort_by: "name".to_string(),
            sort_order: "asc".to_string(),
            page: 1,
            limit: 100,
            total_entries: 0,
            filter_pattern: None,
        }
    }

    pub fn url_path(mut self, path: &str) -> Self {
        self.url_path = path.to_string();
        self
    }

    pub fn entries(mut self, entries: Vec<DirectoryEntry>) -> Self {
        self.total_entries = entries.len();
        self.entries = entries;
        self
    }

    pub fn sort_by(mut self, sort_by: &str) -> Self {
        self.sort_by = sort_by.to_string();
        self
    }

    pub fn sort_order(mut self, order: &str) -> Self {
        self.sort_order = order.to_string();
        self
    }

    pub fn page(mut self, page: usize) -> Self {
        self.page = page;
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    pub fn filter(mut self, pattern: Option<&str>) -> Self {
        self.filter_pattern = pattern.map(|s| s.to_string());
        self
    }

    fn build_base_params(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if self.sort_by != "name" {
            params.insert("sort".to_string(), self.sort_by.clone());
        }
        if self.sort_order != "asc" {
            params.insert("order".to_string(), self.sort_order.clone());
        }
        if self.page > 1 {
            params.insert("page".to_string(), self.page.to_string());
        }
        if self.limit != 100 {
            params.insert("limit".to_string(), self.limit.to_string());
        }
        if let Some(ref filter) = self.filter_pattern {
            if !filter.is_empty() {
                params.insert("filter".to_string(), filter.clone());
            }
        }
        params
    }

    fn generate_sort_controls(&self) -> String {
        let base_params = self.build_base_params();
        let sort_options = ["name", "date", "size"];
        let order_options = [("asc", "Ascending"), ("desc", "Descending")];

        let mut html = String::from(
            r#"<nav class="waf-dir-sort" aria-label="Sort options"><span class="waf-sr-only">Sort by:</span>"#,
        );

        for sort_opt in &sort_options {
            let is_active = self.sort_by == *sort_opt;
            let mut params = base_params.clone();
            params.insert("sort".to_string(), sort_opt.to_string());
            let query = if params.is_empty() {
                String::new()
            } else {
                let pairs: Vec<String> = params
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, percent_encode(v)))
                    .collect();
                format!("?{}", pairs.join("&"))
            };
            html.push_str(&format!(
                r#"<a href="{}" class="{}" aria-label="Sort by {}" aria-current="{}">{}</a>"#,
                query,
                if is_active { "active" } else { "" },
                sort_opt,
                if is_active { "true" } else { "false" },
                sort_opt.chars().next().unwrap().to_uppercase().to_string() + &sort_opt[1..]
            ));
        }

        html.push_str(" | Order: ");

        for (order_val, order_label) in &order_options {
            let is_active = self.sort_order == *order_val;
            let mut params = base_params.clone();
            params.insert("order".to_string(), order_val.to_string());
            let query = if params.is_empty() {
                String::new()
            } else {
                let pairs: Vec<String> = params
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, percent_encode(v)))
                    .collect();
                format!("?{}", pairs.join("&"))
            };
            html.push_str(&format!(
                r#"<a href="{}" class="{}" aria-label="Sort {}">{}</a>"#,
                query,
                if is_active { "active" } else { "" },
                order_label,
                order_label
            ));
        }

        html.push_str("</nav>");
        html
    }

    fn generate_skip_link(&self) -> String {
        r##"<a href="#directory-listing" class="waf-skip-link">Skip to directory listing</a>"##
            .to_string()
    }

    fn generate_breadcrumbs(&self) -> String {
        if self.url_path == "/" {
            return String::new();
        }

        let mut html = String::from(r#"<div class="waf-dir-breadcrumbs">"#);

        let path_segments: Vec<&str> = self
            .url_path
            .trim_end_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        html.push_str(r#"<a href="/">Home</a>"#);

        let mut accumulated_path = String::new();
        for (i, segment) in path_segments.iter().enumerate() {
            if i == path_segments.len() - 1 {
                html.push_str(&format!(r#"<span>/</span>{}"#, segment));
            } else {
                accumulated_path.push('/');
                accumulated_path.push_str(segment);
                let clean_href = format!("{}{}", accumulated_path, "/");
                html.push_str(&format!(
                    r#"<span>/</span><a href="{}">{}</a>"#,
                    clean_href, segment
                ));
            }
        }

        html.push_str("</div>");
        html
    }

    fn generate_pagination(&self) -> String {
        if self.total_entries <= self.limit {
            return String::new();
        }

        let pagination = PaginationInfo::new(self.page, self.limit, self.total_entries);

        let mut html = String::from(
            r#"<nav class="waf-dir-pagination" aria-label="Directory listing pagination">"#,
        );

        let showing_start = pagination.offset() + 1;
        let showing_end = (pagination.offset() + self.limit).min(pagination.total);
        html.push_str(&format!(
            r#"<div class="waf-dir-pagination-info" aria-live="polite">Showing {}-{} of {} entries</div>"#,
            showing_start, showing_end, pagination.total
        ));

        html.push_str(r#"<div class="waf-dir-pagination-controls">"#);

        let base_params = self.build_base_params();

        let first_params = {
            let mut p = base_params.clone();
            p.insert("page".to_string(), "1".to_string());
            p
        };
        let first_query = if first_params.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = first_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, percent_encode(v)))
                .collect();
            format!("?{}", pairs.join("&"))
        };
        html.push_str(&format!(
            r#"<a href="{}" class="{}" aria-label="First page">First</a>"#,
            first_query,
            if pagination.has_prev { "" } else { "disabled" }
        ));

        let prev_params = {
            let mut p = base_params.clone();
            p.insert("page".to_string(), pagination.prev_page.to_string());
            p
        };
        let prev_query = if prev_params.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = prev_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, percent_encode(v)))
                .collect();
            format!("?{}", pairs.join("&"))
        };
        html.push_str(&format!(
            r#"<a href="{}" class="{}" aria-label="Previous page">Prev</a>"#,
            prev_query,
            if pagination.has_prev { "" } else { "disabled" }
        ));

        html.push_str(&format!(
            "<span aria-current=\"page\">Page {} of {}</span>",
            pagination.page, pagination.total_pages
        ));

        let next_params = {
            let mut p = base_params.clone();
            p.insert("page".to_string(), pagination.next_page.to_string());
            p
        };
        let next_query = if next_params.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = next_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, percent_encode(v)))
                .collect();
            format!("?{}", pairs.join("&"))
        };
        html.push_str(&format!(
            r#"<a href="{}" class="{}" aria-label="Next page">Next</a>"#,
            next_query,
            if pagination.has_next { "" } else { "disabled" }
        ));

        let last_params = {
            let mut p = base_params.clone();
            p.insert("page".to_string(), pagination.total_pages.to_string());
            p
        };
        let last_query = if last_params.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = last_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, percent_encode(v)))
                .collect();
            format!("?{}", pairs.join("&"))
        };
        html.push_str(&format!(
            r#"<a href="{}" class="{}" aria-label="Last page">Last</a>"#,
            last_query,
            if pagination.has_next { "" } else { "disabled" }
        ));

        html.push_str("</div></nav>");
        html
    }

    fn sort_entries(
        entries: Vec<DirectoryEntry>,
        sort_by: &str,
        sort_order: &str,
    ) -> Vec<DirectoryEntry> {
        let is_asc = sort_order == "asc";

        let mut sorted: Vec<DirectoryEntry> = entries;

        sorted.sort_by(|a, b| {
            let dirs_first = a.is_dir.cmp(&b.is_dir).reverse();
            if dirs_first != std::cmp::Ordering::Equal {
                return dirs_first;
            }

            let cmp = match sort_by {
                "date" => a.modified_timestamp.cmp(&b.modified_timestamp),
                "size" => a.size_bytes.cmp(&b.size_bytes),
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            };

            if is_asc {
                cmp
            } else {
                cmp.reverse()
            }
        });

        sorted
    }

    fn filter_entries(
        entries: Vec<DirectoryEntry>,
        filter_pattern: &Option<String>,
    ) -> Vec<DirectoryEntry> {
        let Some(ref pattern) = filter_pattern else {
            return entries;
        };

        if pattern.is_empty() {
            return entries;
        }

        let extensions: Vec<String> = pattern
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .map(|s| {
                if s.starts_with('.') {
                    s
                } else {
                    format!(".{}", s)
                }
            })
            .collect();

        entries
            .into_iter()
            .filter(|entry| {
                if entry.is_dir {
                    return true;
                }
                extensions
                    .iter()
                    .any(|ext| entry.name.to_lowercase().ends_with(ext))
            })
            .collect()
    }

    fn paginate_entries(
        entries: Vec<DirectoryEntry>,
        page: usize,
        limit: usize,
    ) -> Vec<DirectoryEntry> {
        if page <= 1 && entries.len() <= limit {
            return entries;
        }

        let offset = (page - 1) * limit;
        entries.into_iter().skip(offset).take(limit).collect()
    }

    pub fn render(self) -> String {
        let css = self.renderer.generate_css();
        let dir_css = self.renderer.generate_directory_listing_css();
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

        let breadcrumbs = self.generate_breadcrumbs();
        let sort_controls = self.generate_sort_controls();
        let pagination = self.generate_pagination();
        let skip_link = self.generate_skip_link();

        let filter_pattern = self.filter_pattern.clone();
        let filtered = Self::filter_entries(self.entries, &filter_pattern);
        let sorted = Self::sort_entries(filtered, &self.sort_by, &self.sort_order);
        let paginated = Self::paginate_entries(sorted, self.page, self.limit);

        let parent_link = if self.url_path != "/" {
            let parent = std::path::Path::new(&self.url_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "/".to_string());
            let parent_href = if parent.is_empty() || parent == "/" {
                "/".to_string()
            } else {
                format!("{}{}/", parent, "")
            };
            format!(
                r#"<tr><td colspan="3"><a href="{href}">..</a></td></tr>"#,
                href = parent_href.trim_end_matches('/')
            )
        } else {
            String::new()
        };

        let mut rows = String::new();
        for entry in &paginated {
            let icon = if entry.is_dir { "📁" } else { "📄" };
            rows.push_str(&format!(
                r#"<tr>
                    <td><a href="{href}">{icon} {name}</a></td>
                    <td>{modified}</td>
                    <td class="waf-dir-size">{size}</td>
                </tr>"#,
                href = entry.href,
                icon = icon,
                name = entry.name,
                modified = entry.modified,
                size = entry.size
            ));
        }

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
    {skip_link}
    {theme_toggle_button}
    <div class="waf-container waf-pixel-border" id="directory-listing" tabindex="-1">
        {logo_html}
        <h1 class="waf-dir-title">Index of {url_path}</h1>
        {breadcrumbs}
        {sort_controls}
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
        {pagination}
    </div>
    {theme_script}
</body>
</html>"#,
            url_path = self.url_path,
            css = css,
            dir_css = dir_css,
            theme_toggle_button = theme_toggle_button,
            logo_html = logo_html,
            breadcrumbs = breadcrumbs,
            sort_controls = sort_controls,
            parent_link = parent_link,
            rows = rows,
            pagination = pagination,
            theme_script = theme_toggle_script,
        )
    }
}
