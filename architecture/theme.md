# Theme Architecture

## 1. Purpose and Responsibility

The Theme module (`crates/synvoid-theme/src/`, re-exported by the `src/theme/` compatibility facade) provides a **CSS-driven theming system** for WAF challenge/error/captcha/login pages with dark/light mode support, directory listing, and branded SVG icons.

**Core Responsibilities:**
- CSS generation from theme configuration
- Dark/light/auto mode support
- Challenge/error/captcha/login page templates
- Directory listing with sorting, pagination, filtering
- SVG icon generation (spinner, logo, folder, file icons)

---

## 2. Key Data Structures

```rust
pub struct ThemeRenderer {
    config: ThemeConfig,
}

pub struct ChallengePageTemplate {
    renderer: ThemeRenderer,
    title: String,
    subtitle: String,
    content: String,
    scripts: String,
    honeypot_html: String,
    show_spinner: bool,
    show_logo: bool,
}

pub struct ErrorPageTemplate {
    renderer: ThemeRenderer,
    status_code: u16,
    message: String,
    timestamp: String,   // stealth-jittered, see §5
}

pub struct LoginPageTemplate { /* action_url, error_message, label fields */ }
pub struct CaptchaPageTemplate { /* challenge_id, image_url, action_url */ }

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

pub struct DirectoryEntry {
    pub name: String,
    pub href: String,
    pub is_dir: bool,
    pub modified: String,
    pub size: String,
    pub modified_timestamp: u64,
    pub size_bytes: u64,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `ThemeRenderer::new(config)` | Constructor |
| `generate_css()` | Generate complete CSS |
| `generate_directory_listing_css()` | Directory listing styles |
| `generate_spinner_svg()` | Loading spinner icon |
| `generate_logo_svg()` | Brand logo icon |
| `generate_theme_toggle_script()` | Dark/light mode JS |
| `generate_theme_toggle_button()` | Mode toggle HTML |
| `generate_folder_icon_svg()` | Folder icon |
| `generate_file_icon_svg()` | File icon |
| `generate_file_type_icon_svg(filename)` | Type-specific icon |
| `generate_parent_dir_icon_svg()` | Parent-directory ("..") icon for listings |
| `config()` | Borrow the active `ThemeConfig` |
| Template builders | `.title()`, `.subtitle()`, `.content()`, `.render()` |
| `DirectoryListingTemplate::new(config)` | Directory listing page |

---

## 4. Integration Points

- **CAPTCHA**: `CaptchaPageTemplate` for verification pages
- **Challenge**: Challenge page rendering
- **WAF**: Error page generation
- **Static Files**: Directory listing rendering
- **Config**: `ThemeConfig`, `ThemeColors` from synvoid-config

---

## 5. Key Implementation Details

- **CSS-only Theming**: No JavaScript required for basic theming
- **Dark/Light/Auto**: System preference detection via CSS media queries
- **Stealth Timestamps:** `generate_stealth_timestamp(jitter_seconds)`
  (`crates/synvoid-theme/src/template.rs:7`) stamps rendered pages with `Utc::now()` offset by a random
  amount in `±jitter_seconds` (via `rand`), formatted `%a, %d %b %Y %H:%M:%S GMT`. `ErrorPageTemplate`
  calls it with 5 seconds in both constructors (`template.rs:165` and `template.rs:174`), so page
  timestamps are deliberately imprecise rather than an exact request-time oracle. Passing `0` yields the
  exact current time.
- **Neon Effects:** Optional glassmorphism and neon visual effects
- **Accessibility**: ARIA labels and keyboard navigation in directory listings
- **Responsive**: Mobile-friendly templates
