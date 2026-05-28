# Theme Architecture

## 1. Purpose and Responsibility

The Theme module (`src/theme/`) provides a **CSS-driven theming system** for WAF challenge/error/captcha/login pages with dark/light mode support, directory listing, and branded SVG icons.

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
    title: String,
    subtitle: String,
    content: String,
    scripts: String,
    css: String,
}

pub struct ErrorPageTemplate {
    status_code: u16,
    title: String,
    message: String,
    css: String,
}

pub struct LoginPageTemplate { /* ... */ }
pub struct CaptchaPageTemplate { /* ... */ }

pub struct DirectoryListingTemplate {
    entries: Vec<DirectoryEntry>,
    config: DirectoryConfig,
    page: PaginationInfo,
}

pub struct DirectoryEntry {
    pub name: String,
    pub href: String,
    pub is_dir: bool,
    pub modified: Option<DateTime<Utc>>,
    pub size: Option<u64>,
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
- **Neon Effects**: Optional glassmorphism and neon visual effects
- **Accessibility**: ARIA labels and keyboard navigation in directory listings
- **Responsive**: Mobile-friendly templates
