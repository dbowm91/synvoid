use chrono::Utc;
use rand::Rng;

use super::renderer::ThemeRenderer;
use synvoid_config::theme::ThemeConfig;

fn generate_stealth_timestamp(jitter_seconds: u32) -> String {
    let offset = if jitter_seconds > 0 {
        let mut rng = rand::rng();
        let secs = rng.random_range(-(jitter_seconds as i64)..=jitter_seconds as i64);
        Utc::now() + chrono::Duration::seconds(secs)
    } else {
        Utc::now()
    };
    offset.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
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

impl ChallengePageTemplate {
    pub fn new(config: ThemeConfig) -> Self {
        let renderer = ThemeRenderer::new(config);
        Self {
            renderer,
            title: "Verifying...".to_string(),
            subtitle: "Please wait while we verify your browser.".to_string(),
            content: String::new(),
            scripts: String::new(),
            honeypot_html: String::new(),
            show_spinner: true,
            show_logo: true,
        }
    }

    pub fn from_renderer(renderer: ThemeRenderer) -> Self {
        Self {
            renderer,
            title: "Verifying...".to_string(),
            subtitle: "Please wait while we verify your browser.".to_string(),
            content: String::new(),
            scripts: String::new(),
            honeypot_html: String::new(),
            show_spinner: true,
            show_logo: true,
        }
    }

    pub fn title(mut self, title: &str) -> Self {
        self.title = title.to_string();
        self
    }

    pub fn subtitle(mut self, subtitle: &str) -> Self {
        self.subtitle = subtitle.to_string();
        self
    }

    pub fn content(mut self, content: &str) -> Self {
        self.content = content.to_string();
        self
    }

    pub fn scripts(mut self, scripts: &str) -> Self {
        self.scripts = scripts.to_string();
        self
    }

    pub fn honeypot(mut self, honeypot_html: &str) -> Self {
        self.honeypot_html = honeypot_html.to_string();
        self
    }

    pub fn spinner(mut self, show: bool) -> Self {
        self.show_spinner = show;
        self
    }

    pub fn logo(mut self, show: bool) -> Self {
        self.show_logo = show;
        self
    }

    pub fn render(self) -> String {
        let css = self.renderer.generate_css();
        let theme_toggle_script = self.renderer.generate_theme_toggle_script();
        let theme_toggle_button = self.renderer.generate_theme_toggle_button();

        let logo_html = if self.show_logo && self.renderer.config().branding.show_logo {
            format!(
                r#"<div class="waf-logo">{}</div>"#,
                self.renderer.generate_logo_svg()
            )
        } else {
            String::new()
        };

        let spinner_html = if self.show_spinner {
            format!(
                r#"<div class="waf-spinner">{}</div>"#,
                self.renderer.generate_spinner_svg()
            )
        } else {
            String::new()
        };

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>{css}</style>
</head>
<body>
    {theme_toggle_button}
    <div class="waf-container waf-pixel-border">
        {logo_html}
        {spinner_html}
        <h1 class="waf-title">{title}</h1>
        <p class="waf-subtitle">{subtitle}</p>
        {content}
    </div>
    {honeypot}
    {theme_script}
    {scripts}
</body>
</html>"#,
            title = self.title,
            css = css,
            theme_toggle_button = theme_toggle_button,
            logo_html = logo_html,
            spinner_html = spinner_html,
            subtitle = self.subtitle,
            content = self.content,
            honeypot = self.honeypot_html,
            theme_script = theme_toggle_script,
            scripts = self.scripts,
        )
    }
}

pub struct ErrorPageTemplate {
    renderer: ThemeRenderer,
    status_code: u16,
    message: String,
    timestamp: String,
}

impl ErrorPageTemplate {
    pub fn new(config: ThemeConfig) -> Self {
        Self {
            renderer: ThemeRenderer::new(config),
            status_code: 500,
            message: "An error occurred".to_string(),
            timestamp: generate_stealth_timestamp(5),
        }
    }

    pub fn from_renderer(renderer: ThemeRenderer) -> Self {
        Self {
            renderer,
            status_code: 500,
            message: "An error occurred".to_string(),
            timestamp: generate_stealth_timestamp(5),
        }
    }

    pub fn status(mut self, code: u16) -> Self {
        self.status_code = code;
        self
    }

    pub fn message(mut self, message: &str) -> Self {
        self.message = message.to_string();
        self
    }

    pub fn timestamp(mut self, timestamp: &str) -> Self {
        self.timestamp = timestamp.to_string();
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

        let status_title = match self.status_code {
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Error",
        };

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{code} - {status_title}</title>
    <style>{css}</style>
</head>
<body>
    {theme_toggle_button}
    <div class="waf-container waf-pixel-border">
        {logo_html}
        <p class="waf-error-code">{code}</p>
        <h1 class="waf-title">{status_title}</h1>
        <p class="waf-message">{message}</p>
        <p class="waf-progress">Timestamp: {timestamp}</p>
    </div>
    {theme_script}
</body>
</html>"#,
            code = self.status_code,
            status_title = status_title,
            css = css,
            theme_toggle_button = theme_toggle_button,
            logo_html = logo_html,
            message = self.message,
            timestamp = self.timestamp,
            theme_script = theme_toggle_script,
        )
    }
}

pub struct LoginPageTemplate {
    renderer: ThemeRenderer,
    action_url: String,
    error_message: Option<String>,
    username_label: String,
    password_label: String,
    submit_label: String,
}

impl LoginPageTemplate {
    pub fn new(config: ThemeConfig) -> Self {
        Self {
            renderer: ThemeRenderer::new(config),
            action_url: "/_waf_login".to_string(),
            error_message: None,
            username_label: "Username".to_string(),
            password_label: "Password".to_string(),
            submit_label: "Sign In".to_string(),
        }
    }

    pub fn from_renderer(renderer: ThemeRenderer) -> Self {
        Self {
            renderer,
            action_url: "/_waf_login".to_string(),
            error_message: None,
            username_label: "Username".to_string(),
            password_label: "Password".to_string(),
            submit_label: "Sign In".to_string(),
        }
    }

    pub fn action(mut self, url: &str) -> Self {
        self.action_url = url.to_string();
        self
    }

    pub fn error(mut self, message: &str) -> Self {
        self.error_message = Some(message.to_string());
        self
    }

    pub fn username_label(mut self, label: &str) -> Self {
        self.username_label = label.to_string();
        self
    }

    pub fn password_label(mut self, label: &str) -> Self {
        self.password_label = label.to_string();
        self
    }

    pub fn submit_label(mut self, label: &str) -> Self {
        self.submit_label = label.to_string();
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

        let error_html = if let Some(ref error) = self.error_message {
            format!(r#"<p class="waf-error">{}</p>"#, error)
        } else {
            String::new()
        };

        let content = format!(
            r#"{error}
<form class="waf-form" method="POST" action="{action}">
    <input type="text" name="username" class="waf-input" placeholder="{username_label}" required autocomplete="username">
    <input type="password" name="password" class="waf-input" placeholder="{password_label}" required autocomplete="current-password">
    <button type="submit" class="waf-button">{submit_label}</button>
</form>"#,
            error = error_html,
            action = self.action_url,
            username_label = self.username_label,
            password_label = self.password_label,
            submit_label = self.submit_label,
        );

        let _template = ChallengePageTemplate::from_renderer(self.renderer)
            .title("Sign In")
            .subtitle("")
            .spinner(false)
            .content(&content);

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In</title>
    <style>{css}</style>
</head>
<body>
    {theme_toggle_button}
    <div class="waf-container waf-pixel-border">
        {logo_html}
        <h1 class="waf-title">Sign In</h1>
        {content}
    </div>
    {theme_script}
</body>
</html>"#,
            css = css,
            theme_toggle_button = theme_toggle_button,
            logo_html = logo_html,
            content = content,
            theme_script = theme_toggle_script,
        )
    }
}

pub struct CaptchaPageTemplate {
    renderer: ThemeRenderer,
    challenge_id: String,
    image_url: String,
    action_url: String,
}

impl CaptchaPageTemplate {
    pub fn new(config: ThemeConfig) -> Self {
        Self {
            renderer: ThemeRenderer::new(config),
            challenge_id: String::new(),
            image_url: "/_waf_captcha_img".to_string(),
            action_url: "/_waf_captcha_verify".to_string(),
        }
    }

    pub fn from_renderer(renderer: ThemeRenderer) -> Self {
        Self {
            renderer,
            challenge_id: String::new(),
            image_url: "/_waf_captcha_img".to_string(),
            action_url: "/_waf_captcha_verify".to_string(),
        }
    }

    pub fn challenge_id(mut self, id: &str) -> Self {
        self.challenge_id = id.to_string();
        self
    }

    pub fn image_url(mut self, url: &str) -> Self {
        self.image_url = url.to_string();
        self
    }

    pub fn action_url(mut self, url: &str) -> Self {
        self.action_url = url.to_string();
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

        let content = format!(
            r#"<img class="waf-captcha-img" src="{image_url}?id={challenge_id}" alt="CAPTCHA" width="200" height="80">
<form class="waf-form" method="POST" action="{action_url}">
    <input type="hidden" name="id" value="{challenge_id}">
    <input type="text" name="answer" class="waf-input" placeholder="Enter code" required autocomplete="off">
    <button type="submit" class="waf-button">Verify</button>
</form>"#,
            image_url = self.image_url,
            challenge_id = self.challenge_id,
            action_url = self.action_url,
        );

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Required</title>
    <style>{css}</style>
</head>
<body>
    {theme_toggle_button}
    <div class="waf-container waf-pixel-border">
        {logo_html}
        <h1 class="waf-title">Verify</h1>
        <p class="waf-subtitle">Enter the code shown above</p>
        {content}
    </div>
    {theme_script}
</body>
</html>"#,
            css = css,
            theme_toggle_button = theme_toggle_button,
            logo_html = logo_html,
            content = content,
            theme_script = theme_toggle_script,
        )
    }
}
