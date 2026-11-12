use crate::hooks::use_css::use_css_props;
use yew::prelude::*;

/// Inline sample error page. The previous implementation rendered the
/// preview through a sandboxed `srcdoc` iframe, but the admin document's
/// `style-src 'self'` CSP is inherited by `srcdoc` documents and drops
/// their `<style>` blocks — the preview rendered unstyled and never
/// reflected the saved theme. This renders the same card inline with
/// scoped classes instead; the dynamic theme colors arrive through the
/// CSSOM hook, which is not an inline style in the CSP sense.
#[derive(Properties, PartialEq)]
pub struct ThemePreviewProps {
    pub background: String,
    pub surface: String,
    pub text: String,
    pub border: String,
    pub primary: String,
    #[prop_or(403)]
    pub status: u16,
    #[prop_or_default]
    pub title: Option<String>,
    #[prop_or_default]
    pub message: Option<String>,
}

#[function_component]
pub fn ThemePreview(props: &ThemePreviewProps) -> Html {
    let node = use_node_ref();
    use_css_props(
        node.clone(),
        vec![
            ("--tp-bg", props.background.clone()),
            ("--tp-surface", props.surface.clone()),
            ("--tp-text", props.text.clone()),
            ("--tp-border", props.border.clone()),
            ("--tp-primary", props.primary.clone()),
        ],
    );

    html! {
        <div ref={node} class="tp-body">
            <div class="tp-card">
                <div class="tp-status">{ props.status }</div>
                <div class="tp-title">
                    { props.title.clone().unwrap_or_else(|| "Forbidden".to_string()) }
                </div>
                <div class="tp-text">
                    {
                        props.message.clone().unwrap_or_else(|| {
                            "Access to this resource has been blocked by the WAF.".to_string()
                        })
                    }
                </div>
                <div class="tp-footer">{ "SynVoid" }</div>
            </div>
        </div>
    }
}
