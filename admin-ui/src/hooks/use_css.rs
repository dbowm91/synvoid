use yew::prelude::*;

/// Apply dynamic geometry through the CSSOM instead of a `style` attribute.
///
/// The admin document is served with `style-src 'self'`, which blocks every
/// `style="..."` attribute (including Yew-rendered ones) and every inline
/// `<style>` element. Values that are only known at runtime (chart heights,
/// skeleton sizes, legend colors) therefore cannot be expressed as markup;
/// setting them here via `CSSStyleDeclaration` is not an inline style in
/// the CSP sense and is permitted.
///
/// The effect re-runs whenever `props` changes, so late data updates
/// (fetches completing after mount) still size the element.
#[hook]
pub fn use_css_props(node: NodeRef, props: Vec<(&'static str, String)>) {
    use_effect_with(props, move |props| {
        if let Some(el) = node.cast::<web_sys::HtmlElement>() {
            for (name, value) in props.iter() {
                let _ = el.style().set_property(name, value);
            }
        } else if let Some(el) = node.cast::<web_sys::SvgElement>() {
            for (name, value) in props.iter() {
                let _ = el.style().set_property(name, value);
            }
        }
        || ()
    });
}
