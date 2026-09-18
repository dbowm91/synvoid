//! Phase 39 minification parity corpus.
//!
//! Baseline captured against released `minify-html 0.18.1` (Oxc 0.95) on
//! 2026-09-18. These tests freeze SynVoid's user-visible HTML/inline-JS/
//! inline-CSS minification semantics so the Oxc 0.95 -> 0.111 compatibility
//! fork can be validated without silent behavior change.
//!
//! Two assertion classes:
//! 1. exact/golden output for stable representative inputs;
//! 2. semantic invariants where the embedded JS/CSS minifier may legitimately
//!    choose different but equivalent formatting.

use synvoid_static_files::minifier::MinifierGenerator;

fn minify(input: &str) -> String {
    MinifierGenerator::new()
        .minify_html(input)
        .expect("html minification must succeed")
}

// ---------------------------------------------------------------------------
// Upstream public API shape used by SynVoid (must be preserved by any fork).
// ---------------------------------------------------------------------------

#[test]
fn upstream_minify_api_shape_is_preserved() {
    use minify_html::{minify as upstream_minify, Cfg};

    let mut cfg = Cfg::new();
    cfg.minify_js = true;
    cfg.minify_css = true;
    let out = upstream_minify(b"<p>  Hi  </p>", &cfg);
    assert_eq!(out, b"<p>Hi".to_vec());
}

// ---------------------------------------------------------------------------
// Golden outputs (released 0.18.1 baseline).
// ---------------------------------------------------------------------------

#[test]
fn whitespace_and_comment_reduction_golden() {
    assert_eq!(minify("<p>  Hello,   world!  </p>"), "<p>Hello, world!");
    assert_eq!(minify("<!-- hi --><p>hi</p>"), "<p>hi");
    assert_eq!(minify("<div>   </div>"), "<div></div>");
    assert_eq!(minify("<p>a</p>"), "<p>a");
}

#[test]
fn whitespace_sensitive_elements_preserved_golden() {
    assert_eq!(
        minify("<pre>  keep   spaces\n\n  newline  </pre>"),
        "<pre>  keep   spaces\n\n  newline  </pre>"
    );
    assert_eq!(
        minify("<textarea>  keep   me  </textarea>"),
        "<textarea>  keep   me  </textarea>"
    );
}

#[test]
fn attribute_quoting_golden() {
    assert_eq!(
        minify(r#"<div class="foo" id='bar' data-x=1 title="a &amp; b">t</div>"#),
        r#"<div title="a & b" class=foo data-x=1 id=bar>t</div>"#
    );
    assert_eq!(minify(r#"<img src="a.png" />"#), "<img src=a.png>");
    // `&` in a URL value forces quoting to stay parseable.
    assert_eq!(
        minify(r#"<a href="?a=1&amp;b=2">x</a>"#),
        r#"<a href="?a=1&b=2">x</a>"#
    );
}

#[test]
fn classic_inline_js_golden() {
    assert_eq!(
        minify("<script>function foo(  x  ) { return x + 1; }</script>"),
        "<script>function foo(x){return x+1}</script>"
    );
    assert_eq!(
        minify("<script>var x = 1;</script>"),
        "<script>var x=1;</script>"
    );
}

#[test]
fn module_inline_js_golden() {
    assert_eq!(
        minify(
            r#"<script type="module">import { x } from './m.js'; export const y = x ?? 1;</script>"#
        ),
        r#"<script type=module>import{x}from"./m.js";export const y=x??1;</script>"#
    );
}

#[test]
fn inline_css_golden() {
    assert_eq!(
        minify("<style>body { color : red ; margin : 0px 0px; }</style>"),
        "<style>body{color:red;margin:0}</style>"
    );
    assert_eq!(
        minify(r#"<div style="color : red ; margin : 0;">t</div>"#),
        "<div style=color:red;margin:0>t</div>"
    );
    // Already-minimal CSS is stable.
    assert_eq!(
        minify("<style>a{color:red}</style>"),
        "<style>a{color:red}</style>"
    );
}

#[test]
fn data_script_bodies_are_not_js_minified_golden() {
    assert_eq!(
        minify(
            r#"<script type="application/ld+json">{"@context": "https://schema.org", "name": "Test"}</script>"#
        ),
        r#"<script type=application/ld+json>{"@context": "https://schema.org", "name": "Test"}</script>"#
    );
    assert_eq!(
        minify(r#"<script type="application/json">{"a":  1}</script>"#),
        r#"<script type=application/json>{"a":  1}</script>"#
    );
    // Opaque template bodies are preserved byte-for-byte (only attrs minified).
    assert_eq!(
        minify(r#"<script type="text/template"><div>  not html  </div></script>"#),
        r#"<script type=text/template><div>  not html  </div></script>"#
    );
}

#[test]
fn malformed_empty_fragment_utf8_golden() {
    assert_eq!(
        minify("<div><p>unclosed<div>oops"),
        "<div><p>unclosed<div>oops"
    );
    assert_eq!(minify(""), "");
    assert_eq!(minify("just text"), "just text");
    assert_eq!(
        minify("<p>héllo wörld 日本語 🎉</p>"),
        "<p>héllo wörld 日本語 🎉"
    );
    assert_eq!(minify("<br>"), "<br>");
}

#[test]
fn entities_golden() {
    assert_eq!(
        minify("<p>&lt;div&gt; &amp; &quot;q&quot; &#39;</p>"),
        "<p>&lt;div> & \"q\" '"
    );
}

#[test]
fn tag_case_normalization_golden() {
    assert_eq!(
        minify("<SCRIPT>function f( x ) { return x; }</SCRIPT>"),
        "<script>function f(x){return x}</script>"
    );
}

// ---------------------------------------------------------------------------
// Semantic invariants (equivalent formatting allowed across Oxc lines).
// ---------------------------------------------------------------------------

#[test]
fn modern_js_features_preserve_semantics() {
    let out = minify(
        "<script>const a = obj?.foo ?? 'd'; const re = /ab+c/g; const t = `hi ${a}`; // c\n/* m */</script>",
    );
    // Optional chaining, nullish coalescing, regex literal, and template
    // literal interpolation must survive minification.
    assert!(out.contains("?."), "optional chaining lost: {out:?}");
    assert!(out.contains("??"), "nullish coalescing lost: {out:?}");
    assert!(out.contains("/ab+c/g"), "regex literal lost: {out:?}");
    assert!(out.contains("${a}"), "template interpolation lost: {out:?}");
    // Line comment is stripped; output must still be a script element.
    assert!(out.starts_with("<script>"), "script wrapper lost: {out:?}");
    assert!(
        !out.contains("// c"),
        "line comment should be minified: {out:?}"
    );
}

#[test]
fn js_compress_keeps_call_semantics() {
    let out = minify("<script>if(a){b()}</script>");
    assert!(
        out.contains("b()"),
        "compressed conditional must still call b(): {out:?}"
    );
}

#[test]
fn js_string_content_preserved() {
    let out = minify(r#"<script>var s = "  spaces  ";</script>"#);
    assert!(
        out.contains("  spaces  "),
        "string payload spacing must be preserved: {out:?}"
    );
}

#[test]
fn output_never_grows_beyond_input_for_corpus() {
    // Minification must not inflate: every corpus input minifies to <= input.
    let corpus = [
        "<p>  Hello,   world!  </p>",
        "<!-- hi --><p>hi</p>",
        "<pre>  keep   spaces\n\n  newline  </pre>",
        "<textarea>  keep   me  </textarea>",
        r#"<div class="foo" id='bar' data-x=1 title="a &amp; b">t</div>"#,
        "<script>function foo(  x  ) { return x + 1; }</script>",
        r#"<script type="module">import { x } from './m.js'; export const y = x ?? 1;</script>"#,
        "<style>body { color : red ; margin : 0px 0px; }</style>",
        r#"<div style="color : red ; margin : 0;">t</div>"#,
        r#"<script type="application/ld+json">{"@context": "https://schema.org", "name": "Test"}</script>"#,
        "<div><p>unclosed<div>oops",
        "",
        "just text",
        "<p>héllo wörld 日本語 🎉</p>",
        "<script>var x = 1;</script>",
        "<script>x</script>",
        "<style>a{color:red}</style>",
        "<p>&lt;div&gt; &amp; &quot;q&quot; &#39;</p>",
    ];
    for input in corpus {
        let out = minify(input);
        assert!(
            out.len() <= input.len(),
            "minified output grew for {input:?}: {} -> {} ({out:?})",
            input.len(),
            out.len()
        );
    }
}

#[test]
fn tiny_or_single_char_bodies_do_not_panic_or_grow() {
    assert!(minify("<script>x</script>").len() <= "<script>x</script>".len());
    assert!(minify("<script></script>").len() <= "<script></script>".len());
    assert!(minify("<style></style>").len() <= "<style></style>".len());
}
