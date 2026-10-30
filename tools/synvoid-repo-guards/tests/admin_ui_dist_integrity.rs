//! Guards on the committed `admin-ui/dist` build artifact.
//!
//! `admin-ui/dist` is a committed build output that the server serves directly
//! (`resolve_admin_ui_assets` in `src/admin/mod.rs`). Nothing in `cargo xtask
//! verify` rebuilds it, so it can drift silently from `admin-ui/src` — and it
//! did: the shipped WASM lagged the Rust sources by ~3 months while the
//! stylesheet was regenerated separately, leaving a half-updated artifact.
//!
//! These guards cannot detect source drift on their own (that needs a real
//! rebuild, which the `admin-ui-build` CI job performs). What they *can* catch
//! cheaply, inside routine verification, is the internally inconsistent state
//! a partial or interrupted rebuild leaves behind.

use std::collections::BTreeSet;
use std::path::Path;

use synvoid_repo_guards::workspace_root;

/// Extract Trunk's content-hashed asset names (`admin-ui-<hash>.js`,
/// `admin-ui-<hash>_bg.wasm`) that `dist/index.html` actually references.
///
/// Walks forward from each `admin-ui-` marker taking name characters until a
/// delimiter. The delimiter set deliberately covers both quote styles: Trunk's
/// generated bootstrap imports the bundle with single quotes while the
/// wasm-bindgen init options use double quotes.
fn referenced_assets(index_html: &str) -> BTreeSet<String> {
    let mut assets = BTreeSet::new();
    let mut rest = index_html;

    while let Some(pos) = rest.find("admin-ui-") {
        let tail = &rest[pos..];
        let name: String = tail
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .collect();

        if name.ends_with(".js") || name.ends_with(".wasm") {
            assets.insert(name);
        }

        // Continue after the marker regardless, so a malformed name cannot
        // wedge the scan on the same offset.
        rest = &tail["admin-ui-".len()..];
    }

    assets
}

fn list_dist_assets(dist: &Path) -> BTreeSet<String> {
    let mut assets = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir(dist) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("admin-ui-") && (name.ends_with(".js") || name.ends_with(".wasm")) {
                assets.insert(name);
            }
        }
    }
    assets
}

/// Every hashed asset `dist/index.html` references must exist on disk.
///
/// A stale `index.html` pointing at a bundle that was deleted or renamed is a
/// hard 404 for the whole dashboard — the SPA never boots and the operator
/// sees a blank page with no console error from SynVoid itself.
#[test]
fn admin_ui_dist_referenced_assets_exist() {
    let root = workspace_root();
    let dist = root.join("admin-ui").join("dist");
    let index = dist.join("index.html");

    assert!(
        index.exists(),
        "admin_ui_dist_referenced_assets_exist: admin-ui/dist/index.html is missing.\n\
         The admin SPA is served from this directory; run `cd admin-ui && npm run build` \
         and commit the result."
    );

    let html = std::fs::read_to_string(&index).expect("read admin-ui/dist/index.html");
    let referenced = referenced_assets(&html);

    assert!(
        !referenced.is_empty(),
        "admin_ui_dist_referenced_assets_exist: no hashed assets referenced by admin-ui/dist/index.html.\n\
         Expected the Trunk bootstrap to import an `admin-ui-<hash>.js` bundle."
    );

    let missing: Vec<String> = referenced
        .iter()
        .filter(|name| !dist.join(name).is_file())
        .cloned()
        .collect();

    assert!(
        missing.is_empty(),
        "admin_ui_dist_referenced_assets_exist: dist/index.html references {} asset(s) that do not exist:\n  {}\n\
         The dashboard will fail to boot. Rebuild with `cd admin-ui && npm run build`.",
        missing.len(),
        missing.join("\n  ")
    );
}

/// No hashed asset may sit in `dist` unreferenced by `index.html`.
///
/// This is the signature of an interrupted or partial rebuild: the new bundle
/// is written but `index.html` was never updated, or an old bundle was left
/// behind. Shipping that state means the served page and the committed source
/// disagree with no single rebuild having produced them.
#[test]
fn admin_ui_dist_has_no_orphan_bundles() {
    let root = workspace_root();
    let dist = root.join("admin-ui").join("dist");
    let index = dist.join("index.html");

    if !index.exists() {
        // Covered by admin_ui_dist_referenced_assets_exist.
        return;
    }

    let html = std::fs::read_to_string(&index).expect("read admin-ui/dist/index.html");
    let referenced = referenced_assets(&html);
    let present = list_dist_assets(&dist);

    let orphans: Vec<String> = present
        .iter()
        .filter(|name| !referenced.contains(*name))
        .cloned()
        .collect();

    assert!(
        orphans.is_empty(),
        "admin_ui_dist_has_no_orphan_bundles: {} asset(s) in admin-ui/dist are not referenced by index.html:\n  {}\n\
         A partial rebuild left the artifact inconsistent. Rebuild with `cd admin-ui && npm run build`.",
        orphans.len(),
        orphans.join("\n  ")
    );
}

/// The stylesheet must be present and linked.
///
/// Trunk emits the `rel="css"` stylesheet content-hashed
/// (`styles-<hash>.css`), so both the hashed and the unhashed (`styles.css`,
/// from a standalone `npm run build:css` copy) layouts are accepted. Either
/// way the two properties must hold: the file is on disk and `index.html`
/// links it. A missing or unlinked stylesheet ships the panel unstyled.
#[test]
fn admin_ui_dist_stylesheet_is_present_and_linked() {
    let root = workspace_root();
    let dist = root.join("admin-ui").join("dist");
    let index = dist.join("index.html");

    if !index.exists() {
        return;
    }

    let html = std::fs::read_to_string(&index).expect("read admin-ui/dist/index.html");
    let mut linked = Vec::new();
    if html.contains("styles.css") {
        linked.push("styles.css".to_string());
    }
    if let Ok(entries) = std::fs::read_dir(&dist) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "styles.css"
                && name.starts_with("styles-")
                && name.ends_with(".css")
                && html.contains(&name)
            {
                linked.push(name);
            }
        }
    }

    assert!(
        !linked.is_empty(),
        "admin_ui_dist_stylesheet_is_present_and_linked: dist/index.html links no \
         stylesheet (neither styles.css nor a styles-<hash>.css present on disk), \
         so the committed stylesheet would never load."
    );
}

/// No inline scripts in `dist/index.html`.
///
/// The admin server sends `script-src 'self'` with no `'unsafe-inline'`
/// (`security_headers_middleware`), so an inline `<script>` — including
/// Trunk's default inline WASM bootstrap — is refused and the panel sticks
/// on its loading screen with no login form. The bootstrap must stay an
/// external file (`bootstrap.js`). A Trunk rebuild reintroduces the inline
/// bootstrap; extract it again instead of loosening the CSP.
#[test]
fn admin_ui_dist_has_no_inline_scripts() {
    let root = workspace_root();
    let dist = root.join("admin-ui").join("dist");
    let index = dist.join("index.html");

    if !index.exists() {
        // Covered by admin_ui_dist_referenced_assets_exist.
        return;
    }

    let html = std::fs::read_to_string(&index).expect("read admin-ui/dist/index.html");

    // Scan absolute offsets; skip `<!-- -->` comments so prose naming the
    // rejected pattern (like this comment) is not itself a violation.
    // `str::get` keeps the scan total on non-ASCII input.
    let mut inline = 0;
    let mut i = 0;
    while i < html.len() {
        let Some(tail) = html.get(i..) else {
            i += 1;
            continue;
        };
        if let Some(after_open) = tail.strip_prefix("<!--") {
            if let Some(end) = after_open.find("-->") {
                i += "<!--".len() + end + "-->".len();
                continue;
            }
            break;
        }
        if tail.starts_with("<script") {
            let tag_end = tail.find('>').map(|o| i + o).unwrap_or(html.len());
            if !html[i..tag_end].contains("src=") {
                inline += 1;
            }
            i = (tag_end + 1).min(html.len());
            continue;
        }
        i += 1;
    }

    assert_eq!(
        inline, 0,
        "admin_ui_dist_has_no_inline_scripts: dist/index.html contains {inline} inline \
         <script> block(s). The admin CSP refuses inline scripts, so the panel never \
         boots. Move the bootstrap to an external file (see dist/bootstrap.js)."
    );
}
