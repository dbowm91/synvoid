use crate::components::confirm_dialog::{ConfirmDialog, ConfirmType};
use crate::components::toast::{toast_error, toast_success};
use crate::components::tooltip::HelpIcon;
use crate::services::ApiService;
use crate::types::ErrorPageResponse;
use yew::prelude::*;

/// Custom error page editor.
///
/// Backs `GET /api/error-pages`, `GET /api/error-pages/{code}` and
/// `PUT /api/error-pages/{code}` — a family the panel never touched, so a
/// deployment could not author or even inspect its own error pages.
///
/// Two upstream constraints shape this UI:
///
/// * `list_error_pages` returns a **bare JSON array** (no envelope), and the
///   catalogue is fixed at 400/403/404/429/500/502/503 — any other code 404s.
/// * `html_preview` is hardcoded to `null` in both `list()` and `from_code()`,
///   so there is **no read-back path** for the HTML that `PUT` writes. The
///   editor therefore cannot show what is currently deployed; it can only
///   overwrite it. The copy below says so rather than implying a preview.
#[function_component]
pub fn ErrorPages() -> Html {
    let pages = use_state(Vec::<ErrorPageResponse>::new);
    let loading = use_state(|| true);
    let error = use_state(|| None as Option<String>);

    // Editing state
    let selected = use_state(|| None as Option<u16>);
    let content = use_state(String::new);
    let title = use_state(String::new);
    let saving = use_state(|| false);
    let confirm_write = use_state(|| None as Option<u16>);

    {
        let pages = pages.clone();
        let loading = loading.clone();
        let error = error.clone();

        use_effect_with((), move |_| {
            let pages = pages.clone();
            let loading = loading.clone();
            let error = error.clone();

            wasm_bindgen_futures::spawn_local(async move {
                loading.set(true);
                match ApiService::new().list_error_pages().await {
                    Ok(list) => pages.set(list),
                    Err(e) => error.set(Some(e.to_string())),
                }
                loading.set(false);
            });

            || ()
        });
    }

    let on_select = {
        let selected = selected.clone();
        let content = content.clone();
        let title = title.clone();

        Callback::from(move |page: ErrorPageResponse| {
            let selected = selected.clone();
            let content = content.clone();
            let title = title.clone();

            // Fetch the individual record so the panel is driven by the
            // documented per-code endpoint rather than the list projection.
            wasm_bindgen_futures::spawn_local(async move {
                match ApiService::new().get_error_page(page.code).await {
                    Ok(detail) => {
                        content.set(String::new());
                        title.set(detail.name.clone());
                        selected.set(Some(page.code));
                    }
                    Err(e) => toast_error(&format!("Failed to load error page: {}", e)),
                }
            });
        })
    };

    let on_content_input = {
        let content = content.clone();
        Callback::from(move |e: InputEvent| {
            let target: web_sys::HtmlTextAreaElement = e.target_unchecked_into();
            content.set(target.value());
        })
    };

    let on_title_input = {
        let title = title.clone();
        Callback::from(move |e: InputEvent| {
            let target: web_sys::HtmlInputElement = e.target_unchecked_into();
            title.set(target.value());
        })
    };

    let on_request_save = {
        let selected = selected.clone();
        let confirm_write = confirm_write.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(code) = *selected {
                confirm_write.set(Some(code));
            }
        })
    };

    let on_confirm_save = {
        let selected = selected.clone();
        let content = content.clone();
        let title = title.clone();
        let saving = saving.clone();
        let confirm_write = confirm_write.clone();

        Callback::from(move |_: ()| {
            let code = match *confirm_write {
                Some(code) => code,
                None => return,
            };
            let selected = selected.clone();
            let content = content.clone();
            let title = title.clone();
            let saving = saving.clone();
            confirm_write.set(None);
            saving.set(true);

            let body = (*content).clone();
            // `title` is recorded on the audit event only; it is not written
            // into the page. `message` is never read by the backend at all.
            let title_value = (*title).clone();

            wasm_bindgen_futures::spawn_local(async move {
                match ApiService::new()
                    .update_error_page(code, &body, Some(&title_value))
                    .await
                {
                    Ok(result) => {
                        if result.applied() {
                            toast_success(&format!("Error page {} written", code));
                            if let Some(audit_id) = result.audit_id.clone() {
                                tracing::info!("error page {} audited as {}", code, audit_id);
                            }
                        } else {
                            // 200 but not applied — do not report success.
                            toast_error(&format!(
                                "Error page {} not written: {}",
                                code, result.status
                            ));
                        }
                    }
                    Err(e) => toast_error(&format!("Failed to write error page: {}", e)),
                }
                saving.set(false);
                selected.set(Some(code));
            });
        })
    };

    let on_cancel_save = {
        let confirm_write = confirm_write.clone();
        Callback::from(move |_: ()| confirm_write.set(None))
    };

    let selected_code = *selected;

    html! {
        <div class="space-y-6">
            <header>
                <h1 class="text-2xl font-bold">{ "Error Pages" }</h1>
                <p class="text-sm text-secondary">
                    { "Custom HTML served for the status codes SynVoid can intercept." }
                </p>
            </header>

            if let Some(err) = (*error).clone() {
                <div class="p-4 rounded-lg bg-red-500/10 border border-red-500">
                    <p class="text-sm text-red-400">{ format!("Failed to load error pages: {}", err) }</p>
                </div>
            }

            if *loading {
                <crate::components::skeleton::LoadingPage />
            } else {
                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">

                    // ── Catalogue ──────────────────────────────────────────
                    <section class="bg-secondary rounded-lg border border-default p-4">
                        <h2 class="text-lg font-semibold mb-3">{ "Status codes" }</h2>
                        <div class="space-y-2">
                            { for (*pages).iter().map(|page| {
                                let active = selected_code == Some(page.code);
                                let onclick = {
                                    let on_select = on_select.clone();
                                    let page = page.clone();
                                    Callback::from(move |_: MouseEvent| on_select.emit(page.clone()))
                                };
                                html! {
                                    <button
                                        onclick={onclick}
                                        aria-pressed={active.to_string()}
                                        class={classes!(
                                            "w-full",
                                                "text-left",
                                                "px-3",
                                                "py-2",
                                                "rounded-lg",
                                                "border",
                                                "transition",
                                            if active {
                                                "border-action-500 bg-action-500/10"
                                            } else {
                                                "border-default bg-tertiary hover:border-action-500"
                                            }
                                        )}
                                    >
                                        <span class="font-mono text-sm font-semibold">{ page.code }</span>
                                        <span class="text-sm ml-2">{ &page.name }</span>
                                        <p class="text-xs text-secondary mt-0.5">{ &page.description }</p>
                                    </button>
                                }
                            }) }
                        </div>
                    </section>

                    // ── Editor ─────────────────────────────────────────────
                    <section class="lg:col-span-2 bg-secondary rounded-lg border border-default p-4">
                        <div class="flex items-center gap-2 mb-3">
                            <h2 class="text-lg font-semibold">
                                {
                                    match selected_code {
                                        Some(code) => format!("Editing {}", code),
                                        None => "Editor".to_string(),
                                    }
                                }
                            </h2>
                            <HelpIcon
                                content={"The backend embeds `content` verbatim inside <body> and exposes no read-back endpoint, so saving overwrites the deployed page without previewing what is live."}
                            />
                        </div>

                        if selected_code.is_none() {
                            <p class="text-sm text-secondary">
                                { "Select a status code on the left to edit its page." }
                            </p>
                        } else {
                            <div class="space-y-4">
                                <div>
                                    <label for="error-page-title" class="block text-sm text-secondary mb-1">
                                        { "Title (audit metadata only)" }
                                    </label>
                                    <input
                                        id="error-page-title"
                                        type="text"
                                        class="w-full px-3 py-2 rounded-lg bg-tertiary border border-default text-sm focus:outline-none focus:ring-2 focus:ring-action-500"
                                        value={(*title).clone()}
                                        oninput={on_title_input}
                                    />
                                    <p class="text-xs text-tertiary mt-1">
                                        { "Recorded on the audit event. It is not written into the rendered page." }
                                    </p>
                                </div>

                                <div>
                                    <label for="error-page-content" class="block text-sm text-secondary mb-1">
                                        { "HTML content" }
                                    </label>
                                    <textarea
                                        id="error-page-content"
                                        rows="12"
                                        spellcheck="false"
                                        class="w-full px-3 py-2 rounded-lg bg-tertiary border border-default font-mono text-xs focus:outline-none focus:ring-2 focus:ring-action-500"
                                        value={(*content).clone()}
                                        oninput={on_content_input}
                                        placeholder="<div class=\"error\"><h1>Service unavailable</h1><p>Please try again shortly.</p></div>"
                                    />
                                    <p class="text-xs text-tertiary mt-1">
                                        { "Injected verbatim. An empty document still writes a page built from catalogue defaults." }
                                    </p>
                                </div>

                                <div class="flex justify-end">
                                    <button
                                        onclick={on_request_save}
                                        disabled={*saving}
                                        class="px-4 py-2 rounded-lg bg-action-600 hover:bg-action-700 text-white disabled:opacity-50 transition"
                                    >
                                        { if *saving { "Writing…" } else { "Write error page" } }
                                    </button>
                                </div>
                            </div>
                        }
                    </section>
                </div>
            }

            <ConfirmDialog
                show={confirm_write.is_some()}
                title={match *confirm_write {
                    Some(code) => format!("Overwrite error page {}?", code),
                    None => String::new(),
                }}
                message={String::from(
                    "This replaces the deployed page for this status code. The backend provides no read-back, so the previous content cannot be restored from here. The change is recorded in the audit log.",
                )}
                confirm_label={Some(String::from("Write page"))}
                cancel_label={Some(String::from("Cancel"))}
                confirm_type={Some(ConfirmType::Warning)}
                on_confirm={on_confirm_save}
                on_cancel={on_cancel_save}
            />
        </div>
    }
}
