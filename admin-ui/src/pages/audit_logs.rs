use crate::components::tooltip::HelpIcon;
use crate::services::ApiService;
use crate::types::AuditLogsResponse;
use yew::prelude::*;

/// Which filter field is active.
///
/// The backend treats `username` and `resource` as mutually exclusive with
/// `username` winning (`crates/synvoid-admin/src/handlers/logs.rs`): sending
/// both silently drops `resource`. Modelling it as a single enum here means the
/// UI cannot construct that contradictory request in the first place.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuditFilter {
    None,
    Username,
    Resource,
}

#[derive(Clone, PartialEq)]
struct FilterKind {
    key: &'static str,
    filter: AuditFilter,
}

const FILTERS: [FilterKind; 3] = [
    FilterKind {
        key: "All activity",
        filter: AuditFilter::None,
    },
    FilterKind {
        key: "By user",
        filter: AuditFilter::Username,
    },
    FilterKind {
        key: "By resource",
        filter: AuditFilter::Resource,
    },
];

/// Maps the UI's filter selection onto the backend's mutually exclusive
/// parameters.
///
/// `username` is an exact match and `resource` is a substring, and the handler
/// gives `username` precedence while silently dropping `resource`. Returning a
/// pair guarantees at most one is ever populated, so the UI cannot construct
/// the contradictory request the backend cannot represent.
fn filter_params(filter: AuditFilter, value: &str) -> (Option<String>, Option<String>) {
    match filter {
        AuditFilter::None => (None, None),
        AuditFilter::Username => (Some(value.to_string()), None),
        AuditFilter::Resource => (None, Some(value.to_string())),
    }
}

/// Read-only admin audit trail.
///
/// Backs `GET /api/audit-logs`. Block/unblock, error-page writes and
/// configuration changes all emit audit events, but the panel had no way to
/// read them back — the trail was write-only from the operator's perspective.
///
/// Read-only by design: this page never mutates, so there is no confirm dialog.
#[function_component]
pub fn AuditLogs() -> Html {
    let data = use_state(|| None as Option<AuditLogsResponse>);
    let error = use_state(|| None as Option<String>);
    let loading = use_state(|| false);

    // Filters
    let filter = use_state(|| AuditFilter::None);
    let query = use_state(String::new);
    let offset = use_state(|| 0usize);

    const PAGE_SIZE: usize = 50;

    {
        let data = data.clone();
        let error = error.clone();
        let loading = loading.clone();
        let filter = filter.clone();
        let query = query.clone();
        let offset = offset.clone();

        use_effect_with((*filter, (*query).clone(), *offset), move |_| {
            let data = data.clone();
            let error = error.clone();
            let loading = loading.clone();
            let filter = *filter;
            let query_value = (*query).clone();
            let page_offset = *offset;

            wasm_bindgen_futures::spawn_local(async move {
                loading.set(true);
                error.set(None);
                let api = ApiService::new();

                let trimmed = query_value.trim();
                let (username, resource) = filter_params(filter, trimmed);

                // Upstream drops `offset` entirely when a filter is set, so
                // an offset page would silently return the same rows. Reset
                // to the first page whenever a filter changes.
                let effective_offset = if trimmed.is_empty() { page_offset } else { 0 };

                let username_ref = username.as_deref();
                let resource_ref = resource.as_deref();

                match api
                    .get_audit_logs(
                        Some(PAGE_SIZE),
                        Some(effective_offset),
                        username_ref,
                        resource_ref,
                    )
                    .await
                {
                    Ok(response) => data.set(Some(response)),
                    Err(e) => {
                        error.set(Some(e.to_string()));
                        data.set(None);
                    }
                }
                loading.set(false);
            });

            || ()
        });
    }

    let on_filter = {
        let filter = filter.clone();
        let offset = offset.clone();
        Callback::from(move |next: AuditFilter| {
            filter.set(next);
            offset.set(0);
        })
    };

    let on_query_input = {
        let query = query.clone();
        let offset = offset.clone();
        Callback::from(move |e: InputEvent| {
            let target: web_sys::HtmlInputElement = e.target_unchecked_into();
            query.set(target.value());
            offset.set(0);
        })
    };

    let total = (*data).as_ref().map(|d| d.logs.len()).unwrap_or(0);
    let can_prev = *offset > 0;
    let can_next = data
        .as_ref()
        .map(|d| d.logs.len() == PAGE_SIZE)
        .unwrap_or(false);

    html! {
        <div class="space-y-6">
            <header>
                <h1 class="text-2xl font-bold">{ "Audit Log" }</h1>
                <p class="text-sm text-secondary">
                    { "Every privileged control-plane action, newest first. Retained in memory up to 10,000 entries and mirrored to audit.log." }
                </p>
            </header>

            // ── Filters ─────────────────────────────────────────────────────
            <div class="bg-secondary rounded-lg border border-default p-4 space-y-3">
                <div class="flex flex-wrap gap-2">
                    { for FILTERS.iter().map(|f| {
                        let active = *filter == f.filter;
                        let on_click = {
                            let on_filter = on_filter.clone();
                            let f = f.filter;
                            Callback::from(move |_: MouseEvent| on_filter.emit(f))
                        };
                        html! {
                            <button
                                onclick={on_click}
                                aria-pressed={active.to_string()}
                                class={classes!(
                                    "px-3",
                                    "py-1.5",
                                    "rounded-lg",
                                    "text-sm",
                                    "transition",
                                    if active {
                                        "bg-action-600 text-white"
                                    } else {
                                        "bg-tertiary text-secondary hover:text-primary"
                                    }
                                )}
                            >
                                { f.key }
                            </button>
                        }
                    }) }
                </div>

                if *filter != AuditFilter::None {
                    <div class="flex items-center gap-2">
                        <input
                            type="text"
                            class="flex-1 px-3 py-2 rounded-lg bg-tertiary border border-default text-sm focus:outline-none focus:ring-2 focus:ring-action-500"
                            placeholder={match *filter {
                                AuditFilter::Username => "Exact username match",
                                AuditFilter::Resource => "Substring of target resource (e.g. site:acme)",
                                AuditFilter::None => "",
                            }}
                            value={(*query).clone()}
                            oninput={on_query_input}
                        />
                    </div>
                    <p class="text-xs text-tertiary">
                        { match *filter {
                            AuditFilter::Username => "Matches the username exactly.",
                            AuditFilter::Resource => "Matches anywhere inside the target resource string.",
                            AuditFilter::None => "",
                        } }
                    </p>
                }
            </div>

            if let Some(err) = (*error).clone() {
                <div class="p-4 rounded-lg bg-red-500/10 border border-red-500">
                    <p class="text-sm text-red-400">{ format!("Failed to load audit log: {}", err) }</p>
                </div>
            }

            if *loading {
                <crate::components::skeleton::LoadingPage />
            } else {
                <section class="bg-secondary rounded-lg border border-default p-4">
                    <div class="flex items-center gap-2 mb-3">
                        <h2 class="text-lg font-semibold">
                            { format!("{} entr{}", total, if total == 1 { "y" } else { "ies" }) }
                        </h2>
                        <HelpIcon
                            content={"A successful HTTP status is not the same as a successful action — read the Outcome column, which mirrors the audit event's own success flag."}
                        />
                    </div>

                    if total == 0 {
                        <p class="text-sm text-secondary">
                            { if (*query).trim().is_empty() {
                                "No audit entries have been recorded yet."
                            } else {
                                "No audit entries match this filter."
                            } }
                        </p>
                    } else {
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead>
                                    <tr class="text-left text-secondary border-b border-default">
                                        <th class="py-2 pr-4 font-medium">{ "Time" }</th>
                                        <th class="py-2 pr-4 font-medium">{ "Actor" }</th>
                                        <th class="py-2 pr-4 font-medium">{ "Action" }</th>
                                        <th class="py-2 pr-4 font-medium">{ "Target" }</th>
                                        <th class="py-2 pr-4 font-medium">{ "Client IP" }</th>
                                        <th class="py-2 font-medium">{ "Outcome" }</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    { for (*data).as_ref().map(|d| d.logs.iter()).into_iter().flatten().map(|entry| html! {
                                        <tr class="border-b border-default/50 align-top">
                                            <td class="py-2 pr-4 font-mono text-xs whitespace-nowrap text-secondary">
                                                { &entry.timestamp }
                                            </td>
                                            <td class="py-2 pr-4">
                                                { entry.username.clone().or_else(|| entry.user_id.clone()).unwrap_or_else(|| "—".to_string()) }
                                            </td>
                                            <td class="py-2 pr-4 font-mono text-xs break-all">{ &entry.action }</td>
                                            <td class="py-2 pr-4 font-mono text-xs break-all">{ &entry.target_resource }</td>
                                            <td class="py-2 pr-4 font-mono text-xs text-secondary">{ &entry.client_ip }</td>
                                            <td class="py-2">
                                                <span class={classes!(
                                                    "px-2",
                                                    "py-0.5",
                                                    "rounded",
                                                    "text-xs",
                                                    "font-medium",
                                                    if entry.success {
                                                        "bg-green-500/15 text-green-400"
                                                    } else {
                                                        "bg-red-500/15 text-red-400"
                                                    }
                                                )}>
                                                    { if entry.success { "Success" } else { "Failed" } }
                                                </span>
                                                if let Some(details) = entry.details.clone().filter(|d| !d.is_empty()) {
                                                    <p class="text-xs text-tertiary mt-1 break-all">{ details }</p>
                                                }
                                            </td>
                                        </tr>
                                    }) }
                                </tbody>
                            </table>
                        </div>

                        <div class="flex items-center justify-between gap-2 mt-4">
                            <span class="text-xs text-tertiary">
                                { format!("Showing {}–{}", *offset + 1, *offset + total) }
                            </span>
                            <div class="flex gap-2">
                                <button
                                    disabled={!can_prev}
                                    onclick={{
                                        let offset = offset.clone();
                                        Callback::from(move |_: MouseEvent| {
                                            offset.set((*offset).saturating_sub(PAGE_SIZE));
                                        })
                                    }}
                                    class="px-3 py-1.5 rounded-lg text-sm bg-tertiary hover:bg-default transition disabled:opacity-40 disabled:cursor-not-allowed"
                                >
                                    { "Previous" }
                                </button>
                                <button
                                    disabled={!can_next}
                                    onclick={{
                                        let offset = offset.clone();
                                        Callback::from(move |_: MouseEvent| {
                                            offset.set(*offset + PAGE_SIZE);
                                        })
                                    }}
                                    class="px-3 py-1.5 rounded-lg text-sm bg-tertiary hover:bg-default transition disabled:opacity-40 disabled:cursor-not-allowed"
                                >
                                    { "Next" }
                                </button>
                            </div>
                        </div>
                    }
                </section>
            }
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend gives `username` precedence over `resource` and ignores the
    /// latter entirely, so the UI must never build a request carrying both.
    #[test]
    fn a_filter_selects_exactly_one_backend_parameter() {
        assert_eq!(filter_params(AuditFilter::None, "x"), (None, None));
        assert_eq!(
            filter_params(AuditFilter::Username, "admin"),
            (Some("admin".to_string()), None)
        );
        assert_eq!(
            filter_params(AuditFilter::Resource, "site:acme"),
            (None, Some("site:acme".to_string()))
        );
    }

    /// Guards the invariant the backend cannot express: `username` wins and
    /// `resource` is dropped, so sending both is a silent no-op on one field.
    #[test]
    fn the_two_filters_are_never_simultaneously_populated() {
        for f in FILTERS.iter() {
            let (username, resource) = filter_params(f.filter, "value");
            assert!(
                !(username.is_some() && resource.is_some()),
                "sending both silently discards `resource` server-side"
            );
        }
    }
}
