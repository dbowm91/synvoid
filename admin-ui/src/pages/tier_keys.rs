use crate::services::api::ApiService;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct TierKeyInfo {
    pub key_id: String,
    pub tier: u32,
    pub valid_from: u64,
    pub valid_until: u64,
    pub issued_by: String,
    pub bound_to: Option<String>,
    pub is_unspent: bool,
    pub revoked: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct TierKeyListResponse {
    pub tier_keys: Vec<TierKeyInfo>,
    pub total: usize,
    pub unspent_count: usize,
}

pub struct TierKeys {
    tier_keys: Vec<TierKeyInfo>,
    loading: bool,
    error: Option<String>,
    show_issue_modal: bool,
    issue_org_id: String,
    issue_tier: u32,
}

pub enum Msg {
    LoadTierKeys,
    TierKeysLoaded(Vec<TierKeyInfo>),
    LoadError(String),
    ToggleIssueModal,
    SetOrgId(String),
    SetTier(u32),
    IssueKey,
    RevokeKey(String, String),
    UnbindKey(String, String),
}

#[derive(Properties, PartialEq)]
pub struct Props {}

impl Component for TierKeys {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Msg::LoadTierKeys);
        Self {
            tier_keys: Vec::new(),
            loading: false,
            error: None,
            show_issue_modal: false,
            issue_org_id: String::new(),
            issue_tier: 1,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::LoadTierKeys => {
                self.loading = true;
                let link = ctx.link().clone();
                spawn_local(async move {
                    let api = ApiService::new();
                    match api.get::<TierKeyListResponse>("/tier-keys").await {
                        Ok(response) => {
                            link.send_message(Msg::TierKeysLoaded(response.tier_keys));
                        }
                        Err(e) => {
                            link.send_message(Msg::LoadError(e));
                        }
                    }
                });
                true
            }
            Msg::TierKeysLoaded(keys) => {
                self.tier_keys = keys;
                self.loading = false;
                true
            }
            Msg::LoadError(e) => {
                self.error = Some(e);
                self.loading = false;
                true
            }
            Msg::ToggleIssueModal => {
                self.show_issue_modal = !self.show_issue_modal;
                if self.show_issue_modal {
                    self.issue_org_id.clear();
                    self.issue_tier = 1;
                }
                true
            }
            Msg::SetOrgId(org_id) => {
                self.issue_org_id = org_id;
                true
            }
            Msg::SetTier(tier) => {
                self.issue_tier = tier;
                true
            }
            Msg::IssueKey => {
                let org_id = self.issue_org_id.clone();
                let tier = self.issue_tier;
                if !org_id.is_empty() {
                    let api = ApiService::new();
                    let body = serde_json::json!({ "org_id": org_id, "tier": tier });
                    spawn_local(async move {
                        let _: Result<serde_json::Value, _> =
                            api.post("/tier-keys/issue", &body).await;
                    });
                }
                self.show_issue_modal = false;
                true
            }
            Msg::RevokeKey(org_id, key_id) => {
                let api = ApiService::new();
                let body = serde_json::json!({ "org_id": org_id, "key_id": key_id });
                spawn_local(async move {
                    let _: Result<serde_json::Value, _> =
                        api.post("/tier-keys/revoke", &body).await;
                });
                true
            }
            Msg::UnbindKey(org_id, key_id) => {
                let api = ApiService::new();
                let body = serde_json::json!({ "org_id": org_id, "key_id": key_id });
                spawn_local(async move {
                    let _: Result<serde_json::Value, _> =
                        api.post("/tier-keys/unbind", &body).await;
                });
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let on_issue = ctx.link().callback(|_| Msg::ToggleIssueModal);

        html! {
            <div class="space-y-6">
                { if self.show_issue_modal {
                    let on_close = ctx.link().callback(|_| Msg::ToggleIssueModal);
                    html! {
                        <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                            <div class="bg-secondary rounded-lg p-6 w-full max-w-md border border-default">
                                <h2 class="text-xl font-bold mb-4">{ "Issue New Key" }</h2>
                                <p class="text-secondary mb-4">{ "Issue a new tier key with specified tier level" }</p>
                                <div class="mb-4">
                                    <label class="block text-sm font-medium mb-2">{ "Organization ID" }</label>
                                    <input
                                        type="text"
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg"
                                        placeholder="org_xxx"
                                        value={self.issue_org_id.clone()}
                                        oninput={ctx.link().callback(|e: InputEvent| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            Msg::SetOrgId(input.value())
                                        })}
                                    />
                                </div>
                                <div class="mb-4">
                                    <label class="block text-sm font-medium mb-2">{ "Tier Level" }</label>
                                    <select
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg"
                                        value={self.issue_tier.to_string()}
                                        onchange={ctx.link().callback(|e: Event| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            let val = input.value();
                                            Msg::SetTier(val.parse().unwrap_or(1))
                                        })}
                                    >
                                        <option value="1">{ "Tier 1 - Basic" }</option>
                                        <option value="2">{ "Tier 2 - Standard" }</option>
                                        <option value="3">{ "Tier 3 - Premium" }</option>
                                    </select>
                                </div>
                                <div class="flex justify-end gap-4">
                                    <button onclick={on_close} class="px-4 py-2 bg-tertiary rounded-lg">
                                        { "Cancel" }
                                    </button>
                                    <button
                                        onclick={ctx.link().callback(|_| Msg::IssueKey)}
                                        class="px-4 py-2 bg-accent text-white rounded-lg"
                                    >
                                        { "Issue Key" }
                                    </button>
                                </div>
                            </div>
                        </div>
                    }
                } else {
                    html! {}
                }}

                <div class="flex justify-between items-center">
                    <div>
                        <h1 class="text-2xl font-bold">{ "Tier Keys" }</h1>
                        <p class="text-secondary">{ "Manage tier keys and their binding status" }</p>
                    </div>
                    <button
                        onclick={on_issue}
                        class="px-4 py-2 bg-accent text-white rounded-lg hover:opacity-80"
                    >
                        { "Issue New Key" }
                    </button>
                </div>

                if self.loading {
                    <div class="text-center py-10">
                        <p class="text-secondary">{ "Loading tier keys..." }</p>
                    </div>
                } else if let Some(error) = &self.error {
                    <div class="bg-red-900/20 border border-red-500 rounded-lg p-4">
                        <p class="text-red-400">{ error }</p>
                    </div>
                } else {
                    <div class="bg-secondary rounded-lg border border-default overflow-hidden">
                        <table class="w-full">
                            <thead class="bg-tertiary">
                                <tr>
                                    <th class="px-4 py-3 text-left text-sm font-semibold">{ "Key ID" }</th>
                                    <th class="px-4 py-3 text-left text-sm font-semibold">{ "Tier" }</th>
                                    <th class="px-4 py-3 text-left text-sm font-semibold">{ "Bound To" }</th>
                                    <th class="px-4 py-3 text-left text-sm font-semibold">{ "Status" }</th>
                                    <th class="px-4 py-3 text-left text-sm font-semibold">{ "Valid Until" }</th>
                                    <th class="px-4 py-3 text-left text-sm font-semibold">{ "Actions" }</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-default">
                                { for self.tier_keys.iter().map(|key| {
                                    let status = if key.revoked {
                                        html! { <span class="text-red-400">{ "Revoked" }</span> }
                                    } else if key.is_unspent {
                                        html! { <span class="text-yellow-400">{ "Unspent" }</span> }
                                    } else {
                                        html! { <span class="text-green-400">{ "Active" }</span> }
                                    };

                                    let bound_to = key.bound_to.clone().unwrap_or_else(|| "None".to_string());
                                    let key_id = key.key_id.clone();
                                    let bound_for_revoke = key.bound_to.clone().unwrap_or_default();
                                    let key_id_for_revoke = key.key_id.clone();
                                    let bound_for_unbind = key.bound_to.clone().unwrap_or_default();
                                    let key_id_for_unbind = key.key_id.clone();

                                    let on_revoke = {
                                        let link = ctx.link().clone();
                                        move |_| {
                                            link.send_message(Msg::RevokeKey(bound_for_revoke.clone(), key_id_for_revoke.clone()));
                                        }
                                    };
                                    let on_unbind = {
                                        let link = ctx.link().clone();
                                        move |_| {
                                            link.send_message(Msg::UnbindKey(bound_for_unbind.clone(), key_id_for_unbind.clone()));
                                        }
                                    };

                                    html! {
                                        <tr class="hover:bg-tertiary/50">
                                            <td class="px-4 py-3 font-mono text-sm">{ &key.key_id[..8] }</td>
                                            <td class="px-4 py-3">{ key.tier }</td>
                                            <td class="px-4 py-3">{ bound_to }</td>
                                            <td class="px-4 py-3">{ status }</td>
                                            <td class="px-4 py-3">{ key.valid_until }</td>
                                            <td class="px-4 py-3">
                                                if !key.revoked && !key.is_unspent {
                                                    <button
                                                        onclick={on_unbind}
                                                        class="text-yellow-400 hover:text-yellow-300 text-sm mr-2"
                                                    >
                                                        { "Unbind" }
                                                    </button>
                                                }
                                                if !key.revoked {
                                                    <button
                                                        onclick={on_revoke}
                                                        class="text-red-400 hover:text-red-300 text-sm"
                                                    >
                                                        { "Revoke" }
                                                    </button>
                                                }
                                            </td>
                                        </tr>
                                    }
                                }) }
                            </tbody>
                        </table>
                    </div>
                }
            </div>
        }
    }
}
