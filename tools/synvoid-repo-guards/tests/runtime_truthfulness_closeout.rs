//! Phase 48 campaign-status drift guard.
//!
//! Pins the Phase 41-47 corrective closeout so the planning surface cannot
//! silently drift back to "active handoff" and so the stale eggfetch
//! version claim cannot return to current-state docs.
//!
//! Scope is deliberately narrow:
//! - status surfaces only (umbrella roadmap, Phase 41-48 plans,
//!   `plans/roadmap.md`, closeout report + follow-up plan existence);
//! - the known stale literal `eggfetch still 0.1.4` in current-state docs
//!   only (`AGENTS.md`, `architecture/public_crate_release_readiness_phase47.md`,
//!   `architecture/agent_knowledge_maintenance.md`).
//!
//! Historical records under `plans/` (Phase 34/35 matrices, dated decision
//! text) and dated architecture decision records are explicitly out of
//! scope: they are allowed to describe what was true at the time.

use synvoid_repo_guards::workspace_root;

fn read_repo(rel: &str) -> String {
    let repo = workspace_root();
    std::fs::read_to_string(repo.join(rel))
        .unwrap_or_else(|_| panic!("runtime_truthfulness_closeout_guard: read {rel}"))
}

#[test]
fn umbrella_roadmap_is_closed() {
    let body = read_repo("plans/runtime_truthfulness_security_publication_roadmap.md");
    assert!(
        body.contains("Status: complete"),
        "runtime_truthfulness_closeout_guard: umbrella roadmap must be marked complete, not active"
    );
    assert!(
        !body.contains("Status: detailed active handoff roadmap"),
        "runtime_truthfulness_closeout_guard: umbrella roadmap still claims active handoff"
    );
    assert!(
        body.contains("architecture/runtime_truthfulness_security_publication_closeout.md"),
        "runtime_truthfulness_closeout_guard: umbrella roadmap must point at the closeout report"
    );
}

#[test]
fn phase_plans_are_closed() {
    let plans = [
        "plans/phase_41_fail_closed_config_and_process_bounds.md",
        "plans/phase_42_shared_memory_unsafe_boundary_hardening.md",
        "plans/phase_43_auth_cpu_and_persistence_hardening.md",
        "plans/phase_44_pqc_dependency_truth_and_kyberslash_closure.md",
        "plans/phase_45_dns_runtime_contract_and_protocol_completeness.md",
        "plans/phase_46_platform_sandbox_truthfulness_and_macos_closure.md",
        "plans/phase_47_public_crate_release_readiness.md",
    ];
    let mut violations = Vec::new();
    for rel in plans {
        let body = read_repo(rel);
        if body.contains("Status: detailed handoff plan.") {
            violations.push(format!("{rel} still marked as active handoff plan"));
        }
        if !body.contains("implemented and closed") {
            violations.push(format!("{rel} missing implemented-and-closed status"));
        }
        if !body.contains("runtime_truthfulness_security_publication_closeout.md") {
            violations.push(format!("{rel} missing closeout report pointer"));
        }
    }
    assert!(
        violations.is_empty(),
        "runtime_truthfulness_closeout_guard:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn phase_48_plan_is_closed() {
    let body = read_repo("plans/phase_48_runtime_truthfulness_campaign_corrective_closeout.md");
    assert!(
        body.contains("Status: implemented and closed"),
        "runtime_truthfulness_closeout_guard: Phase 48 plan must be marked implemented and closed"
    );
    assert!(
        !body.contains("Status: detailed active corrective handoff plan"),
        "runtime_truthfulness_closeout_guard: Phase 48 plan still claims active handoff"
    );
    assert!(
        body.contains("architecture/runtime_truthfulness_security_publication_closeout.md"),
        "runtime_truthfulness_closeout_guard: Phase 48 plan must point at the closeout report"
    );
}

#[test]
fn top_level_roadmap_agrees() {
    let body = read_repo("plans/roadmap.md");
    assert!(
        !body.contains("Phase 48 is the active corrective closeout")
            && !body.contains("Phase 48 corrective closeout active"),
        "runtime_truthfulness_closeout_guard: plans/roadmap.md still marks Phase 48 active after closeout"
    );
    assert!(
        body.contains("runtime_truthfulness_security_publication_closeout.md")
            || body.contains("Phase 48") && body.contains("omplete"),
        "runtime_truthfulness_closeout_guard: plans/roadmap.md must record the completed campaign/closeout"
    );
}

#[test]
fn no_stale_eggfetch_literal_in_current_state_docs() {
    let current_state = [
        "AGENTS.md",
        "architecture/public_crate_release_readiness_phase47.md",
        "architecture/agent_knowledge_maintenance.md",
    ];
    let mut violations = Vec::new();
    for rel in current_state {
        let body = read_repo(rel);
        if body.contains("eggfetch still 0.1.4") {
            violations.push(format!(
                "{rel} contains stale present-tense `eggfetch still 0.1.4`"
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "runtime_truthfulness_closeout_guard: stale eggfetch claim in current-state docs:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn closeout_and_followup_records_exist() {
    let closeout = read_repo("architecture/runtime_truthfulness_security_publication_closeout.md");
    assert!(
        closeout.contains("Phase 41") && closeout.contains("Phase 47"),
        "runtime_truthfulness_closeout_guard: closeout report must cover Phase 41-47"
    );
    let followup = read_repo("plans/eggfetch_current_line_parity_review.md");
    assert!(
        followup.contains("synvoid-http-client") && followup.contains("matrix"),
        "runtime_truthfulness_closeout_guard: eggfetch follow-up plan must own the parity decision gate"
    );
}
