//! Pure nftables batch rendering for the Linux baseline (Phase 95).
//!
//! This module is platform-independent and performs zero kernel mutation.
//! The Linux `NftablesFilter` backend (`nftables.rs`) loads the exact string
//! rendered here through a single `nft -f -` transaction.
//!
//! Batch grammar (all imperative, one command per line):
//!
//! ```text
//! destroy table inet <table>
//! add table inet <table>
//! add chain inet <table> input_icmp { type filter hook input priority -150; policy accept; }
//! add rule inet <table> input_icmp <match> <verdict>
//! ...
//! add chain inet <table> output_icmp { type filter hook output priority -150; policy accept; }
//! add rule inet <table> output_icmp <match> <verdict>
//! ...
//! add chain inet <table> gen_<16hex>
//! ```
//!
//! Rule order inside each hook chain is load-bearing:
//!
//! 1. exempt-source ACCEPTs (bypass everything, including the global cap);
//! 2. global rate-limit DROP-over-limit (when enabled; must precede per-type
//!    ACCEPTs or allowed types bypass the cap — native `rate_limit_global`
//!    proved this in Phase 95 run `36333721321`);
//! 3. per-type ALLOW/BLOCK rules (double-protocol form
//!    `ip protocol icmp icmp type …`, likewise `ip6 nexthdr icmpv6 …`);
//! 4. plain base DROP (no embedded limit; the limit already ran early).
//!
//! Why this shape:
//!
//! - `nft -f -` (stdin batch) rejects the previous composition of
//!   `flush table inet ...` followed by a declarative `table inet ... { ... }`
//!   block split across lines (`table inet <t>` + newline + `{`). Native
//!   nftables 1.0.9 reported `syntax error, unexpected '{'` at the opening
//!   brace and cascading errors for every inner `chain`/`type`/`policy`/rule
//!   line (Phase 93 run `36279326809`, 0/8). Every line here is a complete
//!   imperative command, which is what stdin batch mode parses.
//! - `destroy table` is idempotent (no error when the table is absent, unlike
//!   `delete`), so the same batch serves first install and replacement, and
//!   unlike `flush table` (which leaves chains behind and caused stale
//!   `gen_*` markers plus rule-append instead of replace in run
//!   `36333721321`) it truly clears the previous generation.
//! - A single `nft -f` load is atomic: on failure the previous owned table
//!   survives, which is what the rollback/failure-path case requires. No
//!   `flush ruleset`, no host-scoped flush, no unrelated-table mutation.
//! - Disable never uses this batch; it runs scoped
//!   `delete table inet <owned-table>` only.

use crate::config::{Direction, IcmpFilterConfig, IcmpTypeRule, InterfaceSpec};
use crate::enforce::fingerprint_hex;

/// Generation marker chain binding an owned table to one policy fingerprint.
pub(crate) fn marker_chain(fingerprint: u64) -> String {
    format!("gen_{}", fingerprint_hex(fingerprint))
}

/// Scoped delete argv used by the disable path (owned table only).
/// Single source of truth: `nftables::remove_ruleset` executes exactly this.
pub(crate) fn delete_table_argv(table: &str) -> Vec<String> {
    ["delete", "table", "inet", table]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn wants_input(config: &IcmpFilterConfig) -> bool {
    config.direction == Direction::Both || config.direction == Direction::Inbound
}

fn wants_output(config: &IcmpFilterConfig) -> bool {
    config.direction == Direction::Both || config.direction == Direction::Outbound
}

fn interface_filters(config: &IcmpFilterConfig) -> (String, String) {
    match &config.interfaces {
        InterfaceSpec::All => (String::new(), String::new()),
        InterfaceSpec::Specific(ifaces) => {
            if ifaces.len() == 1 {
                (format!("iif {} ", ifaces[0]), format!("oif {} ", ifaces[0]))
            } else {
                let list = ifaces.join(", ");
                (format!("iif {{ {list} }} "), format!("oif {{ {list} }} "))
            }
        }
    }
}

fn icmp_type_match_body(rule: &IcmpTypeRule, interface_filter: &str, is_v6: bool) -> String {
    let action = if rule.is_block() { "drop" } else { "accept" };
    let proto = if is_v6 { "icmpv6" } else { "icmp" };
    let ip_proto = if is_v6 { "ip6 nexthdr" } else { "ip protocol" };
    // `ip protocol icmp` selects the L4 proto; the following `icmp type …`
    // (and optional `icmp code …`) selects within the ICMP header. Both
    // `icmp` tokens are required: `ip protocol icmp type 8` parses `type`
    // as unexpected (native nft 1.0.9, Phase 95 run 36332367209).
    let type_match = if let Some(code) = rule.icmp_code {
        format!(
            "{} type {} {} code {} {}",
            proto, rule.icmp_type, proto, code, action
        )
    } else {
        format!("{} type {} {}", proto, rule.icmp_type, action)
    };
    format!("{interface_filter}{ip_proto} {proto} {type_match}")
}

fn base_match_body(interface_filter: &str, is_v6: bool) -> String {
    // Plain terminal drop. The global rate cap (when enabled) is emitted as
    // separate early rules via `limit_match_body` so it precedes per-type
    // ACCEPTs; embedding the limit here would leave allowed types uncapped.
    let (proto, ip_proto) = if is_v6 {
        ("icmpv6", "ip6 nexthdr")
    } else {
        ("icmp", "ip protocol")
    };
    format!("{interface_filter}{ip_proto} {proto} drop")
}

/// Global rate-cap rule bodies (one per family) when the policy enables the
/// limiter. Emitted after exempt ACCEPTs and before per-type rules so the
/// cap is truly global for non-exempt traffic.
fn limit_match_bodies(config: &IcmpFilterConfig, interface_filter: &str) -> Vec<String> {
    let Some(ref rate_limit) = config.rate_limit else {
        return Vec::new();
    };
    if !rate_limit.enabled {
        return Vec::new();
    }
    vec![
        format!(
            "{interface_filter}ip protocol icmp limit rate over {}/second burst {} packets drop",
            rate_limit.packets_per_second, rate_limit.burst
        ),
        format!(
            "{interface_filter}ip6 nexthdr icmpv6 limit rate over {}/second burst {} packets drop",
            rate_limit.packets_per_second, rate_limit.burst
        ),
    ]
}

/// Paired echo-reply auto-allowance.
///
/// A stateless `ALLOW echo-request` alone cannot make `ping` work: the
/// request (v4 type 8 / v6 type 128) is accepted on ingress, but the
/// kernel-generated reply (v4 type 0 / v6 type 129) leaves via the opposite
/// hook chain and hits the terminal base DROP. Native
/// `atomic_update_replacement` (allow-echo generation B) and
/// `rate_limit_global` (allow-echo under-limit) both proved
/// `allowed_b=false` / `below=0/3` without this.
///
/// When the policy explicitly allows the request type and carries no
/// explicit rule (allow or block) for the paired reply type, emit an
/// `ALLOW` for the reply in both hook chains so bidirectional echo works.
/// An explicit reply rule always wins (no auto-add), and a blocked request
/// never auto-allows its reply.
fn echo_reply_auto_allows(config: &IcmpFilterConfig) -> Vec<(u8, bool)> {
    let mut out = Vec::new();
    let v4_has = |t: u8| config.icmp_type_rules.iter().any(|r| r.icmp_type == t);
    let v4_allows = |t: u8| {
        config
            .icmp_type_rules
            .iter()
            .any(|r| r.icmp_type == t && r.is_allow())
    };
    if v4_allows(8) && !v4_has(0) {
        out.push((0, false));
    }
    let v6_has = |t: u8| config.icmpv6_type_rules.iter().any(|r| r.icmp_type == t);
    let v6_allows = |t: u8| {
        config
            .icmpv6_type_rules
            .iter()
            .any(|r| r.icmp_type == t && r.is_allow())
    };
    if v6_allows(128) && !v6_has(129) {
        out.push((129, true));
    }
    out
}

/// Render the single atomic replacement batch for install, replacement,
/// drift repair, and rollback-retry paths (all share this exact grammar).
pub(crate) fn render_batch(config: &IcmpFilterConfig, fingerprint: u64) -> String {
    let table = &config.table_name;
    let mut lines = Vec::new();
    // Idempotent destroy (no-op when absent) then create, both inside one
    // atomic transaction. `flush table` is insufficient: it leaves chains
    // (including the previous `gen_*` marker) behind, turning replacement
    // into rule-append with a stale generation still present.
    lines.push(format!("destroy table inet {table}"));
    lines.push(format!("add table inet {table}"));

    let (in_if, out_if) = interface_filters(config);

    if wants_input(config) {
        lines.push(format!(
            "add chain inet {table} input_icmp {{ type filter hook input priority -150; policy accept; }}"
        ));
        for ip in &config.exempt_ips {
            let body = match ip {
                std::net::IpAddr::V4(addr) => format!("{in_if}ip saddr {addr} accept"),
                std::net::IpAddr::V6(addr) => format!("{in_if}ip6 saddr {addr} accept"),
            };
            lines.push(format!("add rule inet {table} input_icmp {body}"));
        }
        for body in limit_match_bodies(config, &in_if) {
            lines.push(format!("add rule inet {table} input_icmp {body}"));
        }
        for rule in &config.icmp_type_rules {
            let body = icmp_type_match_body(rule, &in_if, false);
            lines.push(format!("add rule inet {table} input_icmp {body}"));
        }
        for rule in &config.icmpv6_type_rules {
            let body = icmp_type_match_body(rule, &in_if, true);
            lines.push(format!("add rule inet {table} input_icmp {body}"));
        }
        for (reply_type, is_v6) in echo_reply_auto_allows(config) {
            let auto = IcmpTypeRule::new(reply_type, crate::config::IcmpAction::Allow);
            let body = icmp_type_match_body(&auto, &in_if, is_v6);
            lines.push(format!("add rule inet {table} input_icmp {body}"));
        }
        for is_v6 in [false, true] {
            let body = base_match_body(&in_if, is_v6);
            lines.push(format!("add rule inet {table} input_icmp {body}"));
        }
    }

    if wants_output(config) {
        lines.push(format!(
            "add chain inet {table} output_icmp {{ type filter hook output priority -150; policy accept; }}"
        ));
        for ip in &config.exempt_ips {
            let body = match ip {
                std::net::IpAddr::V4(addr) => format!("{out_if}ip daddr {addr} accept"),
                std::net::IpAddr::V6(addr) => format!("{out_if}ip6 daddr {addr} accept"),
            };
            lines.push(format!("add rule inet {table} output_icmp {body}"));
        }
        for body in limit_match_bodies(config, &out_if) {
            lines.push(format!("add rule inet {table} output_icmp {body}"));
        }
        for rule in &config.icmp_type_rules {
            let body = icmp_type_match_body(rule, &out_if, false);
            lines.push(format!("add rule inet {table} output_icmp {body}"));
        }
        for rule in &config.icmpv6_type_rules {
            let body = icmp_type_match_body(rule, &out_if, true);
            lines.push(format!("add rule inet {table} output_icmp {body}"));
        }
        for (reply_type, is_v6) in echo_reply_auto_allows(config) {
            let auto = IcmpTypeRule::new(reply_type, crate::config::IcmpAction::Allow);
            let body = icmp_type_match_body(&auto, &out_if, is_v6);
            lines.push(format!("add rule inet {table} output_icmp {body}"));
        }
        for is_v6 in [false, true] {
            let body = base_match_body(&out_if, is_v6);
            lines.push(format!("add rule inet {table} output_icmp {body}"));
        }
    }

    // Generation marker: unhooked inert chain. Readback requires it;
    // unrelated operator tables never carry this name.
    lines.push(format!(
        "add chain inet {table} {}",
        marker_chain(fingerprint)
    ));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Direction, FilterType, IcmpAction, InterfaceSpec, RateLimitConfig};

    fn minimal_config() -> IcmpFilterConfig {
        IcmpFilterConfig {
            enabled: true,
            filter_type: FilterType::Nftables,
            direction: Direction::Both,
            interfaces: InterfaceSpec::All,
            rate_limit: None,
            exempt_ips: Vec::new(),
            table_name: "synvoid_q_abc123".to_string(),
            icmp_type_rules: vec![IcmpTypeRule::new(8, IcmpAction::Block)],
            icmpv6_type_rules: Vec::new(),
            ebpf_bytecode_path: None,
        }
    }

    #[test]
    fn batch_uses_destroy_add_sequence() {
        let cfg = minimal_config();
        let batch = render_batch(&cfg, 0x0123_4567_89ab_cdef);
        let lines: Vec<&str> = batch.lines().collect();
        assert!(
            lines.len() >= 5,
            "batch must carry table+chains+rules+marker"
        );
        assert_eq!(lines[0], "destroy table inet synvoid_q_abc123");
        assert_eq!(lines[1], "add table inet synvoid_q_abc123");
        assert!(
            lines[2]
                .starts_with("add chain inet synvoid_q_abc123 input_icmp { type filter hook input"),
            "third line must create the input base chain, got: {}",
            lines[2]
        );
        assert!(
            batch.contains("add chain inet synvoid_q_abc123 output_icmp { type filter hook output"),
            "both-direction batch must create the output base chain"
        );
        assert!(
            batch.contains("add chain inet synvoid_q_abc123 gen_0123456789abcdef"),
            "batch must carry the generation marker chain"
        );
        assert!(
            batch.contains(
                "add rule inet synvoid_q_abc123 input_icmp ip protocol icmp icmp type 8 drop"
            ),
            "type rule must be an add-rule command, got:\n{batch}"
        );
        // `flush table` leaves chains (and stale markers) behind; replacement
        // must destroy so the new generation is exact, not appended.
        assert!(
            !batch.contains("flush table "),
            "replacement must destroy, not flush, got:\n{batch}"
        );
    }

    #[test]
    fn batch_rejects_legacy_flush_plus_declarative() {
        let cfg = minimal_config();
        let batch = render_batch(&cfg, 1);
        // The Phase 93 failure: `flush table ...` + bare `table inet ...` + `{`.
        assert!(
            !batch.contains("flush table inet synvoid_q_abc123\ntable inet"),
            "must not compose flush with a declarative table block"
        );
        for line in batch.lines() {
            let t = line.trim_start();
            assert!(
                !t.starts_with("table inet "),
                "bare declarative `table inet` line is forbidden, got: {line}"
            );
            assert!(
                !t.starts_with("chain "),
                "bare declarative `chain` line is forbidden, got: {line}"
            );
            // Rule bodies must never appear as bare lines; they need add-rule.
            if t.starts_with("ip protocol") || t.starts_with("ip6 nexthdr") {
                panic!("bare rule body without `add rule` prefix is forbidden, got: {line}");
            }
            if t == "{" || t == "}" {
                panic!("declarative brace-only line is forbidden, got: {line}");
            }
        }
        // Every nft line is an imperative command.
        for line in batch.lines() {
            assert!(
                line.starts_with("destroy table ")
                    || line.starts_with("add table ")
                    || line.starts_with("add chain ")
                    || line.starts_with("add rule "),
                "every batch line must be imperative, got: {line}"
            );
        }
    }

    #[test]
    fn batch_preserves_atomic_owned_scope() {
        let cfg = minimal_config();
        let batch = render_batch(&cfg, 42);
        assert!(
            !batch.contains("flush ruleset"),
            "must never flush the whole ruleset"
        );
        assert!(
            !batch.contains("flush table "),
            "must destroy, not flush, so stale chains cannot survive replacement"
        );
        assert!(
            !batch.contains("flush chain"),
            "must not flush unrelated chains"
        );
        for line in batch.lines() {
            assert!(
                line.contains("synvoid_q_abc123"),
                "every line must be scoped to the owned table, got: {line}"
            );
        }
    }

    #[test]
    fn install_and_replacement_share_one_batch() {
        // Install, atomic replacement, drift repair, and rollback-retry all
        // load this exact renderer; determinism + fingerprint binding is the
        // contract that lets readback distinguish generations.
        let cfg = minimal_config();
        let a = render_batch(&cfg, 0xaaaa);
        let b = render_batch(&cfg, 0xaaaa);
        assert_eq!(a, b, "same config+fingerprint must render identically");
        let c = render_batch(&cfg, 0xbbbb);
        assert_ne!(
            a, c,
            "different fingerprints must produce different marker chains"
        );
        assert!(c.contains(&marker_chain(0xbbbb)));
    }

    #[test]
    fn disable_is_owned_delete_only() {
        let argv = delete_table_argv("synvoid_q_abc123");
        assert_eq!(
            argv,
            vec![
                "delete".to_string(),
                "table".to_string(),
                "inet".to_string(),
                "synvoid_q_abc123".to_string()
            ]
        );
        // The replacement batch uses idempotent `destroy` (not `delete`, which
        // fails when absent); disable never loads the batch.
        let batch = render_batch(&minimal_config(), 7);
        assert!(!batch.contains("delete "), "replacement must not delete");
    }

    #[test]
    fn direction_matrix_controls_chains() {
        let mut inbound = minimal_config();
        inbound.direction = Direction::Inbound;
        let b = render_batch(&inbound, 1);
        assert!(b.contains("input_icmp"), "inbound must keep input chain");
        assert!(
            !b.contains("output_icmp"),
            "inbound must not create output chain"
        );

        let mut outbound = minimal_config();
        outbound.direction = Direction::Outbound;
        let b = render_batch(&outbound, 1);
        assert!(
            !b.contains("input_icmp"),
            "outbound must not create input chain"
        );
        assert!(b.contains("output_icmp"), "outbound must keep output chain");
    }

    #[test]
    fn exempt_rate_code_rules_render_as_add_rule() {
        let mut cfg = minimal_config();
        cfg.exempt_ips = vec!["10.201.0.2".parse().unwrap()];
        cfg.icmp_type_rules = vec![
            IcmpTypeRule::new(8, IcmpAction::Block).with_code(0),
            IcmpTypeRule::new(0, IcmpAction::Allow),
        ];
        cfg.rate_limit = Some(RateLimitConfig {
            enabled: true,
            packets_per_second: 10,
            burst: 20,
        });
        let batch = render_batch(&cfg, 9);
        assert!(
            batch.contains("add rule inet synvoid_q_abc123 input_icmp ip saddr 10.201.0.2 accept"),
            "exempt source must be an add-rule accept, got:\n{batch}"
        );
        assert!(
            batch.contains("icmp type 8 icmp code 0 drop"),
            "code-qualified rule must survive, got:\n{batch}"
        );
        assert!(
            batch.contains("limit rate over 10/second burst 20 packets drop"),
            "rate-limit base rule must survive, got:\n{batch}"
        );
        assert!(
            batch.contains("add rule inet synvoid_q_abc123 output_icmp ip daddr 10.201.0.2 accept"),
            "output exempt must use daddr, got:\n{batch}"
        );
        // Global cap must precede per-type ACCEPTs or allowed types bypass
        // it (native `rate_limit_global` proved burst_loss=false otherwise).
        let limit_pos = batch
            .find("limit rate over 10/second burst 20 packets drop")
            .expect("limit rule must be present");
        let allow_pos = batch
            .find("icmp type 0 accept")
            .expect("allow rule must be present");
        assert!(
            limit_pos < allow_pos,
            "limit must precede type allow, got:\n{batch}"
        );
        // Base stays a plain terminal drop; the cap already ran early.
        assert!(
            batch.contains("add rule inet synvoid_q_abc123 input_icmp ip protocol icmp drop"),
            "base must remain a plain drop, got:\n{batch}"
        );
    }

    #[test]
    fn v6_rules_use_ip6_nexthdr() {
        let mut cfg = minimal_config();
        cfg.icmpv6_type_rules = vec![IcmpTypeRule::new(128, IcmpAction::Block)];
        let batch = render_batch(&cfg, 11);
        assert!(
            batch.contains(
                "add rule inet synvoid_q_abc123 input_icmp ip6 nexthdr icmpv6 icmpv6 type 128 drop"
            ),
            "v6 type rule must use ip6 nexthdr, got:\n{batch}"
        );
        assert!(
            batch.contains("add rule inet synvoid_q_abc123 input_icmp ip6 nexthdr icmpv6 drop"),
            "v6 base rule must use ip6 nexthdr, got:\n{batch}"
        );
    }

    #[test]
    fn marker_chain_format_is_stable() {
        assert_eq!(marker_chain(0x0123_4567_89ab_cdef), "gen_0123456789abcdef");
        assert!(marker_chain(0).starts_with("gen_"));
    }

    #[test]
    fn allow_echo_auto_allows_reply_both_chains() {
        let mut cfg = minimal_config();
        // minimal_config blocks echo; switch to allow to trigger pairing.
        cfg.icmp_type_rules = vec![IcmpTypeRule::new(8, IcmpAction::Allow)];
        let batch = render_batch(&cfg, 77);
        assert!(
            batch.contains(
                "add rule inet synvoid_q_abc123 input_icmp ip protocol icmp icmp type 0 accept"
            ),
            "input must auto-allow echo-reply, got:\n{batch}"
        );
        assert!(
            batch.contains(
                "add rule inet synvoid_q_abc123 output_icmp ip protocol icmp icmp type 0 accept"
            ),
            "output must auto-allow echo-reply, got:\n{batch}"
        );
    }

    #[test]
    fn explicit_reply_rule_wins_over_auto() {
        let mut cfg = minimal_config();
        cfg.icmp_type_rules = vec![
            IcmpTypeRule::new(8, IcmpAction::Allow),
            IcmpTypeRule::new(0, IcmpAction::Block),
        ];
        let batch = render_batch(&cfg, 78);
        // Explicit BLOCK 0 present; auto ALLOW 0 must not appear.
        assert!(
            batch.contains("icmp type 0 drop"),
            "explicit block must survive, got:\n{batch}"
        );
        assert!(
            !batch.contains("icmp type 0 accept"),
            "auto-allow must not override explicit block, got:\n{batch}"
        );
    }

    #[test]
    fn block_echo_never_auto_allows_reply() {
        // minimal_config blocks 8 and has no 0 rule: no auto-allow.
        let batch = render_batch(&minimal_config(), 79);
        assert!(
            !batch.contains("type 0"),
            "blocked request must not auto-allow reply, got:\n{batch}"
        );
    }
}
