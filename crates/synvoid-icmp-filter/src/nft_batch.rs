//! Pure nftables batch rendering for the Linux baseline (Phase 95).
//!
//! This module is platform-independent and performs zero kernel mutation.
//! The Linux `NftablesFilter` backend (`nftables.rs`) loads the exact string
//! rendered here through a single `nft -f -` transaction.
//!
//! Batch grammar (all imperative, one command per line):
//!
//! ```text
//! add table inet <table>
//! flush table inet <table>
//! add chain inet <table> input_icmp { type filter hook input priority -150; policy accept; }
//! add rule inet <table> input_icmp <match> <verdict>
//! ...
//! add chain inet <table> output_icmp { type filter hook output priority -150; policy accept; }
//! add rule inet <table> output_icmp <match> <verdict>
//! ...
//! add chain inet <table> gen_<16hex>
//! ```
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
//! - `add table` is idempotent (`create` would fail when the table already
//!   exists), so the same batch serves first install and replacement.
//! - `flush table` inside the same transaction clears stale chains/rules
//!   from the previous generation (including the previous `gen_*` marker)
//!   without touching unrelated tables. No `flush ruleset`, no
//!   `delete table`, no host-scoped flush.
//! - A single `nft -f` load is atomic: on failure the previous owned table
//!   survives, which is what the rollback/failure-path case requires.
//! - Disable never uses this batch; it runs scoped
//!   `delete table inet <owned-table>` only.

use crate::config::{Direction, IcmpFilterConfig, IcmpTypeRule, InterfaceSpec};
use crate::enforce::fingerprint_hex;

/// Generation marker chain binding an owned table to one policy fingerprint.
pub(crate) fn marker_chain(fingerprint: u64) -> String {
    format!("gen_{}", fingerprint_hex(fingerprint))
}

/// Scoped delete command used by the disable path (owned table only).
pub(crate) fn delete_table_command(table: &str) -> String {
    format!("delete table inet {table}")
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
    let type_match = if let Some(code) = rule.icmp_code {
        format!(
            "{} type {} {} code {} {}",
            proto, rule.icmp_type, proto, code, action
        )
    } else {
        format!("{} type {} {}", proto, rule.icmp_type, action)
    };
    format!("{interface_filter}{ip_proto} {type_match}")
}

fn base_match_body(config: &IcmpFilterConfig, interface_filter: &str, is_v6: bool) -> String {
    let (proto, ip_proto) = if is_v6 {
        ("icmpv6", "ip6 nexthdr")
    } else {
        ("icmp", "ip protocol")
    };
    if let Some(ref rate_limit) = config.rate_limit {
        if rate_limit.enabled {
            return format!(
                "{interface_filter}{ip_proto} {proto} limit rate over {}/second burst {} packets drop",
                rate_limit.packets_per_second, rate_limit.burst
            );
        }
    }
    format!("{interface_filter}{ip_proto} {proto} drop")
}

/// Render the single atomic replacement batch for install, replacement,
/// drift repair, and rollback-retry paths (all share this exact grammar).
pub(crate) fn render_batch(config: &IcmpFilterConfig, fingerprint: u64) -> String {
    let table = &config.table_name;
    let mut lines = Vec::new();
    // Idempotent create, then owned-scope clear, both inside one transaction.
    lines.push(format!("add table inet {table}"));
    lines.push(format!("flush table inet {table}"));

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
        for rule in &config.icmp_type_rules {
            let body = icmp_type_match_body(rule, &in_if, false);
            lines.push(format!("add rule inet {table} input_icmp {body}"));
        }
        for rule in &config.icmpv6_type_rules {
            let body = icmp_type_match_body(rule, &in_if, true);
            lines.push(format!("add rule inet {table} input_icmp {body}"));
        }
        for is_v6 in [false, true] {
            let body = base_match_body(config, &in_if, is_v6);
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
        for rule in &config.icmp_type_rules {
            let body = icmp_type_match_body(rule, &out_if, false);
            lines.push(format!("add rule inet {table} output_icmp {body}"));
        }
        for rule in &config.icmpv6_type_rules {
            let body = icmp_type_match_body(rule, &out_if, true);
            lines.push(format!("add rule inet {table} output_icmp {body}"));
        }
        for is_v6 in [false, true] {
            let body = base_match_body(config, &out_if, is_v6);
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
    fn batch_uses_add_flush_add_sequence() {
        let cfg = minimal_config();
        let batch = render_batch(&cfg, 0x0123_4567_89ab_cdef);
        let lines: Vec<&str> = batch.lines().collect();
        assert!(
            lines.len() >= 5,
            "batch must carry table+chains+rules+marker"
        );
        assert_eq!(lines[0], "add table inet synvoid_q_abc123");
        assert_eq!(lines[1], "flush table inet synvoid_q_abc123");
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
            batch
                .contains("add rule inet synvoid_q_abc123 input_icmp ip protocol icmp type 8 drop"),
            "type rule must be an add-rule command, got:\n{batch}"
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
                line.starts_with("add table ")
                    || line.starts_with("flush table ")
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
            !batch.contains("delete table"),
            "replacement batch must not delete tables"
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
        let cmd = delete_table_command("synvoid_q_abc123");
        assert_eq!(cmd, "delete table inet synvoid_q_abc123");
        // The replacement batch never deletes; disable never loads the batch.
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
    }

    #[test]
    fn v6_rules_use_ip6_nexthdr() {
        let mut cfg = minimal_config();
        cfg.icmpv6_type_rules = vec![IcmpTypeRule::new(128, IcmpAction::Block)];
        let batch = render_batch(&cfg, 11);
        assert!(
            batch.contains(
                "add rule inet synvoid_q_abc123 input_icmp ip6 nexthdr icmpv6 type 128 drop"
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
}
