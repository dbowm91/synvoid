use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::time::unix_timestamp_secs;

use crate::geo::CountryLookup;
use crate::parsed_query::ParsedDnsQuery;

#[derive(Debug, Clone)]
pub struct DnsFirewallRule {
    pub id: String,
    pub rule_type: DnsFirewallRuleType,
    pub action: DnsFirewallAction,
    pub target: String,
    pub ttl: u32,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsFirewallRuleType {
    Domain,
    IpAddress,
    Subnet,
    QueryType,
    Opcode,
    ResponseCode,
    GeoLocation,
    TimeWindow,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsFirewallAction {
    Block,
    Allow,
    Redirect { target: String },
    Sinkhole,
    RateLimit { limit: u32, window: Duration },
    LogOnly,
}

pub struct DnsFirewall {
    rules: Vec<DnsFirewallRule>,
    last_cleanup: u64,
    country_lookup: Option<Arc<dyn CountryLookup>>,
    /// Phase 135 F-2: an unevaluable geo rule is a real condition an operator
    /// must learn about, but it is evaluated per query. Warn once per firewall
    /// instance so the signal survives without becoming a log flood.
    geo_unavailable_warned: AtomicBool,
}

/// Hand-written rather than derived: the country-lookup capability is a trait
/// object with no `Debug` bound (adding one would constrain every provider for
/// no benefit), and printing a provider's internals in a firewall dump is noise.
impl std::fmt::Debug for DnsFirewall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsFirewall")
            .field("rules", &self.rules.len())
            .field("last_cleanup", &self.last_cleanup)
            .field("can_evaluate_geo_rules", &self.can_evaluate_geo_rules())
            .finish()
    }
}

impl Default for DnsFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsFirewall {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            last_cleanup: 0,
            country_lookup: None,
            geo_unavailable_warned: AtomicBool::new(false),
        }
    }

    /// Attach the country-lookup capability.
    ///
    /// A firewall built without one can still evaluate every non-geo rule. Geo
    /// rules become indeterminate, which is handled fail-closed for restrictive
    /// actions and visibly, rather than silently passing traffic.
    pub fn with_country_lookup(mut self, lookup: Arc<dyn CountryLookup>) -> Self {
        self.country_lookup = Some(lookup);
        self
    }

    /// Whether this firewall can evaluate geo rules at all.
    pub fn can_evaluate_geo_rules(&self) -> bool {
        self.country_lookup.is_some()
    }

    pub fn add_rule(&mut self, rule: DnsFirewallRule) -> Result<(), String> {
        if let Some(expires_at) = rule.expires_at {
            if expires_at < unix_timestamp_secs() {
                return Err("Rule has already expired".to_string());
            }
        }

        self.rules.push(rule);
        Ok(())
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> Result<(), String> {
        self.rules.retain(|r| r.id != rule_id);
        Ok(())
    }

    pub fn evaluate_query(
        &self,
        parsed: &ParsedDnsQuery<'_>,
        client_ip: IpAddr,
        qname: &str,
    ) -> Result<DnsFirewallDecision, String> {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            match self.rule_matches(rule, parsed, client_ip, qname) {
                RuleEvaluation::Yes => {
                    return Ok(DnsFirewallDecision {
                        action: rule.action.clone(),
                        rule_id: rule.id.clone(),
                        reason: format!("Rule {} matched", rule.id),
                    });
                }
                RuleEvaluation::Indeterminate {
                    reason,
                    applied: true,
                } => {
                    self.warn_indeterminate_once(rule, reason);
                    return Ok(DnsFirewallDecision {
                        action: rule.action.clone(),
                        rule_id: rule.id.clone(),
                        reason: format!(
                            "Rule {} could not be evaluated ({}); applied {} because it \
                             is restrictive",
                            rule.id,
                            reason.as_str(),
                            action_name(&rule.action)
                        ),
                    });
                }
                // A permissive rule that cannot be evaluated is skipped, and an
                // unevaluable rule is skipped rather than treated as a match.
                RuleEvaluation::No | RuleEvaluation::Indeterminate { .. } => continue,
            }
        }

        Ok(DnsFirewallDecision {
            action: DnsFirewallAction::Allow,
            rule_id: "default".to_string(),
            reason: "No matching rules, allowing query".to_string(),
        })
    }

    /// Phase 135 F-2: make the unevaluable condition visible once per firewall.
    ///
    /// Silence was half of the original defect: an operator who configured a
    /// country block and had no GeoIP database got no error and no log line, so
    /// the control simply stopped existing. The decision `reason` names the rule
    /// on every affected query; this adds the operator-facing signal without
    /// turning a per-query condition into a log flood.
    fn warn_indeterminate_once(&self, rule: &DnsFirewallRule, reason: RuleIndeterminate) {
        if self.geo_unavailable_warned.swap(true, Ordering::Relaxed) {
            return;
        }
        tracing::warn!(
            rule_id = %rule.id,
            target = %rule.target,
            reason = reason.as_str(),
            "Geo firewall rule cannot be evaluated and is being applied fail-closed. \
             Attach a GeoIP provider, or set the rule disabled to park it"
        );
    }

    pub fn evaluate_response(
        &mut self,
        response: &[u8],
        client_ip: IpAddr,
        qname: &str,
    ) -> Result<DnsFirewallDecision, String> {
        self.cleanup_expired_rules();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if !self.response_rule_matches(rule, response, client_ip, qname) {
                continue;
            }

            return Ok(DnsFirewallDecision {
                action: rule.action.clone(),
                rule_id: rule.id.clone(),
                reason: format!("Response rule {} matched", rule.id),
            });
        }

        Ok(DnsFirewallDecision {
            action: DnsFirewallAction::Allow,
            rule_id: "default".to_string(),
            reason: "No matching response rules, allowing response".to_string(),
        })
    }

    fn rule_matches(
        &self,
        rule: &DnsFirewallRule,
        parsed: &ParsedDnsQuery<'_>,
        client_ip: IpAddr,
        qname: &str,
    ) -> RuleEvaluation {
        match &rule.rule_type {
            DnsFirewallRuleType::Domain => {
                if qname.eq_ignore_ascii_case(&rule.target) {
                    return RuleEvaluation::Yes;
                }
                if qname.ends_with(&format!(".{}", rule.target)) {
                    return RuleEvaluation::Yes;
                }
            }
            DnsFirewallRuleType::IpAddress => {
                if let Ok(rule_ip) = rule.target.parse::<IpAddr>() {
                    if client_ip == rule_ip {
                        return RuleEvaluation::Yes;
                    }
                }
            }
            DnsFirewallRuleType::Subnet => {
                if let Ok(cidr) = rule.target.parse::<ipnetwork::IpNetwork>() {
                    if cidr.contains(client_ip) {
                        return RuleEvaluation::Yes;
                    }
                }
            }
            DnsFirewallRuleType::QueryType => {
                if rule.target == format!("0x{:x}", parsed.qtype) {
                    return RuleEvaluation::Yes;
                }
            }
            DnsFirewallRuleType::Opcode => {
                if rule.target == format!("0x{:x}", parsed.flags.opcode) {
                    return RuleEvaluation::Yes;
                }
            }
            DnsFirewallRuleType::ResponseCode => {
                if rule.target == format!("0x{:x}", parsed.flags.response_code) {
                    return RuleEvaluation::Yes;
                }
            }
            DnsFirewallRuleType::GeoLocation => {
                let geo = rule.target.parse::<GeoLocation>();
                return match geo {
                    Ok(geo) => match geo.matches_ip(client_ip, self.country_lookup.as_ref()) {
                        GeoMatch::Yes => RuleEvaluation::Yes,
                        GeoMatch::No => RuleEvaluation::No,
                        // Phase 135 F-2: a geo rule that cannot be evaluated is
                        // not "no match". A restrictive action is applied anyway;
                        // a permissive one is skipped.
                        GeoMatch::Unavailable => RuleEvaluation::Indeterminate {
                            reason: RuleIndeterminate::NoCountryLookup,
                            applied: rule.action.fails_closed_when_indeterminate(),
                        },
                    },
                    // Phase 133 F-3: `GeoLocation::from_str` is infallible in
                    // practice, so this arm is defensive only. It is kept
                    // because a future validator would land here.
                    Err(_) => RuleEvaluation::Indeterminate {
                        reason: RuleIndeterminate::UnparseableTarget,
                        applied: rule.action.fails_closed_when_indeterminate(),
                    },
                };
            }
            DnsFirewallRuleType::TimeWindow => {
                if let Ok(time_window) = rule.target.parse::<TimeWindow>() {
                    if time_window.contains(chrono::Utc::now()) {
                        return RuleEvaluation::Yes;
                    }
                }
            }
        }

        RuleEvaluation::No
    }

    fn response_rule_matches(
        &self,
        rule: &DnsFirewallRule,
        response: &[u8],
        client_ip: IpAddr,
        qname: &str,
    ) -> bool {
        match &rule.rule_type {
            DnsFirewallRuleType::ResponseCode => {
                let flags = u16::from_be_bytes([response[2], response[3]]);
                let rcode = flags & 0x000F;
                if rule.target == format!("0x{:x}", rcode) {
                    return true;
                }
            }
            DnsFirewallRuleType::Domain => {
                if qname.eq_ignore_ascii_case(&rule.target) {
                    return true;
                }
                if qname.ends_with(&format!(".{}", rule.target)) {
                    return true;
                }
            }
            DnsFirewallRuleType::IpAddress => {
                if let Ok(rule_ip) = rule.target.parse::<IpAddr>() {
                    if client_ip == rule_ip {
                        return true;
                    }
                }
            }
            _ => return false,
        }

        false
    }

    fn cleanup_expired_rules(&mut self) {
        let now = unix_timestamp_secs();
        if now.saturating_sub(self.last_cleanup) < 60 {
            return;
        }

        self.rules.retain(|r| {
            if let Some(expires_at) = r.expires_at {
                expires_at > now
            } else {
                true
            }
        });

        self.last_cleanup = now;
    }

    pub fn get_stats(&self) -> DnsFirewallStats {
        let active_rules = self.rules.len();
        let blocked_queries = 0; // Would be tracked in real implementation
        let blocked_responses = 0; // Would be tracked in real implementation

        DnsFirewallStats {
            active_rules,
            blocked_queries,
            blocked_responses,
            last_cleanup: self.last_cleanup,
        }
    }

    pub fn export_rules(&self, file_path: &str) -> Result<(), String> {
        let export_data = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "rules": self.rules.iter().map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "rule_type": format!("{:?}", r.rule_type),
                    "action": format!("{:?}", r.action),
                    "target": r.target,
                    "ttl": r.ttl,
                    "created_at": r.created_at,
                    "expires_at": r.expires_at,
                    "enabled": r.enabled,
                })
            }).collect::<Vec<_>>(),
        });

        std::fs::write(
            file_path,
            serde_json::to_string_pretty(&export_data).map_err(|e| format!("JSON error: {}", e))?,
        )
        .map_err(|e| format!("Failed to write firewall rules: {}", e))?;

        Ok(())
    }
}

/// Outcome of evaluating a `GeoLocation` rule against a client address.
///
/// Phase 135 F-2: `bool` could not express the case the plan cares about. With
/// only `true`/`false`, a rule that *cannot be evaluated* was
/// indistinguishable from one that was evaluated and did not match, so a
/// `GeoLocation` **block** rule with no provider silently stopped blocking
/// traffic — no error, no log line, and the decision did not even name the
/// skipped rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoMatch {
    /// The provider answered: the address is in the location.
    Yes,
    /// The provider answered: the address is not in the location.
    No,
    /// The provider is absent or could not answer. The rule is indeterminate.
    Unavailable,
}

impl DnsFirewallAction {
    /// Whether this action should be applied when its rule is indeterminate.
    ///
    /// The posture is deliberately asymmetric: a **restrictive** action fails
    /// closed, because a control that cannot be evaluated must not silently let
    /// traffic through, while a **permissive** action fails open, because
    /// applying "allow" to a rule nobody scoped would be granting access nobody
    /// granted.
    pub fn fails_closed_when_indeterminate(&self) -> bool {
        matches!(
            self,
            DnsFirewallAction::Block
                | DnsFirewallAction::Redirect { .. }
                | DnsFirewallAction::Sinkhole
                | DnsFirewallAction::RateLimit { .. }
        )
    }
}

/// Why a rule's condition could not be evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleIndeterminate {
    /// The rule needs a country lookup and there is no provider.
    NoCountryLookup,
    /// The rule's target could not be parsed, so the rule matches nothing.
    UnparseableTarget,
}

/// How a rule evaluated against one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleEvaluation {
    /// Evaluated, and the condition did not hold.
    No,
    /// Evaluated, and the condition held.
    Yes,
    /// The condition could not be evaluated. `applied` is `true` when the
    /// rule's action was applied anyway because it is restrictive.
    Indeterminate {
        reason: RuleIndeterminate,
        applied: bool,
    },
}

#[derive(Debug, Clone)]
pub struct DnsFirewallDecision {
    pub action: DnsFirewallAction,
    pub rule_id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct DnsFirewallStats {
    pub active_rules: usize,
    pub blocked_queries: usize,
    pub blocked_responses: usize,
    pub last_cleanup: u64,
}

#[derive(Debug, Clone)]
pub struct GeoLocation {
    pub country: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
}

impl GeoLocation {
    /// Evaluate this location against a client address.
    ///
    /// Phase 135: takes the DNS-owned [`CountryLookup`] capability and returns
    /// [`GeoMatch`] rather than `bool`, so an unevaluable rule is
    /// distinguishable from a rule that was evaluated and did not match.
    pub fn matches_ip(&self, ip: IpAddr, lookup: Option<&Arc<dyn CountryLookup>>) -> GeoMatch {
        let Some(lookup) = lookup else {
            return GeoMatch::Unavailable;
        };

        let Some(country_info) = lookup.country_info(ip) else {
            // A provider that exists but cannot answer this address is still an
            // *answer*: the address is not in the location. Reporting
            // `Unavailable` here would make every uncovered address look like a
            // misconfiguration and turn one bad address into a fail-closed
            // block.
            return GeoMatch::No;
        };

        if !country_info.code.eq_ignore_ascii_case(&self.country) {
            return GeoMatch::No;
        }

        if let Some(ref region) = self.region {
            match country_info.subdivision.as_deref() {
                Some(subdivision) if subdivision.eq_ignore_ascii_case(region) => {}
                _ => return GeoMatch::No,
            }
        }

        if let Some(ref city) = self.city {
            match country_info.city.as_deref() {
                Some(found) if found.eq_ignore_ascii_case(city) => {}
                _ => return GeoMatch::No,
            }
        }

        if let Some(asn) = self.asn {
            // A database that carries no ASN cannot satisfy an ASN-scoped rule.
            // That is an evaluated "no", not a misconfiguration.
            match lookup.asn(ip) {
                Some(found) if found == asn => {}
                _ => return GeoMatch::No,
            }
        }

        GeoMatch::Yes
    }

    /// Whether the address is in this location.
    ///
    /// Convenience wrapper for callers that do not care *why* a rule did not
    /// match. Prefer [`GeoLocation::matches_ip`] in the evaluation path, where
    /// collapsing `Unavailable` into `false` is the Phase 135 F-2 defect.
    pub fn contains(&self, ip: IpAddr, lookup: Option<&Arc<dyn CountryLookup>>) -> bool {
        self.matches_ip(ip, lookup) == GeoMatch::Yes
    }
}

impl RuleIndeterminate {
    /// Stable operator-facing wording. Kept as one place so the log line and
    /// the decision `reason` cannot drift apart.
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleIndeterminate::NoCountryLookup => "no country lookup is configured",
            RuleIndeterminate::UnparseableTarget => "the rule target could not be parsed",
        }
    }
}

/// Stable short name for an action, for decision reasons.
fn action_name(action: &DnsFirewallAction) -> &'static str {
    match action {
        DnsFirewallAction::Block => "block",
        DnsFirewallAction::Allow => "allow",
        DnsFirewallAction::Redirect { .. } => "redirect",
        DnsFirewallAction::Sinkhole => "sinkhole",
        DnsFirewallAction::RateLimit { .. } => "rate-limit",
        DnsFirewallAction::LogOnly => "log-only",
    }
}

#[derive(Debug, Clone)]
pub struct TimeWindow {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

impl TimeWindow {
    pub fn contains(&self, time: chrono::DateTime<chrono::Utc>) -> bool {
        time >= self.start && time <= self.end
    }
}

impl std::str::FromStr for GeoLocation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').map(|p| p.trim()).collect();
        if parts.is_empty() {
            return Err("Invalid geo location format".to_string());
        }

        let asn = if parts.len() > 3 {
            parts[3].parse::<u32>().ok()
        } else {
            None
        };

        // Phase 135 F-16: an empty field is a *placeholder*, not a value. The
        // ASN lives at index 3, so a country+ASN rule has to spell out indices
        // 1 and 2 — and those used to become `Some("")`, which then failed the
        // region and city comparisons against a provider that has neither. The
        // result was that an ASN-scoped rule could never match, however the
        // target was written.
        let optional = |index: usize| -> Option<String> {
            parts
                .get(index)
                .map(|part| part.trim())
                .filter(|part| !part.is_empty())
                .map(str::to_string)
        };

        Ok(GeoLocation {
            country: parts[0].to_string(),
            region: optional(1),
            city: optional(2),
            asn,
        })
    }
}

impl std::str::FromStr for TimeWindow {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').map(|p| p.trim()).collect();
        if parts.len() != 2 {
            return Err("Invalid time window format".to_string());
        }

        let start = chrono::DateTime::parse_from_rfc3339(parts[0])
            .map_err(|e| format!("Invalid start time: {}", e))?;
        let end = chrono::DateTime::parse_from_rfc3339(parts[1])
            .map_err(|e| format!("Invalid end time: {}", e))?;

        Ok(TimeWindow {
            start: start.into(),
            end: end.into(),
        })
    }
}

pub fn create_default_firewall_rules() -> Vec<DnsFirewallRule> {
    vec![
        DnsFirewallRule {
            id: "block_internal_ips".to_string(),
            rule_type: DnsFirewallRuleType::Subnet,
            action: DnsFirewallAction::Block,
            target: "10.0.0.0/8".to_string(),
            ttl: 300,
            created_at: unix_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "block_multicast".to_string(),
            rule_type: DnsFirewallRuleType::Subnet,
            action: DnsFirewallAction::Block,
            target: "224.0.0.0/4".to_string(),
            ttl: 300,
            created_at: unix_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "block_reserved_domains".to_string(),
            rule_type: DnsFirewallRuleType::Domain,
            action: DnsFirewallAction::Block,
            target: "localhost".to_string(),
            ttl: 300,
            created_at: unix_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "block_example_domains".to_string(),
            rule_type: DnsFirewallRuleType::Domain,
            action: DnsFirewallAction::Block,
            target: "example.com".to_string(),
            ttl: 300,
            created_at: unix_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "block_zone_transfer".to_string(),
            rule_type: DnsFirewallRuleType::QueryType,
            action: DnsFirewallAction::Block,
            target: "0xfc".to_string(), // AXFR query type (252)
            ttl: 300,
            created_at: unix_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "block_ixfr".to_string(),
            rule_type: DnsFirewallRuleType::QueryType,
            action: DnsFirewallAction::Block,
            target: "0xfb".to_string(), // IXFR query type (251)
            ttl: 300,
            created_at: unix_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
    ]
}

pub fn create_rate_limit_rules() -> Vec<DnsFirewallRule> {
    vec![
        DnsFirewallRule {
            id: "rate_limit_per_domain".to_string(),
            rule_type: DnsFirewallRuleType::Domain,
            action: DnsFirewallAction::RateLimit {
                limit: 100,
                window: Duration::from_secs(60),
            },
            target: "*".to_string(), // All domains
            ttl: 60,
            created_at: unix_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "rate_limit_per_ip".to_string(),
            rule_type: DnsFirewallRuleType::IpAddress,
            action: DnsFirewallAction::RateLimit {
                limit: 500,
                window: Duration::from_secs(60),
            },
            target: "*".to_string(), // All IPs
            ttl: 60,
            created_at: unix_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
    ]
}
