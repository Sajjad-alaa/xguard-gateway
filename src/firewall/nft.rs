//! Rendering a [`Policy`] as one nftables JSON transaction, and applying it.
//!
//! XGuard owns a single table, `inet xguard`. Every apply replaces that whole table in one
//! transaction (add, delete, re-create), so the kernel switches from the old ruleset to the new
//! one atomically and other tables on the host are never touched.
//!
//! Layout:
//!
//! ```text
//! table inet xguard
//!   set s<id>_v4 / s<id>_v6        interval sets with the policy's address ranges
//!   chain input   (filter hook)    iifname <wg> jump vpn
//!   chain forward (filter hook)    iifname <wg> jump vpn
//!   chain vpn                      ct established,related accept; ct invalid drop;
//!                                  rules in order; default action
//!   chain postrouting (nat hook)   SNAT bindings; masquerade
//! ```

use std::{
    io::Write,
    net::IpAddr,
    process::{Command, Stdio},
};

use serde_json::{Value, json};

use super::policy::{Action, AddressSet, Policy, Rule};

pub const TABLE: &str = "xguard";
const FAMILY: &str = "inet";
const POLICY_CHAIN: &str = "vpn";

/// What the table should contain.
pub struct Ruleset<'a> {
    pub interface: &'a str,
    /// Priority of the input/forward filter hooks.
    pub filter_priority: i32,
    pub policy: Option<&'a Policy>,
    pub masquerade: bool,
}

impl Ruleset<'_> {
    /// Whether the table has anything in it; if not, applying just removes it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.masquerade
            && self
                .policy
                .is_none_or(|p| p.default_action.is_none() && p.snat.is_empty())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn payload(self) -> &'static str {
        match self {
            Self::V4 => "ip",
            Self::V6 => "ip6",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }

    fn has(self, set: &AddressSet) -> bool {
        match self {
            Self::V4 => !set.v4.is_empty(),
            Self::V6 => !set.v6.is_empty(),
        }
    }
}

fn set_name(id: u32, family: Family) -> String {
    format!("s{id}_{}", family.suffix())
}

fn element<T: std::fmt::Display + PartialEq>(start: &T, end: &T) -> Value {
    if start == end {
        json!(start.to_string())
    } else {
        json!({ "range": [start.to_string(), end.to_string()] })
    }
}

fn add(object: Value) -> Value {
    json!({ "add": object })
}

fn chain(name: &str) -> Value {
    json!({ "chain": { "family": FAMILY, "table": TABLE, "name": name } })
}

fn base_chain(name: &str, kind: &str, hook: &str, priority: i32) -> Value {
    json!({ "chain": {
        "family": FAMILY, "table": TABLE, "name": name,
        "type": kind, "hook": hook, "prio": priority, "policy": "accept",
    } })
}

fn rule(chain: &str, comment: Option<String>, expr: Vec<Value>) -> Value {
    let mut rule = json!({ "family": FAMILY, "table": TABLE, "chain": chain, "expr": expr });
    if let Some(comment) = comment {
        rule["comment"] = json!(comment);
    }
    json!({ "rule": rule })
}

fn matches(left: Value, op: &str, right: Value) -> Value {
    json!({ "match": { "op": op, "left": left, "right": right } })
}

fn meta(key: &str) -> Value {
    json!({ "meta": { "key": key } })
}

fn payload(protocol: &str, field: &str) -> Value {
    json!({ "payload": { "protocol": protocol, "field": field } })
}

fn verdict(action: Action) -> Value {
    match action {
        Action::Accept => json!({ "accept": null }),
        Action::Drop => json!({ "drop": null }),
        Action::Reject => json!({ "reject": null }),
    }
}

/// One value or an anonymous set of values.
fn one_or_set(mut values: Vec<Value>) -> Value {
    if values.len() == 1 {
        values.remove(0)
    } else {
        json!({ "set": values })
    }
}

fn sets(policy: &Policy) -> Vec<Value> {
    let used = policy.referenced_sets();
    let mut out = Vec::new();
    for (id, set) in policy.sets.iter().filter(|(id, _)| used.contains(id)) {
        let families = [
            (
                Family::V4,
                "ipv4_addr",
                set.v4
                    .iter()
                    .map(|r| element(r.start(), r.end()))
                    .collect::<Vec<_>>(),
            ),
            (
                Family::V6,
                "ipv6_addr",
                set.v6.iter().map(|r| element(r.start(), r.end())).collect(),
            ),
        ];
        for (family, kind, elements) in families {
            if elements.is_empty() {
                continue;
            }
            out.push(add(json!({ "set": {
                "family": FAMILY, "table": TABLE, "name": set_name(*id, family),
                "type": kind, "flags": ["interval"], "elem": elements,
            } })));
        }
    }
    out
}

/// The nft rules for one policy rule: one per address family it can match, or a single
/// family-agnostic rule when it names no addresses at all.
fn policy_rules(policy: &Policy, rule: &Rule) -> Vec<Value> {
    let lookup = |id: Option<u32>| id.map(|id| &policy.sets[&id]);
    let (source, destination) = (lookup(rule.source), lookup(rule.destination));

    let mut tail = Vec::new();
    if !rule.protocols.is_empty() {
        let protocols = rule.protocols.iter().map(|p| json!(p)).collect();
        tail.push(matches(meta("l4proto"), "==", one_or_set(protocols)));
    }
    if !rule.ports.is_empty() {
        let ports = rule
            .ports
            .iter()
            .map(|r| {
                if r.start() == r.end() {
                    json!(r.start())
                } else {
                    json!({ "range": [r.start(), r.end()] })
                }
            })
            .collect();
        tail.push(matches(payload("th", "dport"), "==", one_or_set(ports)));
    }
    tail.push(json!({ "counter": null }));
    tail.push(verdict(rule.action));
    let comment = Some(format!("xguard rule {}", rule.id));

    if source.is_none() && destination.is_none() {
        return vec![self::rule(POLICY_CHAIN, comment, tail)];
    }

    let mut out = Vec::new();
    for family in [Family::V4, Family::V6] {
        // A rule naming a set with no addresses of this family can't match it.
        if source.is_some_and(|s| !family.has(s)) || destination.is_some_and(|d| !family.has(d)) {
            continue;
        }
        let mut expr = Vec::new();
        if let Some(id) = rule.source {
            expr.push(matches(
                payload(family.payload(), "saddr"),
                "==",
                json!(format!("@{}", set_name(id, family))),
            ));
        }
        if let Some(id) = rule.destination {
            expr.push(matches(
                payload(family.payload(), "daddr"),
                "==",
                json!(format!("@{}", set_name(id, family))),
            ));
        }
        expr.extend(tail.iter().cloned());
        out.push(self::rule(POLICY_CHAIN, comment.clone(), expr));
    }
    out
}

/// Renders the full transaction for `ruleset`.
#[must_use]
pub fn render(ruleset: &Ruleset) -> Value {
    let table = json!({ "table": { "family": FAMILY, "name": TABLE } });
    // `add` then `delete` removes the table whether or not it existed.
    let mut commands = vec![
        json!({ "metainfo": { "json_schema_version": 1 } }),
        add(table.clone()),
        json!({ "delete": table.clone() }),
    ];
    if ruleset.is_empty() {
        return json!({ "nftables": commands });
    }
    commands.push(add(table));

    let iif = || matches(meta("iifname"), "==", json!(ruleset.interface));
    let policy = ruleset.policy;

    if let Some((policy, default)) = policy.and_then(|p| p.default_action.map(|d| (p, d))) {
        commands.extend(sets(policy));
        commands.push(add(chain(POLICY_CHAIN)));
        let state = json!({ "ct": { "key": "state" } });
        commands.push(add(rule(
            POLICY_CHAIN,
            None,
            vec![
                matches(state.clone(), "in", json!(["established", "related"])),
                json!({ "accept": null }),
            ],
        )));
        commands.push(add(rule(
            POLICY_CHAIN,
            None,
            vec![
                matches(state, "in", json!("invalid")),
                json!({ "drop": null }),
            ],
        )));
        for rule in &policy.rules {
            commands.extend(policy_rules(policy, rule).into_iter().map(add));
        }
        commands.push(add(rule(
            POLICY_CHAIN,
            Some("xguard default".into()),
            vec![json!({ "counter": null }), verdict(default)],
        )));

        for hook in ["input", "forward"] {
            commands.push(add(base_chain(
                hook,
                "filter",
                hook,
                ruleset.filter_priority,
            )));
            commands.push(add(rule(
                hook,
                None,
                vec![iif(), json!({ "jump": { "target": POLICY_CHAIN } })],
            )));
        }
    } else if let Some(policy) = policy {
        // NAT only: SNAT bindings still need their sets.
        commands.extend(sets(policy));
    }

    let snat = policy.map(|p| p.snat.as_slice()).unwrap_or_default();
    if !snat.is_empty() || ruleset.masquerade {
        commands.push(add(base_chain("postrouting", "nat", "postrouting", 100)));
        for binding in snat {
            let family = match binding.to {
                IpAddr::V4(_) => Family::V4,
                IpAddr::V6(_) => Family::V6,
            };
            // Only addresses of the target's family can be rewritten to it.
            let set = &policy.expect("SNAT bindings come from a policy").sets[&binding.source];
            if !family.has(set) {
                continue;
            }
            commands.push(add(rule(
                "postrouting",
                Some(format!("xguard snat {}", binding.source)),
                vec![
                    iif(),
                    matches(
                        payload(family.payload(), "saddr"),
                        "==",
                        json!(format!("@{}", set_name(binding.source, family))),
                    ),
                    json!({ "snat": { "family": family.payload(), "addr": binding.to.to_string() } }),
                ],
            )));
        }
        if ruleset.masquerade {
            commands.push(add(rule(
                "postrouting",
                Some("xguard masquerade".into()),
                vec![
                    iif(),
                    matches(meta("oifname"), "!=", json!(ruleset.interface)),
                    json!({ "masquerade": null }),
                ],
            )));
        }
    }

    json!({ "nftables": commands })
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("failed to run nft: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("nft rejected the ruleset: {0}")]
    Rejected(String),
}

/// Applies a rendered transaction with `nft -j -f -`. The kernel either takes all of it or
/// none of it, so a failure leaves the previous ruleset in place.
pub fn apply(program: &str, transaction: &Value) -> Result<(), ApplyError> {
    let mut child = Command::new(program)
        .args(["-j", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    // Dropping stdin at the end of this scope closes it, so nft sees EOF.
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(transaction.to_string().as_bytes())?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(ApplyError::Rejected(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}
