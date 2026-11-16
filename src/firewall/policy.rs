//! Validation of the policy Core sends into types the renderer can trust.
//!
//! Nothing from the wire reaches the packet filter unchecked: addresses are
//! decoded from fixed-size byte strings, ports and protocols are range-checked,
//! references are resolved, and sizes are capped so a bad policy cannot exhaust
//! the gateway.

use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use crate::proto::gateway::{
    FirewallAction, FirewallPolicy, FirewallRule, IpRange, PortRange, SnatBinding,
};

/// Upper bounds on what one policy may contain.
pub const MAX_RULES: usize = 10_000;
pub const MAX_SETS: usize = 10_000;
pub const MAX_RANGES: usize = 500_000;
pub const MAX_SNAT_BINDINGS: usize = 10_000;

const TCP: u8 = 6;
const UDP: u8 = 17;
const SCTP: u8 = 132;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("policy has too many {what} ({count} > {max})")]
    TooLarge {
        what: &'static str,
        count: usize,
        max: usize,
    },
    #[error("address set {0} is defined twice")]
    DuplicateSet(u32),
    #[error("{0} refers to address set {1}, which is not defined")]
    UnknownSet(String, u32),
    #[error("address set {set}: {reason}")]
    BadRange { set: u32, reason: &'static str },
    #[error("rule {0}: action is not set")]
    MissingAction(u64),
    #[error("rule {0}: protocol {1} is out of range")]
    BadProtocol(u64, u32),
    #[error("rule {0}: port range {1}-{2} is invalid")]
    BadPorts(u64, u32, u32),
    #[error("rule {0}: ports need TCP, UDP or SCTP, not protocol {1}")]
    PortsWithoutTransport(u64, u8),
    #[error("filtering is off (no default action) but the policy has rules")]
    RulesWithoutFilter,
    #[error("SNAT binding for set {0}: address must be 4 or 16 bytes")]
    BadSnatAddress(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
    Reject,
}

/// Sorted, non-overlapping, non-adjacent address ranges per family.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressSet {
    pub v4: Vec<RangeInclusive<Ipv4Addr>>,
    pub v6: Vec<RangeInclusive<Ipv6Addr>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub id: u64,
    pub action: Action,
    pub source: Option<u32>,
    pub destination: Option<u32>,
    /// Sorted and deduplicated; empty means any protocol.
    pub protocols: Vec<u8>,
    /// Sorted and merged; empty means any port.
    pub ports: Vec<RangeInclusive<u16>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snat {
    pub source: u32,
    pub to: IpAddr,
}

/// A policy that passed validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub revision: String,
    /// `None` means packet filtering is off and only NAT applies.
    pub default_action: Option<Action>,
    pub sets: BTreeMap<u32, AddressSet>,
    pub rules: Vec<Rule>,
    pub snat: Vec<Snat>,
}

fn cap(what: &'static str, count: usize, max: usize) -> Result<(), PolicyError> {
    if count > max {
        Err(PolicyError::TooLarge { what, count, max })
    } else {
        Ok(())
    }
}

fn action(value: i32) -> Option<Action> {
    match FirewallAction::try_from(value) {
        Ok(FirewallAction::Accept) => Some(Action::Accept),
        Ok(FirewallAction::Drop) => Some(Action::Drop),
        Ok(FirewallAction::Reject) => Some(Action::Reject),
        Ok(FirewallAction::Unspecified) | Err(_) => None,
    }
}

impl TryFrom<FirewallPolicy> for Policy {
    type Error = PolicyError;

    fn try_from(policy: FirewallPolicy) -> Result<Self, Self::Error> {
        cap("rules", policy.rules.len(), MAX_RULES)?;
        cap("address sets", policy.address_sets.len(), MAX_SETS)?;
        cap(
            "SNAT bindings",
            policy.snat_bindings.len(),
            MAX_SNAT_BINDINGS,
        )?;
        let range_count = policy.address_sets.iter().map(|s| s.ranges.len()).sum();
        cap("address ranges", range_count, MAX_RANGES)?;

        let mut sets = BTreeMap::new();
        for set in policy.address_sets {
            let parsed = parse_set(set.id, &set.ranges)?;
            if sets.insert(set.id, parsed).is_some() {
                return Err(PolicyError::DuplicateSet(set.id));
            }
        }

        let default_action = action(policy.default_action);
        if default_action.is_none() && !policy.rules.is_empty() {
            return Err(PolicyError::RulesWithoutFilter);
        }

        let rules = policy
            .rules
            .into_iter()
            .map(|rule| parse_rule(rule, &sets))
            .collect::<Result<Vec<_>, _>>()?;
        let snat = policy
            .snat_bindings
            .into_iter()
            .map(|binding| parse_snat(binding, &sets))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            revision: policy.revision,
            default_action,
            sets,
            rules,
            snat,
        })
    }
}

fn parse_set(id: u32, ranges: &[IpRange]) -> Result<AddressSet, PolicyError> {
    let bad = |reason| PolicyError::BadRange { set: id, reason };
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for range in ranges {
        match (range.start.len(), range.end.len()) {
            (4, 4) => {
                let start = Ipv4Addr::from(<[u8; 4]>::try_from(&range.start[..]).unwrap());
                let end = Ipv4Addr::from(<[u8; 4]>::try_from(&range.end[..]).unwrap());
                if start > end {
                    return Err(bad("range start is after its end"));
                }
                v4.push(start..=end);
            }
            (16, 16) => {
                let start = Ipv6Addr::from(<[u8; 16]>::try_from(&range.start[..]).unwrap());
                let end = Ipv6Addr::from(<[u8; 16]>::try_from(&range.end[..]).unwrap());
                if start > end {
                    return Err(bad("range start is after its end"));
                }
                v6.push(start..=end);
            }
            _ => return Err(bad("addresses must both be 4 or both be 16 bytes")),
        }
    }
    Ok(AddressSet {
        v4: merge(v4, |a| u32::from(a).checked_add(1).map(Ipv4Addr::from)),
        v6: merge(v6, |a| u128::from(a).checked_add(1).map(Ipv6Addr::from)),
    })
}

/// Sorts ranges and joins overlapping or adjacent ones. `next` returns the value after `x`, or
/// `None` at the top of the domain.
fn merge<T: Ord + Copy>(
    mut ranges: Vec<RangeInclusive<T>>,
    next: impl Fn(T) -> Option<T>,
) -> Vec<RangeInclusive<T>> {
    ranges.sort_unstable_by_key(|r| (*r.start(), *r.end()));
    let mut merged: Vec<RangeInclusive<T>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(last) = merged.last_mut() {
            let touches = match next(*last.end()) {
                Some(after_last) => *range.start() <= after_last,
                None => true, // `last` already reaches the top of the domain
            };
            if touches {
                if range.end() > last.end() {
                    *last = *last.start()..=*range.end();
                }
                continue;
            }
        }
        merged.push(range);
    }
    merged
}

fn check_set(
    owner: impl Fn() -> String,
    id: Option<u32>,
    sets: &BTreeMap<u32, AddressSet>,
) -> Result<(), PolicyError> {
    match id {
        Some(id) if !sets.contains_key(&id) => Err(PolicyError::UnknownSet(owner(), id)),
        _ => Ok(()),
    }
}

fn parse_rule(rule: FirewallRule, sets: &BTreeMap<u32, AddressSet>) -> Result<Rule, PolicyError> {
    let id = rule.id;
    let action = action(rule.action).ok_or(PolicyError::MissingAction(id))?;
    check_set(|| format!("rule {id}"), rule.source_set, sets)?;
    check_set(|| format!("rule {id}"), rule.destination_set, sets)?;

    let mut protocols = rule
        .protocols
        .iter()
        .map(|&p| u8::try_from(p).map_err(|_| PolicyError::BadProtocol(id, p)))
        .collect::<Result<Vec<_>, _>>()?;
    protocols.sort_unstable();
    protocols.dedup();

    let ports = rule
        .destination_ports
        .iter()
        .map(
            |&PortRange { start, end }| match (u16::try_from(start), u16::try_from(end)) {
                (Ok(s), Ok(e)) if s >= 1 && s <= e => Ok(s..=e),
                _ => Err(PolicyError::BadPorts(id, start, end)),
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    let ports = merge(ports, |p| p.checked_add(1));

    if !ports.is_empty() {
        if protocols.is_empty() {
            // Ports imply a transport protocol; the common meaning is TCP and UDP.
            protocols = vec![TCP, UDP];
        } else if let Some(&other) = protocols.iter().find(|p| ![TCP, UDP, SCTP].contains(p)) {
            return Err(PolicyError::PortsWithoutTransport(id, other));
        }
    }

    Ok(Rule {
        id,
        action,
        source: rule.source_set,
        destination: rule.destination_set,
        protocols,
        ports,
    })
}

fn parse_snat(binding: SnatBinding, sets: &BTreeMap<u32, AddressSet>) -> Result<Snat, PolicyError> {
    let set = binding.source_set;
    check_set(|| format!("SNAT binding for set {set}"), Some(set), sets)?;
    let to = match binding.to_address.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(&binding.to_address[..]).unwrap()),
        16 => IpAddr::from(<[u8; 16]>::try_from(&binding.to_address[..]).unwrap()),
        _ => return Err(PolicyError::BadSnatAddress(set)),
    };
    Ok(Snat { source: set, to })
}

impl Policy {
    /// Address sets used by a rule or SNAT binding. Sets nothing refers to are not rendered.
    #[must_use]
    pub fn referenced_sets(&self) -> HashSet<u32> {
        self.rules
            .iter()
            .flat_map(|r| [r.source, r.destination])
            .flatten()
            .chain(self.snat.iter().map(|s| s.source))
            .collect()
    }
}
