use std::{
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    process::{Command, Stdio},
};

use serde_json::Value;

use super::{
    nft::{self, Ruleset},
    policy::{AddressSet, Policy, PolicyError},
};
use crate::proto::gateway::{
    AddressSet as ProtoSet, FirewallAction, FirewallPolicy, FirewallRule, IpRange, PortRange,
    SnatBinding,
};

fn v4(a: [u8; 4], b: [u8; 4]) -> IpRange {
    IpRange {
        start: a.to_vec(),
        end: b.to_vec(),
    }
}

fn one4(a: [u8; 4]) -> IpRange {
    v4(a, a)
}

fn set(id: u32, ranges: Vec<IpRange>) -> ProtoSet {
    ProtoSet { id, ranges }
}

fn allow(id: u64, source: Option<u32>, destination: Option<u32>) -> FirewallRule {
    FirewallRule {
        id,
        action: FirewallAction::Accept.into(),
        source_set: source,
        destination_set: destination,
        ..FirewallRule::default()
    }
}

fn policy(rules: Vec<FirewallRule>, sets: Vec<ProtoSet>) -> FirewallPolicy {
    FirewallPolicy {
        revision: "r1".into(),
        default_action: FirewallAction::Drop.into(),
        address_sets: sets,
        rules,
        snat_bindings: Vec::new(),
    }
}

// --- validation ---

#[test]
fn merges_overlapping_and_adjacent_ranges() {
    let parsed = Policy::try_from(policy(
        vec![allow(1, Some(1), None)],
        vec![set(
            1,
            vec![
                one4([10, 0, 0, 9]),
                v4([10, 0, 0, 1], [10, 0, 0, 5]),
                v4([10, 0, 0, 4], [10, 0, 0, 7]),
                one4([10, 0, 0, 8]), // adjacent to 1-7 and to 9
                one4([10, 0, 1, 0]),
            ],
        )],
    ))
    .unwrap();
    assert_eq!(
        parsed.sets[&1],
        AddressSet {
            v4: vec![
                Ipv4Addr::new(10, 0, 0, 1)..=Ipv4Addr::new(10, 0, 0, 9),
                Ipv4Addr::new(10, 0, 1, 0)..=Ipv4Addr::new(10, 0, 1, 0),
            ],
            v6: Vec::new(),
        }
    );
}

#[test]
fn merge_handles_top_of_address_space() {
    let parsed = Policy::try_from(policy(
        vec![allow(1, Some(1), None)],
        vec![set(
            1,
            vec![
                v4([255, 255, 255, 0], [255, 255, 255, 255]),
                one4([255, 255, 255, 255]),
            ],
        )],
    ))
    .unwrap();
    assert_eq!(parsed.sets[&1].v4.len(), 1);
}

#[test]
fn rejects_malformed_input() {
    let cases: Vec<(FirewallPolicy, PolicyError)> = vec![
        (
            policy(vec![], vec![set(1, vec![v4([10, 0, 0, 5], [10, 0, 0, 1])])]),
            PolicyError::BadRange {
                set: 1,
                reason: "range start is after its end",
            },
        ),
        (
            policy(
                vec![],
                vec![set(
                    1,
                    vec![IpRange {
                        start: vec![10, 0, 0],
                        end: vec![10, 0, 0, 1],
                    }],
                )],
            ),
            PolicyError::BadRange {
                set: 1,
                reason: "addresses must both be 4 or both be 16 bytes",
            },
        ),
        (
            policy(vec![], vec![set(1, vec![]), set(1, vec![])]),
            PolicyError::DuplicateSet(1),
        ),
        (
            policy(vec![allow(7, Some(3), None)], vec![]),
            PolicyError::UnknownSet("rule 7".into(), 3),
        ),
        (
            policy(
                vec![FirewallRule {
                    id: 2,
                    ..FirewallRule::default()
                }],
                vec![],
            ),
            PolicyError::MissingAction(2),
        ),
        (
            policy(
                vec![FirewallRule {
                    protocols: vec![300],
                    ..allow(3, None, None)
                }],
                vec![],
            ),
            PolicyError::BadProtocol(3, 300),
        ),
        (
            policy(
                vec![FirewallRule {
                    destination_ports: vec![PortRange { start: 0, end: 80 }],
                    ..allow(4, None, None)
                }],
                vec![],
            ),
            PolicyError::BadPorts(4, 0, 80),
        ),
        (
            policy(
                vec![FirewallRule {
                    destination_ports: vec![PortRange { start: 90, end: 80 }],
                    ..allow(5, None, None)
                }],
                vec![],
            ),
            PolicyError::BadPorts(5, 90, 80),
        ),
        (
            policy(
                vec![FirewallRule {
                    protocols: vec![1], // ICMP has no ports
                    destination_ports: vec![PortRange { start: 1, end: 1 }],
                    ..allow(6, None, None)
                }],
                vec![],
            ),
            PolicyError::PortsWithoutTransport(6, 1),
        ),
        (
            FirewallPolicy {
                default_action: FirewallAction::Unspecified.into(),
                ..policy(vec![allow(1, None, None)], vec![])
            },
            PolicyError::RulesWithoutFilter,
        ),
        (
            FirewallPolicy {
                snat_bindings: vec![SnatBinding {
                    source_set: 1,
                    to_address: vec![1, 2, 3],
                }],
                ..policy(vec![], vec![set(1, vec![])])
            },
            PolicyError::BadSnatAddress(1),
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(Policy::try_from(input).unwrap_err(), expected);
    }
}

#[test]
fn caps_policy_size() {
    let rules = (0..=super::policy::MAX_RULES as u64)
        .map(|id| allow(id, None, None))
        .collect();
    assert!(matches!(
        Policy::try_from(policy(rules, vec![])),
        Err(PolicyError::TooLarge { what: "rules", .. })
    ));
}

#[test]
fn ports_default_to_tcp_and_udp() {
    let parsed = Policy::try_from(policy(
        vec![FirewallRule {
            destination_ports: vec![
                PortRange {
                    start: 443,
                    end: 443,
                },
                PortRange { start: 80, end: 81 },
                PortRange { start: 82, end: 90 },
            ],
            ..allow(1, None, None)
        }],
        vec![],
    ))
    .unwrap();
    assert_eq!(parsed.rules[0].protocols, [6, 17]);
    assert_eq!(parsed.rules[0].ports, [80..=90, 443..=443]);
}

// --- rendering ---

fn ruleset(policy: Option<&Policy>, masquerade: bool) -> Value {
    nft::render(&Ruleset {
        interface: "wg0",
        filter_priority: 0,
        policy,
        masquerade,
    })
}

fn commands(rendered: &Value) -> &Vec<Value> {
    rendered["nftables"].as_array().unwrap()
}

#[test]
fn empty_ruleset_only_removes_the_table() {
    let rendered = ruleset(None, false);
    let kinds: Vec<_> = commands(&rendered)
        .iter()
        .map(|c| c.as_object().unwrap().keys().next().unwrap().clone())
        .collect();
    assert_eq!(kinds, ["metainfo", "add", "delete"]);
}

#[test]
fn rules_split_by_family_and_skip_impossible_ones() {
    let parsed = Policy::try_from(policy(
        vec![
            allow(1, Some(1), Some(2)), // v4 sources, mixed destinations: v4 only
            allow(2, Some(1), Some(3)), // v4 sources, v6-only destinations: never matches
            allow(3, None, None),       // no addresses: one family-agnostic rule
        ],
        vec![
            set(1, vec![one4([10, 0, 0, 2])]),
            set(
                2,
                vec![
                    one4([192, 168, 1, 1]),
                    IpRange {
                        start: Ipv6Addr::LOCALHOST.octets().to_vec(),
                        end: Ipv6Addr::LOCALHOST.octets().to_vec(),
                    },
                ],
            ),
            set(
                3,
                vec![IpRange {
                    start: Ipv6Addr::LOCALHOST.octets().to_vec(),
                    end: Ipv6Addr::LOCALHOST.octets().to_vec(),
                }],
            ),
        ],
    ))
    .unwrap();
    let rendered = ruleset(Some(&parsed), false);
    let comments: Vec<_> = commands(&rendered)
        .iter()
        .filter_map(|c| c["add"]["rule"]["comment"].as_str())
        .collect();
    assert_eq!(
        comments,
        ["xguard rule 1", "xguard rule 3", "xguard default"]
    );
}

// --- kernel checks: load the ruleset into a throwaway network namespace ---

/// Applies `transaction` in a new network namespace and returns `nft list ruleset` from it.
/// Returns `None` when namespaces or nft are unavailable (not root, no nftables).
fn load_in_netns(transaction: &Value) -> Option<String> {
    let mut child = Command::new("unshare")
        .args(["--net", "sh", "-c", "nft -j -f - && nft list ruleset"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(transaction.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("Operation not permitted") || stderr.contains("not found") {
        eprintln!("skipping kernel check: {stderr}");
        return None;
    }
    assert!(
        output.status.success(),
        "nft rejected the ruleset: {stderr}"
    );
    Some(String::from_utf8(output.stdout).unwrap())
}

#[test]
fn kernel_accepts_full_ruleset() {
    let parsed = Policy::try_from(FirewallPolicy {
        snat_bindings: vec![SnatBinding {
            source_set: 1,
            to_address: vec![203, 0, 113, 7],
        }],
        ..policy(
            vec![
                FirewallRule {
                    action: FirewallAction::Reject.into(),
                    protocols: vec![6],
                    destination_ports: vec![PortRange { start: 22, end: 22 }],
                    ..allow(1, Some(1), Some(2))
                },
                FirewallRule {
                    destination_ports: vec![
                        PortRange { start: 80, end: 80 },
                        PortRange {
                            start: 8000,
                            end: 8080,
                        },
                    ],
                    ..allow(2, Some(1), Some(2))
                },
                FirewallRule {
                    protocols: vec![1, 58],
                    ..allow(3, None, Some(2))
                },
                FirewallRule {
                    action: FirewallAction::Drop.into(),
                    ..allow(4, None, None)
                },
            ],
            vec![
                set(
                    1,
                    vec![v4([10, 6, 0, 2], [10, 6, 0, 40]), one4([10, 6, 0, 99])],
                ),
                set(
                    2,
                    vec![
                        v4([192, 168, 0, 0], [192, 168, 255, 255]),
                        IpRange {
                            start: "fd00::1".parse::<Ipv6Addr>().unwrap().octets().to_vec(),
                            end: "fd00::ff".parse::<Ipv6Addr>().unwrap().octets().to_vec(),
                        },
                    ],
                ),
            ],
        )
    })
    .unwrap();
    let Some(listing) = load_in_netns(&ruleset(Some(&parsed), true)) else {
        return;
    };
    for expected in [
        "table inet xguard",
        "set s1_v4",
        "10.6.0.2-10.6.0.40",
        "set s2_v6",
        "chain vpn",
        "ct state established,related accept",
        "ct state invalid drop",
        "ip saddr @s1_v4 ip daddr @s2_v4 tcp dport 22 counter packets 0 bytes 0 reject",
        "elements = { 192.168.0.0/16 }",
        "elements = { fd00::1-fd00::ff }",
        "meta l4proto { tcp, udp } th dport { 80, 8000-8080 } counter packets 0 bytes 0 accept",
        "ip6 daddr @s2_v6 meta l4proto { icmp, ipv6-icmp }",
        "counter packets 0 bytes 0 drop comment \"xguard rule 4\"",
        "meta l4proto { icmp, ipv6-icmp }",
        "comment \"xguard default\"",
        "iifname \"wg0\" jump vpn",
        "snat ip to 203.0.113.7",
        "iifname \"wg0\" oifname != \"wg0\" masquerade",
    ] {
        assert!(
            listing.contains(expected),
            "missing `{expected}` in:\n{listing}"
        );
    }
}

#[test]
fn kernel_accepts_masquerade_only_and_removal() {
    if let Some(listing) = load_in_netns(&ruleset(None, true)) {
        assert!(listing.contains("masquerade"), "{listing}");
        assert!(!listing.contains("chain vpn"), "{listing}");
    }
    if let Some(listing) = load_in_netns(&ruleset(None, false)) {
        assert!(!listing.contains("xguard"), "{listing}");
    }
}
