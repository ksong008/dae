use std::collections::HashMap;
use std::fs;
use std::hint::black_box;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use criterion::{Criterion, criterion_group, criterion_main};
use dae_domain_matcher::{
    DnsRequestAction, DnsRequestCondition, DnsRequestMatcher, DnsRequestRule, DnsResponseAction,
    DnsResponseCondition, DnsResponseMatcher, DnsResponseRule, DnsRouting, DomainMatchScratch,
    DomainPatternKind, DomainPatternSet, IpPrefix, IpPrefixSet, UserspaceRoutingAction,
    UserspaceRoutingCondition, UserspaceRoutingInput, UserspaceRoutingMatcher,
    UserspaceRoutingRule, UserspaceRoutingSetKind, match_userspace_routing_rules,
};
use serde::Deserialize;
use smallvec::SmallVec;

#[derive(Deserialize)]
struct ActionFixture {
    kind: String,
    value: Option<u8>,
    outbound: Option<u8>,
    mark: Option<u32>,
    must: Option<bool>,
}

#[derive(Deserialize)]
struct RequestConditionFixture {
    kind: String,
    bit_index: Option<usize>,
    values: Option<Vec<u16>>,
    not: Option<bool>,
}

#[derive(Deserialize)]
struct RequestRuleFixture {
    conditions: Vec<RequestConditionFixture>,
    action: ActionFixture,
}

#[derive(Deserialize)]
struct RequestCaseFixture {
    name: String,
    qname: String,
    qtype: u16,
    expected: ActionFixture,
}

#[derive(Deserialize)]
struct RequestFixture {
    domain_hits: HashMap<String, Vec<u32>>,
    rules: Vec<RequestRuleFixture>,
    cases: Vec<RequestCaseFixture>,
}

#[derive(Deserialize)]
struct ResponseConditionFixture {
    kind: String,
    bit_index: Option<usize>,
    values: Option<Vec<u16>>,
    set_index: Option<usize>,
    not: Option<bool>,
}

#[derive(Deserialize)]
struct ResponseRuleFixture {
    conditions: Vec<ResponseConditionFixture>,
    action: ActionFixture,
}

#[derive(Deserialize)]
struct ResponseCaseFixture {
    name: String,
    qname: String,
    qtype: u16,
    ips: Vec<String>,
    request_upstream: i16,
    expected: ActionFixture,
}

#[derive(Deserialize)]
struct ResponseFixture {
    domain_hits: HashMap<String, Vec<u32>>,
    ip_sets: Vec<Vec<String>>,
    rules: Vec<ResponseRuleFixture>,
    cases: Vec<ResponseCaseFixture>,
}

#[derive(Deserialize)]
struct RoutingSetsFixture {
    dest_ip: Vec<Vec<String>>,
    source_ip: Vec<Vec<String>>,
    mac: Vec<Vec<String>>,
}

#[derive(Deserialize)]
struct RoutingConditionFixture {
    kind: String,
    bit_index: Option<usize>,
    set_kind: Option<String>,
    set_index: Option<usize>,
    ranges: Option<Vec<[u16; 2]>>,
    values: Option<Vec<u8>>,
    mask: Option<u8>,
    names: Option<Vec<String>>,
    not: Option<bool>,
}

#[derive(Deserialize)]
struct RoutingRuleFixture {
    conditions: Vec<RoutingConditionFixture>,
    action: ActionFixture,
}

#[derive(Deserialize)]
struct RoutingExpectedFixture {
    outbound: u8,
    mark: u32,
    must: bool,
}

#[derive(Deserialize)]
struct RoutingCaseFixture {
    name: String,
    source_ip: String,
    dest_ip: String,
    source_port: u16,
    dest_port: u16,
    ip_version: u8,
    l4proto: u8,
    domain: String,
    process_name: String,
    dscp: u8,
    mac: String,
    expected: RoutingExpectedFixture,
}

#[derive(Deserialize)]
struct RoutingFixture {
    domain_hits: HashMap<String, Vec<u32>>,
    sets: RoutingSetsFixture,
    rules: Vec<RoutingRuleFixture>,
    cases: Vec<RoutingCaseFixture>,
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_dns_request(c);
    bench_dns_response(c);
    bench_userspace_routing(c);
}

fn bench_dns_request(c: &mut Criterion) {
    let fixture: RequestFixture = load_fixture("dns_request_semantics.json");
    let rules = fixture
        .rules
        .iter()
        .map(build_request_rule)
        .collect::<Vec<_>>();
    let domain_sets = fixture
        .domain_hits
        .keys()
        .map(|domain| DomainPatternSet {
            bit_index: 0,
            kind: DomainPatternKind::Full,
            patterns: vec![domain.clone()],
        })
        .collect::<Vec<_>>();
    let matcher = DnsRequestMatcher::build(32, &domain_sets, rules.clone())
        .expect("build dns request matcher");
    let routing = DnsRouting::new(
        DnsRequestMatcher::build(32, &domain_sets, rules)
            .expect("build dns routing request matcher"),
        DnsResponseMatcher::build(
            32,
            &domain_sets,
            Vec::new(),
            vec![DnsResponseRule {
                conditions: vec![DnsResponseCondition::Fallback],
                action: DnsResponseAction::Accept,
            }],
        )
        .expect("build dns response matcher for dns routing bench"),
    );
    let mut scratch = DomainMatchScratch::default();

    for case in &fixture.cases {
        let action = matcher
            .match_qname(&case.qname, case.qtype)
            .expect("match qname");
        assert_eq!(
            action,
            expected_request_action(&case.expected),
            "case {}",
            case.name
        );
    }

    c.bench_function("dns_request_matcher_shared_fixture", |b| {
        b.iter(|| {
            for case in &fixture.cases {
                let action = matcher
                    .match_qname(black_box(&case.qname), black_box(case.qtype))
                    .expect("match qname");
                black_box(action);
            }
        });
    });

    c.bench_function("dns_request_matcher_shared_fixture_reuse_scratch", |b| {
        b.iter(|| {
            for case in &fixture.cases {
                let action = matcher
                    .match_qname_with_scratch(
                        black_box(&case.qname),
                        black_box(case.qtype),
                        black_box(&mut scratch),
                    )
                    .expect("match qname with scratch");
                black_box(action);
            }
        });
    });

    c.bench_function("dns_routing_plan_request_shared_fixture", |b| {
        b.iter(|| {
            for case in &fixture.cases {
                let plan = routing
                    .plan_request(black_box(&case.qname), black_box(case.qtype), black_box(28))
                    .expect("plan request");
                black_box(plan);
            }
        });
    });
}

fn bench_dns_response(c: &mut Criterion) {
    let fixture: ResponseFixture = load_fixture("dns_response_semantics.json");
    let rules = fixture
        .rules
        .iter()
        .map(build_response_rule)
        .collect::<Vec<_>>();
    let domain_sets = fixture
        .domain_hits
        .keys()
        .map(|domain| DomainPatternSet {
            bit_index: 0,
            kind: DomainPatternKind::Full,
            patterns: vec![domain.clone()],
        })
        .collect::<Vec<_>>();
    let ip_sets = fixture
        .ip_sets
        .iter()
        .map(|set| {
            IpPrefixSet::from_prefixes(set.iter().map(|prefix| parse_ip_prefix(prefix)).collect())
        })
        .collect::<Vec<_>>();
    let matcher = DnsResponseMatcher::build(32, &domain_sets, ip_sets.clone(), rules.clone())
        .expect("build dns response matcher");
    let routing = DnsRouting::new(
        DnsRequestMatcher::build(
            32,
            &[DomainPatternSet {
                bit_index: 0,
                kind: DomainPatternKind::Full,
                patterns: vec!["example.com".into()],
            }],
            vec![DnsRequestRule {
                conditions: vec![DnsRequestCondition::Fallback],
                action: DnsRequestAction::UserDefined(0),
            }],
        )
        .expect("build dns routing request matcher for response bench"),
        DnsResponseMatcher::build(32, &domain_sets, ip_sets, rules)
            .expect("build dns routing response matcher"),
    );
    let mut scratch = DomainMatchScratch::default();

    for case in &fixture.cases {
        let ips = case
            .ips
            .iter()
            .map(|ip| parse_ip_addr(ip))
            .collect::<Vec<_>>();
        let action = matcher
            .match_response(&case.qname, case.qtype, case.request_upstream, &ips, |_| {
                false
            })
            .expect("match response");
        assert_eq!(
            action,
            expected_response_action(&case.expected),
            "case {}",
            case.name
        );
    }

    c.bench_function("dns_response_matcher_shared_fixture", |b| {
        b.iter(|| {
            for case in &fixture.cases {
                let ips = case
                    .ips
                    .iter()
                    .map(|ip| parse_ip_addr(ip))
                    .collect::<Vec<_>>();
                let action = matcher
                    .match_response(
                        black_box(&case.qname),
                        black_box(case.qtype),
                        black_box(case.request_upstream),
                        black_box(ips.as_slice()),
                        |_| false,
                    )
                    .expect("match response");
                black_box(action);
            }
        });
    });

    c.bench_function("dns_response_matcher_shared_fixture_reuse_scratch", |b| {
        b.iter(|| {
            for case in &fixture.cases {
                let ips = case
                    .ips
                    .iter()
                    .map(|ip| parse_ip_addr(ip))
                    .collect::<Vec<_>>();
                let action = matcher
                    .match_response_with_scratch(
                        black_box(&case.qname),
                        black_box(case.qtype),
                        black_box(case.request_upstream),
                        black_box(ips.as_slice()),
                        black_box(&mut scratch),
                        |_| false,
                    )
                    .expect("match response with scratch");
                black_box(action);
            }
        });
    });

    c.bench_function("dns_routing_plan_response_shared_fixture", |b| {
        b.iter(|| {
            for case in &fixture.cases {
                let ips = case
                    .ips
                    .iter()
                    .map(|ip| parse_ip_addr(ip))
                    .collect::<Vec<_>>();
                let decision = routing
                    .plan_response(
                        black_box(&case.qname),
                        black_box(case.qtype),
                        black_box(case.request_upstream),
                        black_box(ips.as_slice()),
                    )
                    .expect("plan response");
                black_box(decision);
            }
        });
    });
}

fn bench_userspace_routing(c: &mut Criterion) {
    let fixture: RoutingFixture = load_fixture("routing_userspace_semantics.json");
    let rules = fixture
        .rules
        .iter()
        .map(build_routing_rule)
        .collect::<Vec<_>>();
    let matcher = UserspaceRoutingMatcher::build(
        32,
        &[DomainPatternSet {
            bit_index: 0,
            kind: DomainPatternKind::Full,
            patterns: vec!["example.com".into()],
        }],
        fixture
            .sets
            .dest_ip
            .iter()
            .map(|set| {
                IpPrefixSet::from_prefixes(
                    set.iter().map(|prefix| parse_ip_prefix(prefix)).collect(),
                )
            })
            .collect(),
        fixture
            .sets
            .source_ip
            .iter()
            .map(|set| {
                IpPrefixSet::from_prefixes(
                    set.iter().map(|prefix| parse_ip_prefix(prefix)).collect(),
                )
            })
            .collect(),
        fixture
            .sets
            .mac
            .iter()
            .map(|set| {
                IpPrefixSet::from_prefixes(
                    set.iter().map(|prefix| parse_ip_prefix(prefix)).collect(),
                )
            })
            .collect(),
        rules.clone(),
    )
    .expect("build userspace routing matcher");
    let mut scratch = DomainMatchScratch::default();

    for case in &fixture.cases {
        let domain_bitmap = fixture
            .domain_hits
            .get(case.domain.as_str())
            .map(Vec::as_slice);
        let input = UserspaceRoutingInput {
            domain_bitmap,
            source_port: case.source_port,
            dest_port: case.dest_port,
            ip_version: case.ip_version,
            l4proto: case.l4proto,
            process_name: process_name16(&case.process_name),
            dscp: case.dscp,
        };
        let matched = match_userspace_routing_rules(&rules, &input, |kind, set_index| match kind {
            UserspaceRoutingSetKind::DestIp => ip_set_matches(
                &fixture.sets.dest_ip[set_index],
                std::slice::from_ref(&case.dest_ip),
            ),
            UserspaceRoutingSetKind::SourceIp => ip_set_matches(
                &fixture.sets.source_ip[set_index],
                std::slice::from_ref(&case.source_ip),
            ),
            UserspaceRoutingSetKind::Mac => fixture.sets.mac[set_index]
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(&case.mac)),
        })
        .expect("match routing");
        assert_eq!(
            matched.outbound, case.expected.outbound,
            "case {}",
            case.name
        );
        assert_eq!(matched.mark, case.expected.mark, "case {}", case.name);
        assert_eq!(matched.must, case.expected.must, "case {}", case.name);
    }

    c.bench_function("userspace_routing_matcher_shared_fixture", |b| {
        b.iter(|| {
            for case in &fixture.cases {
                let domain_bitmap = fixture
                    .domain_hits
                    .get(case.domain.as_str())
                    .map(Vec::as_slice);
                let input = UserspaceRoutingInput {
                    domain_bitmap,
                    source_port: case.source_port,
                    dest_port: case.dest_port,
                    ip_version: case.ip_version,
                    l4proto: case.l4proto,
                    process_name: process_name16(&case.process_name),
                    dscp: case.dscp,
                };
                let matched =
                    match_userspace_routing_rules(&rules, black_box(&input), |kind, set_index| {
                        match kind {
                            UserspaceRoutingSetKind::DestIp => ip_set_matches(
                                &fixture.sets.dest_ip[set_index],
                                std::slice::from_ref(&case.dest_ip),
                            ),
                            UserspaceRoutingSetKind::SourceIp => ip_set_matches(
                                &fixture.sets.source_ip[set_index],
                                std::slice::from_ref(&case.source_ip),
                            ),
                            UserspaceRoutingSetKind::Mac => fixture.sets.mac[set_index]
                                .iter()
                                .any(|candidate| candidate.eq_ignore_ascii_case(&case.mac)),
                        }
                    })
                    .expect("match routing");
                black_box(matched);
            }
        });
    });

    c.bench_function(
        "userspace_routing_matcher_shared_fixture_reuse_scratch",
        |b| {
            b.iter(|| {
                for case in &fixture.cases {
                    let input = UserspaceRoutingInput {
                        domain_bitmap: None,
                        source_port: case.source_port,
                        dest_port: case.dest_port,
                        ip_version: case.ip_version,
                        l4proto: case.l4proto,
                        process_name: process_name16(&case.process_name),
                        dscp: case.dscp,
                    };
                    let matched = matcher
                        .match_input_with_scratch(
                            black_box(&input),
                            black_box(&case.domain),
                            black_box(parse_ip_addr(&case.dest_ip)),
                            black_box(parse_ip_addr(&case.source_ip)),
                            black_box(parse_mac16(&case.mac)),
                            black_box(&mut scratch),
                        )
                        .expect("match routing with scratch");
                    black_box(matched);
                }
            });
        },
    );
}

fn build_request_rule(rule: &RequestRuleFixture) -> DnsRequestRule {
    DnsRequestRule {
        conditions: rule
            .conditions
            .iter()
            .map(|condition| match condition.kind.as_str() {
                "domain_bit" => DnsRequestCondition::DomainBit {
                    bit_index: condition.bit_index.expect("domain_bit bit_index"),
                    not: condition.not.unwrap_or(false),
                },
                "qtype_any" => DnsRequestCondition::QTypeAny {
                    values: SmallVec::from_vec(condition.values.clone().expect("qtype_any values")),
                    not: condition.not.unwrap_or(false),
                },
                "fallback" => DnsRequestCondition::Fallback,
                other => panic!("unknown request condition kind: {other}"),
            })
            .collect(),
        action: expected_request_action(&rule.action),
    }
}

fn build_response_rule(rule: &ResponseRuleFixture) -> DnsResponseRule {
    DnsResponseRule {
        conditions: rule
            .conditions
            .iter()
            .map(|condition| match condition.kind.as_str() {
                "domain_bit" => DnsResponseCondition::DomainBit {
                    bit_index: condition.bit_index.expect("domain_bit bit_index"),
                    not: condition.not.unwrap_or(false),
                },
                "qtype_any" => DnsResponseCondition::QTypeAny {
                    values: SmallVec::from_vec(condition.values.clone().expect("qtype_any values")),
                    not: condition.not.unwrap_or(false),
                },
                "upstream_any" => DnsResponseCondition::UpstreamAny {
                    values: condition
                        .values
                        .as_ref()
                        .expect("upstream_any values")
                        .iter()
                        .map(|value| i16::try_from(*value).expect("upstream value fits in i16"))
                        .collect(),
                    not: condition.not.unwrap_or(false),
                },
                "ip_in_set" => DnsResponseCondition::AnyIpInSet {
                    set_index: condition.set_index.expect("ip_in_set set_index"),
                    not: condition.not.unwrap_or(false),
                },
                "fallback" => DnsResponseCondition::Fallback,
                other => panic!("unknown response condition kind: {other}"),
            })
            .collect(),
        action: expected_response_action(&rule.action),
    }
}

fn build_routing_rule(rule: &RoutingRuleFixture) -> UserspaceRoutingRule {
    UserspaceRoutingRule {
        conditions: rule
            .conditions
            .iter()
            .map(|condition| match condition.kind.as_str() {
                "domain_bit" => UserspaceRoutingCondition::DomainBit {
                    bit_index: condition.bit_index.expect("domain_bit bit_index"),
                    not: condition.not.unwrap_or(false),
                },
                "set_any" => UserspaceRoutingCondition::AnySet {
                    kind: match condition.set_kind.as_deref() {
                        Some("dest_ip") => UserspaceRoutingSetKind::DestIp,
                        Some("source_ip") => UserspaceRoutingSetKind::SourceIp,
                        Some("mac") => UserspaceRoutingSetKind::Mac,
                        other => panic!("unknown set kind: {other:?}"),
                    },
                    set_index: condition.set_index.expect("set_any set_index"),
                    not: condition.not.unwrap_or(false),
                },
                "dest_port_any" => UserspaceRoutingCondition::DestPortAny {
                    ranges: condition
                        .ranges
                        .as_ref()
                        .expect("dest_port_any ranges")
                        .iter()
                        .map(|range| (range[0], range[1]))
                        .collect(),
                    not: condition.not.unwrap_or(false),
                },
                "source_port_any" => UserspaceRoutingCondition::SourcePortAny {
                    ranges: condition
                        .ranges
                        .as_ref()
                        .expect("source_port_any ranges")
                        .iter()
                        .map(|range| (range[0], range[1]))
                        .collect(),
                    not: condition.not.unwrap_or(false),
                },
                "l4proto_mask" => UserspaceRoutingCondition::L4ProtoMask {
                    mask: condition.mask.expect("l4proto_mask mask"),
                    not: condition.not.unwrap_or(false),
                },
                "ip_version_mask" => UserspaceRoutingCondition::IpVersionMask {
                    mask: condition.mask.expect("ip_version_mask mask"),
                    not: condition.not.unwrap_or(false),
                },
                "process_name_any" => UserspaceRoutingCondition::ProcessNameAny {
                    names: condition
                        .names
                        .as_ref()
                        .expect("process_name_any names")
                        .iter()
                        .map(|name| process_name16(name))
                        .collect(),
                    not: condition.not.unwrap_or(false),
                },
                "dscp_any" => UserspaceRoutingCondition::DscpAny {
                    values: SmallVec::from_vec(condition.values.clone().expect("dscp_any values")),
                    not: condition.not.unwrap_or(false),
                },
                "fallback" => UserspaceRoutingCondition::Fallback,
                other => panic!("unknown routing condition kind: {other}"),
            })
            .collect(),
        action: match rule.action.kind.as_str() {
            "continue_must" => UserspaceRoutingAction::ContinueMust,
            "route" => UserspaceRoutingAction::Route {
                outbound: rule.action.outbound.expect("route outbound"),
                mark: rule.action.mark.unwrap_or(0),
                must: rule.action.must.unwrap_or(false),
            },
            other => panic!("unknown routing action kind: {other}"),
        },
    }
}

fn expected_request_action(action: &ActionFixture) -> DnsRequestAction {
    match action.kind.as_str() {
        "user_defined" => DnsRequestAction::UserDefined(action.value.expect("user_defined value")),
        "reject" => DnsRequestAction::Reject,
        "asis" => DnsRequestAction::AsIs,
        other => panic!("unknown request action kind: {other}"),
    }
}

fn expected_response_action(action: &ActionFixture) -> DnsResponseAction {
    match action.kind.as_str() {
        "user_defined" => DnsResponseAction::UserDefined(action.value.expect("user_defined value")),
        "accept" => DnsResponseAction::Accept,
        "reject" => DnsResponseAction::Reject,
        other => panic!("unknown response action kind: {other}"),
    }
}

fn load_fixture<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    let data = fs::read_to_string(path).expect("read fixture");
    serde_json::from_str(&data).expect("parse fixture")
}

fn process_name16(name: &str) -> [u8; 16] {
    let bytes = name.as_bytes();
    assert!(bytes.len() <= 16, "process name too long for fixture");
    let mut out = [0u8; 16];
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

fn ip_set_matches(prefixes: &[String], ips: &[String]) -> bool {
    prefixes
        .iter()
        .any(|prefix| ips.iter().any(|ip| ip_matches_prefix(ip, prefix)))
}

fn ip_matches_prefix(ip: &str, prefix: &str) -> bool {
    let (prefix_addr, bits) = prefix.split_once('/').expect("cidr prefix");
    let bits: u8 = bits.parse().expect("prefix bits");
    let ip = IpAddr::from_str(ip).expect("ip addr");
    let prefix = IpAddr::from_str(prefix_addr).expect("prefix addr");
    match (ip, prefix) {
        (IpAddr::V4(ip), IpAddr::V4(prefix)) => {
            let ip = u32::from(ip);
            let prefix = u32::from(prefix);
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            (ip & mask) == (prefix & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(prefix)) => {
            let ip = u128::from(ip);
            let prefix = u128::from(prefix);
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            (ip & mask) == (prefix & mask)
        }
        _ => false,
    }
}

fn parse_ip_addr(ip: &str) -> [u8; 16] {
    match IpAddr::from_str(ip).expect("ip addr") {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    }
}

fn parse_ip_prefix(prefix: &str) -> IpPrefix {
    let (addr, bits) = prefix.split_once('/').expect("cidr prefix");
    let bits: u8 = bits.parse().expect("prefix bits");
    match IpAddr::from_str(addr).expect("prefix addr") {
        IpAddr::V4(ip) => IpPrefix::new(ip.to_ipv6_mapped().octets(), bits + 96),
        IpAddr::V6(ip) => IpPrefix::new(ip.octets(), bits),
    }
}

fn parse_mac16(mac: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut tail = [0u8; 6];
    for (i, part) in mac.split(':').enumerate() {
        tail[i] = u8::from_str_radix(part, 16).expect("mac byte");
    }
    out[10..].copy_from_slice(&tail);
    out
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
