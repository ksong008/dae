use dae_domain_matcher::{
    DomainPatternKind, DomainPatternSet, build_indexed_matcher, build_reference_matcher,
};

const LIVE_GEOSITE: &str = include_str!("../fixtures/live_geosite.tsv");

struct FixtureCase {
    domain: String,
    expected_words: Vec<u32>,
}

#[test]
fn indexed_matcher_matches_live_geosite_fixture() {
    let (bit_len, sets, cases) = parse_live_geosite_fixture();
    let matcher = build_indexed_matcher(bit_len, &sets).expect("build indexed matcher");

    for case in cases {
        let bitmap = matcher
            .match_domain_bitmap(&case.domain)
            .expect("match live geosite fixture case");
        assert_eq!(bitmap, case.expected_words, "domain: {}", case.domain);
    }
}

#[test]
fn reference_matcher_matches_live_geosite_fixture_sample() {
    let (bit_len, sets, cases) = parse_live_geosite_fixture();
    let matcher = build_reference_matcher(bit_len, &sets).expect("build reference matcher");

    for case in cases.iter().take(64) {
        let bitmap = matcher
            .match_domain_bitmap(&case.domain)
            .expect("match live geosite fixture case");
        assert_eq!(bitmap, case.expected_words, "domain: {}", case.domain);
    }
}

fn parse_live_geosite_fixture() -> (usize, Vec<DomainPatternSet>, Vec<FixtureCase>) {
    let mut bit_len = None;
    let mut sets: Vec<DomainPatternSet> = Vec::new();
    let mut cases = Vec::new();

    for (line_no, raw_line) in LIVE_GEOSITE.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields = line.split('\t').collect::<Vec<_>>();
        match fields.as_slice() {
            ["bit_len", value] => {
                bit_len =
                    Some(value.parse::<usize>().unwrap_or_else(|error| {
                        panic!("line {}: bad bit_len: {error}", line_no + 1)
                    }));
            }
            ["rule", bit_index, kind, pattern] => {
                let bit_index = bit_index
                    .parse::<usize>()
                    .unwrap_or_else(|error| panic!("line {}: bad bit index: {error}", line_no + 1));
                let kind = parse_kind(kind, line_no + 1);
                if let Some(set) = sets
                    .iter_mut()
                    .find(|set| set.bit_index == bit_index && set.kind == kind)
                {
                    set.patterns.push((*pattern).into());
                } else {
                    sets.push(DomainPatternSet {
                        bit_index,
                        kind,
                        patterns: vec![(*pattern).into()],
                    });
                }
            }
            ["case", domain, expected] => {
                cases.push(FixtureCase {
                    domain: (*domain).into(),
                    expected_words: expected
                        .split(',')
                        .map(|word| {
                            word.parse::<u32>().unwrap_or_else(|error| {
                                panic!("line {}: bad bitmap word: {error}", line_no + 1)
                            })
                        })
                        .collect(),
                });
            }
            _ => panic!("line {}: bad live geosite fixture row: {line}", line_no + 1),
        }
    }

    let bit_len = bit_len.expect("live geosite fixture missing bit_len row");
    assert!(!sets.is_empty(), "live geosite fixture has no rule sets");
    assert!(!cases.is_empty(), "live geosite fixture has no cases");
    (bit_len, sets, cases)
}

fn parse_kind(kind: &str, line_no: usize) -> DomainPatternKind {
    match kind {
        "full" => DomainPatternKind::Full,
        "suffix" => DomainPatternKind::Suffix,
        "keyword" => DomainPatternKind::Keyword,
        "regex" => DomainPatternKind::Regex,
        _ => panic!("line {line_no}: unknown domain pattern kind: {kind}"),
    }
}
