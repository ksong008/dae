use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use dae_domain_matcher::{
    DomainPatternKind, DomainPatternSet, IndexedMatcher, ReferenceMatcher, bitmap_words,
    build_indexed_matcher, build_reference_matcher,
};

const SHARED_CORPUS: &str = include_str!("../fixtures/shared_benchmark.tsv");
const LIVE_GEOSITE: &str = include_str!("../fixtures/live_geosite.tsv");

struct BenchCase {
    domain: String,
    expected_words: Vec<u32>,
}

fn bench_sets() -> Vec<DomainPatternSet> {
    shared_corpus().0
}

fn bench_cases() -> Vec<BenchCase> {
    shared_corpus().1
}

fn build_matcher() -> ReferenceMatcher {
    build_reference_matcher(64, &bench_sets()).expect("build reference matcher")
}

fn build_indexed() -> IndexedMatcher {
    build_indexed_matcher(64, &bench_sets()).expect("build indexed matcher")
}

fn shared_corpus() -> (Vec<DomainPatternSet>, Vec<BenchCase>) {
    let mut sets: Vec<DomainPatternSet> = Vec::new();
    let mut cases = Vec::new();

    for (line_no, raw_line) in SHARED_CORPUS.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields = line.split('\t').collect::<Vec<_>>();
        match fields.as_slice() {
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
                let expected_first_word = expected.parse::<u32>().unwrap_or_else(|error| {
                    panic!("line {}: bad expected bitmap word: {error}", line_no + 1)
                });
                cases.push(BenchCase {
                    domain: (*domain).into(),
                    expected_words: vec![expected_first_word, 0],
                });
            }
            _ => panic!("line {}: bad shared corpus row: {line}", line_no + 1),
        }
    }

    assert!(!sets.is_empty(), "shared corpus has no rule sets");
    assert!(!cases.is_empty(), "shared corpus has no cases");
    (sets, cases)
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

fn generated_corpus(groups: usize) -> (usize, Vec<DomainPatternSet>, Vec<BenchCase>) {
    let bit_len = groups * 4;
    let mut sets = Vec::with_capacity(bit_len);
    let mut cases = Vec::with_capacity(groups * 5);

    for group in 0..groups {
        let full_bit = group * 4;
        let suffix_bit = full_bit + 1;
        let keyword_bit = full_bit + 2;
        let regex_bit = full_bit + 3;

        sets.push(DomainPatternSet {
            bit_index: full_bit,
            kind: DomainPatternKind::Full,
            patterns: vec![format!("host{group:06}.example.com")],
        });
        sets.push(DomainPatternSet {
            bit_index: suffix_bit,
            kind: DomainPatternKind::Suffix,
            patterns: vec![format!("suf{group:06}.example.net")],
        });
        sets.push(DomainPatternSet {
            bit_index: keyword_bit,
            kind: DomainPatternKind::Keyword,
            patterns: vec![format!("kw{group:06}-")],
        });
        sets.push(DomainPatternSet {
            bit_index: regex_bit,
            kind: DomainPatternKind::Regex,
            patterns: vec![format!("^r{group:06}[0-9]+\\.example\\.org$")],
        });

        cases.push(generated_case(
            format!("host{group:06}.example.com."),
            bit_len,
            full_bit,
        ));
        cases.push(generated_case(
            format!("api.suf{group:06}.example.net"),
            bit_len,
            suffix_bit,
        ));
        cases.push(generated_case(
            format!("cdn-kw{group:06}-asset.net"),
            bit_len,
            keyword_bit,
        ));
        cases.push(generated_case(
            format!("r{group:06}42.example.org"),
            bit_len,
            regex_bit,
        ));
        cases.push(BenchCase {
            domain: format!("miss{group:06}.example.invalid"),
            expected_words: vec![0; bit_len.div_ceil(32)],
        });
    }

    (bit_len, sets, cases)
}

fn generated_case(domain: String, bit_len: usize, bit_index: usize) -> BenchCase {
    let mut expected_words = vec![0; bit_len.div_ceil(32)];
    expected_words[bit_index / 32] = 1 << (bit_index % 32);
    BenchCase {
        domain,
        expected_words,
    }
}

fn full_only_corpus(entries: usize) -> (usize, Vec<DomainPatternSet>, Vec<BenchCase>) {
    let bit_len = entries;
    let mut sets = Vec::with_capacity(entries);
    let mut cases = Vec::with_capacity(entries + entries / 2);

    for entry in 0..entries {
        sets.push(DomainPatternSet {
            bit_index: entry,
            kind: DomainPatternKind::Full,
            patterns: vec![format!("full{entry:06}.example.com")],
        });
        cases.push(generated_case(
            format!("full{entry:06}.example.com."),
            bit_len,
            entry,
        ));
        if entry % 2 == 0 {
            cases.push(BenchCase {
                domain: format!("miss{entry:06}.example.com"),
                expected_words: vec![0; bit_len.div_ceil(32)],
            });
        }
    }

    (bit_len, sets, cases)
}

fn assert_cases_match(matcher: &ReferenceMatcher, cases: &[BenchCase]) {
    for case in cases {
        let bitmap = matcher
            .match_domain_bitmap(&case.domain)
            .expect("match benchmark corpus case");
        assert_eq!(bitmap, case.expected_words, "domain: {}", case.domain);
    }
}

fn assert_indexed_cases_match(matcher: &IndexedMatcher, cases: &[BenchCase]) {
    for case in cases {
        let bitmap = matcher
            .match_domain_bitmap(&case.domain)
            .expect("match benchmark corpus case");
        assert_eq!(bitmap, case.expected_words, "domain: {}", case.domain);
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("reference_matcher_build", |b| {
        b.iter(|| {
            let matcher = build_reference_matcher(64, black_box(&bench_sets()))
                .expect("build reference matcher");
            black_box(matcher);
        });
    });

    c.bench_function("indexed_matcher_build", |b| {
        b.iter(|| {
            let matcher =
                build_indexed_matcher(64, black_box(&bench_sets())).expect("build indexed matcher");
            black_box(matcher);
        });
    });

    let matcher = build_matcher();
    let indexed = build_indexed();
    let cases = bench_cases();
    assert_cases_match(&matcher, &cases);
    assert_indexed_cases_match(&indexed, &cases);

    c.bench_function("reference_matcher_match_shared_corpus", |b| {
        b.iter(|| {
            for case in &cases {
                let bitmap = matcher
                    .match_domain_bitmap(black_box(&case.domain))
                    .expect("match domain bitmap");
                black_box(bitmap);
            }
        });
    });

    c.bench_function("indexed_matcher_match_shared_corpus", |b| {
        b.iter(|| {
            for case in &cases {
                let bitmap = indexed
                    .match_domain_bitmap(black_box(&case.domain))
                    .expect("match domain bitmap");
                black_box(bitmap);
            }
        });
    });

    let mut shared_reuse_bitmap = vec![0; bitmap_words(64)];
    c.bench_function("reference_matcher_match_shared_corpus_reuse_bitmap", |b| {
        b.iter(|| {
            for case in &cases {
                matcher
                    .match_domain_bitmap_into(
                        black_box(&case.domain),
                        black_box(&mut shared_reuse_bitmap),
                    )
                    .expect("match domain bitmap into caller-owned buffer");
                black_box(&shared_reuse_bitmap);
            }
        });
    });

    let mut indexed_shared_reuse_bitmap = vec![0; bitmap_words(64)];
    c.bench_function("indexed_matcher_match_shared_corpus_reuse_bitmap", |b| {
        b.iter(|| {
            for case in &cases {
                indexed
                    .match_domain_bitmap_into(
                        black_box(&case.domain),
                        black_box(&mut indexed_shared_reuse_bitmap),
                    )
                    .expect("match domain bitmap into caller-owned buffer");
                black_box(&indexed_shared_reuse_bitmap);
            }
        });
    });

    let mut indexed_shared_reuse_bitmap = vec![0; bitmap_words(64)];
    let mut indexed_shared_keyword_scratch = String::new();
    c.bench_function(
        "indexed_matcher_match_shared_corpus_reuse_bitmap_keyword_scratch",
        |b| {
            b.iter(|| {
                for case in &cases {
                    indexed
                        .match_domain_bitmap_into_with_keyword_scratch(
                            black_box(&case.domain),
                            black_box(&mut indexed_shared_reuse_bitmap),
                            black_box(&mut indexed_shared_keyword_scratch),
                        )
                        .expect("match domain bitmap into caller-owned buffers");
                    black_box(&indexed_shared_reuse_bitmap);
                    black_box(&indexed_shared_keyword_scratch);
                }
            });
        },
    );

    bench_generated_profile(c, "medium", 32);
    bench_generated_profile(c, "large", 128);
    bench_full_only_profile(c, "medium", 256);
    bench_full_only_profile(c, "large", 1024);
    bench_live_geosite_profile(c);
}

fn bench_generated_profile(c: &mut Criterion, name: &str, groups: usize) {
    let (bit_len, sets, cases) = generated_corpus(groups);
    let matcher = build_reference_matcher(bit_len, &sets).expect("build generated corpus matcher");
    let indexed = build_indexed_matcher(bit_len, &sets).expect("build indexed generated matcher");
    assert_cases_match(&matcher, &cases);
    assert_indexed_cases_match(&indexed, &cases);

    c.bench_function(&format!("reference_matcher_build_generated_{name}"), |b| {
        b.iter(|| {
            let matcher = build_reference_matcher(bit_len, black_box(&sets))
                .expect("build generated corpus matcher");
            black_box(matcher);
        });
    });

    c.bench_function(&format!("indexed_matcher_build_generated_{name}"), |b| {
        b.iter(|| {
            let matcher = build_indexed_matcher(bit_len, black_box(&sets))
                .expect("build indexed generated corpus matcher");
            black_box(matcher);
        });
    });

    c.bench_function(&format!("reference_matcher_match_generated_{name}"), |b| {
        b.iter(|| {
            for case in &cases {
                let bitmap = matcher
                    .match_domain_bitmap(black_box(&case.domain))
                    .expect("match generated domain bitmap");
                black_box(bitmap);
            }
        });
    });

    c.bench_function(&format!("indexed_matcher_match_generated_{name}"), |b| {
        b.iter(|| {
            for case in &cases {
                let bitmap = indexed
                    .match_domain_bitmap(black_box(&case.domain))
                    .expect("match indexed generated domain bitmap");
                black_box(bitmap);
            }
        });
    });

    let mut reuse_bitmap = vec![0; bitmap_words(bit_len)];
    c.bench_function(
        &format!("reference_matcher_match_generated_{name}_reuse_bitmap"),
        |b| {
            b.iter(|| {
                for case in &cases {
                    matcher
                        .match_domain_bitmap_into(
                            black_box(&case.domain),
                            black_box(&mut reuse_bitmap),
                        )
                        .expect("match generated domain bitmap into caller-owned buffer");
                    black_box(&reuse_bitmap);
                }
            });
        },
    );

    let mut indexed_reuse_bitmap = vec![0; bitmap_words(bit_len)];
    c.bench_function(
        &format!("indexed_matcher_match_generated_{name}_reuse_bitmap"),
        |b| {
            b.iter(|| {
                for case in &cases {
                    indexed
                        .match_domain_bitmap_into(
                            black_box(&case.domain),
                            black_box(&mut indexed_reuse_bitmap),
                        )
                        .expect("match indexed generated domain bitmap into caller-owned buffer");
                    black_box(&indexed_reuse_bitmap);
                }
            });
        },
    );

    let mut indexed_reuse_bitmap = vec![0; bitmap_words(bit_len)];
    let mut indexed_keyword_scratch = String::new();
    c.bench_function(
        &format!("indexed_matcher_match_generated_{name}_reuse_bitmap_keyword_scratch"),
        |b| {
            b.iter(|| {
                for case in &cases {
                    indexed
                        .match_domain_bitmap_into_with_keyword_scratch(
                            black_box(&case.domain),
                            black_box(&mut indexed_reuse_bitmap),
                            black_box(&mut indexed_keyword_scratch),
                        )
                        .expect("match indexed generated domain bitmap into caller-owned buffers");
                    black_box(&indexed_reuse_bitmap);
                    black_box(&indexed_keyword_scratch);
                }
            });
        },
    );
}

fn bench_full_only_profile(c: &mut Criterion, name: &str, entries: usize) {
    let (bit_len, sets, cases) = full_only_corpus(entries);
    let indexed =
        build_indexed_matcher(bit_len, &sets).expect("build indexed full-only corpus matcher");
    assert_indexed_cases_match(&indexed, &cases);

    c.bench_function(&format!("indexed_matcher_build_full_only_{name}"), |b| {
        b.iter(|| {
            let matcher = build_indexed_matcher(bit_len, black_box(&sets))
                .expect("build indexed full-only matcher");
            black_box(matcher);
        });
    });

    c.bench_function(&format!("indexed_matcher_match_full_only_{name}"), |b| {
        b.iter(|| {
            for case in &cases {
                let bitmap = indexed
                    .match_domain_bitmap(black_box(&case.domain))
                    .expect("match indexed full-only domain bitmap");
                black_box(bitmap);
            }
        });
    });

    let mut reuse_bitmap = vec![0; bitmap_words(bit_len)];
    c.bench_function(
        &format!("indexed_matcher_match_full_only_{name}_reuse_bitmap"),
        |b| {
            b.iter(|| {
                for case in &cases {
                    indexed
                        .match_domain_bitmap_into(
                            black_box(&case.domain),
                            black_box(&mut reuse_bitmap),
                        )
                        .expect("match indexed full-only domain bitmap into caller-owned buffer");
                    black_box(&reuse_bitmap);
                }
            });
        },
    );

    let mut reuse_bitmap = vec![0; bitmap_words(bit_len)];
    let mut keyword_scratch = String::new();
    c.bench_function(
        &format!("indexed_matcher_match_full_only_{name}_reuse_bitmap_keyword_scratch"),
        |b| {
            b.iter(|| {
                for case in &cases {
                    indexed
                        .match_domain_bitmap_into_with_keyword_scratch(
                            black_box(&case.domain),
                            black_box(&mut reuse_bitmap),
                            black_box(&mut keyword_scratch),
                        )
                        .expect("match indexed full-only domain bitmap into caller-owned buffers");
                    black_box(&reuse_bitmap);
                    black_box(&keyword_scratch);
                }
            });
        },
    );
}

fn bench_live_geosite_profile(c: &mut Criterion) {
    let (bit_len, sets, cases) = live_geosite_corpus();
    let indexed = build_indexed_matcher(bit_len, &sets).expect("build indexed live matcher");
    assert_indexed_cases_match(&indexed, &cases);

    c.bench_function("indexed_matcher_build_live_geosite", |b| {
        b.iter(|| {
            let matcher = build_indexed_matcher(bit_len, black_box(&sets))
                .expect("build indexed live geosite matcher");
            black_box(matcher);
        });
    });

    c.bench_function("indexed_matcher_match_live_geosite", |b| {
        b.iter(|| {
            for case in &cases {
                let bitmap = indexed
                    .match_domain_bitmap(black_box(&case.domain))
                    .expect("match indexed live geosite domain bitmap");
                black_box(bitmap);
            }
        });
    });

    let mut reuse_bitmap = vec![0; bitmap_words(bit_len)];
    c.bench_function("indexed_matcher_match_live_geosite_reuse_bitmap", |b| {
        b.iter(|| {
            for case in &cases {
                indexed
                    .match_domain_bitmap_into(black_box(&case.domain), black_box(&mut reuse_bitmap))
                    .expect("match indexed live geosite domain bitmap into caller-owned buffer");
                black_box(&reuse_bitmap);
            }
        });
    });

    let mut reuse_bitmap = vec![0; bitmap_words(bit_len)];
    let mut keyword_scratch = String::new();
    c.bench_function(
        "indexed_matcher_match_live_geosite_reuse_bitmap_keyword_scratch",
        |b| {
            b.iter(|| {
                for case in &cases {
                    indexed
                        .match_domain_bitmap_into_with_keyword_scratch(
                            black_box(&case.domain),
                            black_box(&mut reuse_bitmap),
                            black_box(&mut keyword_scratch),
                        )
                        .expect(
                            "match indexed live geosite domain bitmap into caller-owned buffers",
                        );
                    black_box(&reuse_bitmap);
                    black_box(&keyword_scratch);
                }
            });
        },
    );
}

fn live_geosite_corpus() -> (usize, Vec<DomainPatternSet>, Vec<BenchCase>) {
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
                cases.push(BenchCase {
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

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
