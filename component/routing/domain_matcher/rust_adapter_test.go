//go:build rust_domain_matcher && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

func TestRustDomainMatcherSharedCorpusParity(t *testing.T) {
	sets, cases := loadSharedCorpus(t)
	matcher := buildRustDomainMatcher(t, sharedCorpusBitLength, sets)
	assertRustDomainMatcherCases(t, matcher, cases)
}

func TestRustDomainMatcherGeneratedCorpusParity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		groups int
	}{
		{name: "medium", groups: 32},
		{name: "large", groups: 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bitLength, sets, cases := generatedCorpus(tc.groups)
			matcher := buildRustDomainMatcher(t, bitLength, sets)
			assertRustDomainMatcherCases(t, matcher, cases)
		})
	}
}

func TestRustDomainMatcherLiveGeositeFixtureParity(t *testing.T) {
	bitLength, sets, cases := loadLiveGeositeCorpus(t)
	matcher := buildRustDomainMatcher(t, bitLength, sets)
	assertRustDomainMatcherCases(t, matcher, cases)
}

func TestRustDomainMatcherLiveGeositeFixtureIntoParity(t *testing.T) {
	bitLength, sets, cases := loadLiveGeositeCorpus(t)
	matcher := buildRustDomainMatcher(t, bitLength, sets)
	assertRustDomainMatcherIntoCases(t, matcher, cases)
}

func BenchmarkRustDomainMatcherLiveGeositeFixture(b *testing.B) {
	bitLength, sets, cases := loadLiveGeositeCorpus(b)
	matcher := buildRustDomainMatcher(b, bitLength, sets)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			_ = matcher.MatchDomainBitmap(tc.domain)
		}
	}
}

func BenchmarkRustDomainMatcherLiveGeositeFixtureReuseBitmap(b *testing.B) {
	bitLength, sets, cases := loadLiveGeositeCorpus(b)
	matcher := buildRustDomainMatcher(b, bitLength, sets)
	bitmap := make([]uint32, rustDomainBitmapWords(bitLength))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			if err := matcher.MatchDomainBitmapInto(tc.domain, bitmap); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func buildRustDomainMatcher(tb testing.TB, bitLength int, sets []routing.DomainSet) *RustDomainMatcher {
	tb.Helper()

	matcher := NewRustDomainMatcher(bitLength)
	tb.Cleanup(matcher.Close)
	for _, set := range sets {
		matcher.AddSet(set.RuleIndex, set.Domains, set.Key)
	}
	if err := matcher.Build(); err != nil {
		tb.Fatal(err)
	}
	return matcher
}

func assertRustDomainMatcherCases(tb testing.TB, matcher *RustDomainMatcher, cases []sharedCorpusCase) {
	tb.Helper()

	for _, tc := range cases {
		bitmap := matcher.MatchDomainBitmap(tc.domain)
		if len(bitmap) != len(tc.expectedWords) {
			tb.Fatalf("domain %q: bitmap len=%d, want %d", tc.domain, len(bitmap), len(tc.expectedWords))
		}
		for i, expected := range tc.expectedWords {
			if bitmap[i] != expected {
				tb.Fatalf("domain %q: bitmap[%d]=%b, want %b", tc.domain, i, bitmap[i], expected)
			}
		}
	}
}

func assertRustDomainMatcherIntoCases(tb testing.TB, matcher *RustDomainMatcher, cases []sharedCorpusCase) {
	tb.Helper()

	bitmap := make([]uint32, rustDomainBitmapWords(matcher.bitLength))
	for _, tc := range cases {
		for i := range bitmap {
			bitmap[i] = ^uint32(0)
		}
		if err := matcher.MatchDomainBitmapInto(tc.domain, bitmap); err != nil {
			tb.Fatalf("domain %q: %v", tc.domain, err)
		}
		for i, expected := range tc.expectedWords {
			if bitmap[i] != expected {
				tb.Fatalf("domain %q: bitmap[%d]=%b, want %b", tc.domain, i, bitmap[i], expected)
			}
		}
	}
}

func loadLiveGeositeCorpus(tb testing.TB) (int, []routing.DomainSet, []sharedCorpusCase) {
	tb.Helper()

	path := filepath.Join("..", "..", "..", "rust", "crates", "dae-domain-matcher", "fixtures", "live_geosite.tsv")
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}

	var bitLength int
	var sets []routing.DomainSet
	var cases []sharedCorpusCase

	for lineNo, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, "\t")
		switch fields[0] {
		case "bit_len":
			if len(fields) != 2 {
				tb.Fatalf("line %d: bad bit_len field count: %q", lineNo+1, line)
			}
			value, err := strconv.Atoi(fields[1])
			if err != nil {
				tb.Fatalf("line %d: bad bit_len: %v", lineNo+1, err)
			}
			bitLength = value
		case "rule":
			if len(fields) != 4 {
				tb.Fatalf("line %d: bad rule field count: %q", lineNo+1, line)
			}
			bitIndex, err := strconv.Atoi(fields[1])
			if err != nil {
				tb.Fatalf("line %d: bad bit index: %v", lineNo+1, err)
			}
			key := consts.RoutingDomainKey(fields[2])
			var found bool
			for i := range sets {
				if sets[i].RuleIndex == bitIndex && sets[i].Key == key {
					sets[i].Domains = append(sets[i].Domains, fields[3])
					found = true
					break
				}
			}
			if !found {
				sets = append(sets, routing.DomainSet{
					Key:       key,
					RuleIndex: bitIndex,
					Domains:   []string{fields[3]},
				})
			}
		case "case":
			if len(fields) != 3 {
				tb.Fatalf("line %d: bad case field count: %q", lineNo+1, line)
			}
			words := strings.Split(fields[2], ",")
			expected := make([]uint32, 0, len(words))
			for _, word := range words {
				value, err := strconv.ParseUint(word, 10, 32)
				if err != nil {
					tb.Fatalf("line %d: bad bitmap word: %v", lineNo+1, err)
				}
				expected = append(expected, uint32(value))
			}
			cases = append(cases, sharedCorpusCase{
				domain:        fields[1],
				expectedWords: expected,
			})
		default:
			tb.Fatalf("line %d: unknown row type: %q", lineNo+1, fields[0])
		}
	}

	if bitLength == 0 || len(sets) == 0 || len(cases) == 0 {
		tb.Fatal("live geosite corpus is incomplete")
	}
	return bitLength, sets, cases
}
