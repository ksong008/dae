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
	"github.com/sirupsen/logrus"
)

const sharedCorpusBitLength = 64

type sharedCorpusCase struct {
	domain        string
	expectedWords []uint32
}

func loadSharedCorpus(tb testing.TB) ([]routing.DomainSet, []sharedCorpusCase) {
	tb.Helper()

	path := filepath.Join("..", "..", "..", "rust", "crates", "dae-domain-matcher", "fixtures", "shared_benchmark.tsv")
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}

	var sets []routing.DomainSet
	var cases []sharedCorpusCase

	for lineNo, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, "\t")
		switch fields[0] {
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
			expected, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil {
				tb.Fatalf("line %d: bad expected bitmap word: %v", lineNo+1, err)
			}
			cases = append(cases, sharedCorpusCase{
				domain:        fields[1],
				expectedWords: []uint32{uint32(expected), 0},
			})
		default:
			tb.Fatalf("line %d: unknown row type: %q", lineNo+1, fields[0])
		}
	}

	if len(sets) == 0 || len(cases) == 0 {
		tb.Fatal("shared corpus is empty")
	}
	return sets, cases
}

func buildSharedCorpusAhocorasick(tb testing.TB) (*AhocorasickSlimtrie, []sharedCorpusCase) {
	tb.Helper()
	logrus.SetLevel(logrus.WarnLevel)
	sets, cases := loadSharedCorpus(tb)
	matcher := NewAhocorasickSlimtrie(logrus.StandardLogger(), sharedCorpusBitLength)
	for _, set := range sets {
		matcher.AddSet(set.RuleIndex, set.Domains, set.Key)
	}
	if err := matcher.Build(); err != nil {
		tb.Fatal(err)
	}
	return matcher, cases
}

func TestSharedCorpusAhocorasickSlimtrieParity(t *testing.T) {
	matcher, cases := buildSharedCorpusAhocorasick(t)
	assertCorpusCasesMatch(t, matcher, cases)
}

func assertCorpusCasesMatch(tb testing.TB, matcher *AhocorasickSlimtrie, cases []sharedCorpusCase) {
	tb.Helper()
	for _, tc := range cases {
		bitmap := matcher.MatchDomainBitmap(tc.domain)
		for i, expected := range tc.expectedWords {
			if bitmap[i] != expected {
				tb.Fatalf("domain %q: bitmap[%d]=%b, want %b", tc.domain, i, bitmap[i], expected)
			}
		}
	}
}

func BenchmarkSharedCorpusAhocorasickSlimtrie(b *testing.B) {
	matcher, cases := buildSharedCorpusAhocorasick(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			_ = matcher.MatchDomainBitmap(tc.domain)
		}
	}
}

func BenchmarkSharedCorpusGoRegexpNfa(b *testing.B) {
	logrus.SetLevel(logrus.WarnLevel)
	sets, cases := loadSharedCorpus(b)
	matcher := NewGoRegexpNfa(sharedCorpusBitLength)
	for _, set := range sets {
		matcher.AddSet(set.RuleIndex, set.Domains, set.Key)
	}
	if err := matcher.Build(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			_ = matcher.MatchDomainBitmap(tc.domain)
		}
	}
}

func BenchmarkSharedCorpusBruteforce(b *testing.B) {
	sets, cases := loadSharedCorpus(b)
	matcher := NewBruteforce(sharedCorpusBitLength)
	for _, set := range sets {
		matcher.AddSet(set.RuleIndex, set.Domains, set.Key)
	}
	if err := matcher.Build(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			_ = matcher.MatchDomainBitmap(tc.domain)
		}
	}
}

func generatedCorpus(groups int) (bitLength int, sets []routing.DomainSet, cases []sharedCorpusCase) {
	bitLength = groups * 4
	sets = make([]routing.DomainSet, 0, bitLength)
	cases = make([]sharedCorpusCase, 0, groups*5)

	for group := 0; group < groups; group++ {
		fullBit := group * 4
		suffixBit := fullBit + 1
		keywordBit := fullBit + 2
		regexBit := fullBit + 3

		sets = append(sets,
			routing.DomainSet{
				Key:       consts.RoutingDomainKey_Full,
				RuleIndex: fullBit,
				Domains:   []string{generatedName("host", group) + ".example.com"},
			},
			routing.DomainSet{
				Key:       consts.RoutingDomainKey_Suffix,
				RuleIndex: suffixBit,
				Domains:   []string{generatedName("suf", group) + ".example.net"},
			},
			routing.DomainSet{
				Key:       consts.RoutingDomainKey_Keyword,
				RuleIndex: keywordBit,
				Domains:   []string{generatedName("kw", group) + "-"},
			},
			routing.DomainSet{
				Key:       consts.RoutingDomainKey_Regex,
				RuleIndex: regexBit,
				Domains:   []string{"^r" + generatedIndex(group) + "[0-9]+\\.example\\.org$"},
			},
		)

		cases = append(cases,
			generatedCase(generatedName("host", group)+".example.com.", bitLength, fullBit),
			generatedCase("api."+generatedName("suf", group)+".example.net", bitLength, suffixBit),
			generatedCase("cdn-"+generatedName("kw", group)+"-asset.net", bitLength, keywordBit),
			generatedCase("r"+generatedIndex(group)+"42.example.org", bitLength, regexBit),
			sharedCorpusCase{
				domain:        "miss" + generatedIndex(group) + ".example.invalid",
				expectedWords: make([]uint32, bitmapWords(bitLength)),
			},
		)
	}

	return bitLength, sets, cases
}

func generatedName(prefix string, group int) string {
	return prefix + generatedIndex(group)
}

func generatedIndex(group int) string {
	return strconv.FormatInt(int64(group+1000000), 10)[1:]
}

func generatedCase(domain string, bitLength, bitIndex int) sharedCorpusCase {
	expectedWords := make([]uint32, bitmapWords(bitLength))
	expectedWords[bitIndex/32] = 1 << (bitIndex % 32)
	return sharedCorpusCase{
		domain:        domain,
		expectedWords: expectedWords,
	}
}

func bitmapWords(bitLength int) int {
	return (bitLength + 31) / 32
}

func buildGeneratedCorpusAhocorasick(tb testing.TB, groups int) (*AhocorasickSlimtrie, []sharedCorpusCase) {
	tb.Helper()
	logrus.SetLevel(logrus.WarnLevel)
	bitLength, sets, cases := generatedCorpus(groups)
	matcher := NewAhocorasickSlimtrie(logrus.StandardLogger(), bitLength)
	for _, set := range sets {
		matcher.AddSet(set.RuleIndex, set.Domains, set.Key)
	}
	if err := matcher.Build(); err != nil {
		tb.Fatal(err)
	}
	return matcher, cases
}

func TestGeneratedCorpusAhocorasickSlimtrieParity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		groups int
	}{
		{name: "medium", groups: 32},
		{name: "large", groups: 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matcher, cases := buildGeneratedCorpusAhocorasick(t, tc.groups)
			assertCorpusCasesMatch(t, matcher, cases)
		})
	}
}

func BenchmarkGeneratedCorpusMediumAhocorasickSlimtrie(b *testing.B) {
	benchmarkGeneratedCorpusAhocorasick(b, 32)
}

func BenchmarkGeneratedCorpusLargeAhocorasickSlimtrie(b *testing.B) {
	benchmarkGeneratedCorpusAhocorasick(b, 128)
}

func benchmarkGeneratedCorpusAhocorasick(b *testing.B, groups int) {
	matcher, cases := buildGeneratedCorpusAhocorasick(b, groups)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			_ = matcher.MatchDomainBitmap(tc.domain)
		}
	}
}
