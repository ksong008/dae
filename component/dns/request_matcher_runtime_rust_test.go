//go:build rust_dns_request_matcher && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

func TestRustRequestMatcherRuntimeSharedFixtureBuildAndMatch(t *testing.T) {
	fixture := loadDNSRequestFixture(t, "dns_request_semantics.json")
	builder := &RequestMatcherBuilder{
		simulatedDomainSet: []routing.DomainSet{
			{
				Key:       consts.RoutingDomainKey_Full,
				RuleIndex: 0,
				Domains:   []string{"example.com"},
			},
		},
		rules: buildRequestMatchSets(t, fixture.Rules),
	}

	matcher, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	defer matcher.Close()

	if matcher.rustMatcher == nil {
		t.Fatal("expected Rust DNS request matcher runtime to be installed")
	}
	if matcher.domainMatcher != nil {
		t.Fatalf("expected Go domain matcher to be bypassed, got %T", matcher.domainMatcher)
	}

	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			upstream, err := matcher.Match(tc.QName, tc.QType)
			if err != nil {
				t.Fatalf("Match(%q, %d) error = %v", tc.QName, tc.QType, err)
			}
			if upstream != requestActionToIndex(t, tc.Expected) {
				t.Fatalf("Match(%q, %d) = %v, want %v", tc.QName, tc.QType, upstream, requestActionToIndex(t, tc.Expected))
			}
		})
	}
}

func BenchmarkRustRequestMatcherRuntimeSharedFixture(b *testing.B) {
	fixture := loadDNSRequestFixture(b, "dns_request_semantics.json")
	builder := &RequestMatcherBuilder{
		simulatedDomainSet: []routing.DomainSet{
			{
				Key:       consts.RoutingDomainKey_Full,
				RuleIndex: 0,
				Domains:   []string{"example.com"},
			},
		},
		rules: buildRequestMatchSets(b, fixture.Rules),
	}

	matcher, err := builder.Build()
	if err != nil {
		b.Fatalf("Build() error = %v", err)
	}
	defer matcher.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range fixture.Cases {
			upstream, err := matcher.Match(tc.QName, tc.QType)
			if err != nil {
				b.Fatalf("Match(%q, %d) error = %v", tc.QName, tc.QType, err)
			}
			if upstream != requestActionToIndex(b, tc.Expected) {
				b.Fatalf("Match(%q, %d) = %v, want %v", tc.QName, tc.QType, upstream, requestActionToIndex(b, tc.Expected))
			}
		}
	}
}
