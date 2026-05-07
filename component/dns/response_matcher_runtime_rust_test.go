//go:build rust_dns_request_matcher && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

func TestRustResponseMatcherRuntimeSharedFixtureBuildAndMatch(t *testing.T) {
	fixture := loadDNSResponseFixture(t, "dns_response_semantics.json")
	builder := &ResponseMatcherBuilder{
		simulatedDomainSet: []routing.DomainSet{
			{
				Key:       consts.RoutingDomainKey_Full,
				RuleIndex: 0,
				Domains:   []string{"example.com"},
			},
		},
		simulatedIpPrefixes: fixture.IPSetsToPrefixes(t),
		ipSet: buildDNSIPSets(t, fixture.IPSets),
		rules: buildResponseMatchSets(t, fixture.Rules),
	}

	matcher, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	defer matcher.Close()

	if matcher.rustMatcher == nil {
		t.Fatal("expected Rust DNS response matcher runtime to be installed")
	}
	if matcher.domainMatcher != nil {
		t.Fatalf("expected Go response matcher shell to bypass domain matcher, got %T", matcher.domainMatcher)
	}

	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			ips := make([]netip.Addr, 0, len(tc.IPs))
			for _, ip := range tc.IPs {
				ips = append(ips, netip.MustParseAddr(ip))
			}
			upstream, err := matcher.Match(tc.QName, tc.QType, ips, consts.DnsRequestOutboundIndex(tc.RequestUpstream))
			if err != nil {
				t.Fatalf("Match(%q, %d) error = %v", tc.QName, tc.QType, err)
			}
			if upstream != responseActionToIndex(t, tc.Expected) {
				t.Fatalf("Match(%q, %d) = %v, want %v", tc.QName, tc.QType, upstream, responseActionToIndex(t, tc.Expected))
			}
		})
	}
}

func BenchmarkRustResponseMatcherRuntimeSharedFixture(b *testing.B) {
	fixture := loadDNSResponseFixture(b, "dns_response_semantics.json")
	builder := &ResponseMatcherBuilder{
		simulatedDomainSet: []routing.DomainSet{
			{
				Key:       consts.RoutingDomainKey_Full,
				RuleIndex: 0,
				Domains:   []string{"example.com"},
			},
		},
		simulatedIpPrefixes: fixture.IPSetsToPrefixes(b),
		ipSet:               buildDNSIPSets(b, fixture.IPSets),
		rules:               buildResponseMatchSets(b, fixture.Rules),
	}

	matcher, err := builder.Build()
	if err != nil {
		b.Fatalf("Build() error = %v", err)
	}
	defer matcher.Close()

	cases := make([]struct {
		qname           string
		qtype           uint16
		ips             []netip.Addr
		requestUpstream consts.DnsRequestOutboundIndex
		expected        consts.DnsResponseOutboundIndex
	}, 0, len(fixture.Cases))
	for _, tc := range fixture.Cases {
		ips := make([]netip.Addr, 0, len(tc.IPs))
		for _, ip := range tc.IPs {
			ips = append(ips, netip.MustParseAddr(ip))
		}
		cases = append(cases, struct {
			qname           string
			qtype           uint16
			ips             []netip.Addr
			requestUpstream consts.DnsRequestOutboundIndex
			expected        consts.DnsResponseOutboundIndex
		}{
			qname:           tc.QName,
			qtype:           tc.QType,
			ips:             ips,
			requestUpstream: consts.DnsRequestOutboundIndex(tc.RequestUpstream),
			expected:        responseActionToIndex(b, tc.Expected),
		})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			upstream, err := matcher.Match(tc.qname, tc.qtype, tc.ips, tc.requestUpstream)
			if err != nil {
				b.Fatalf("Match(%q, %d) error = %v", tc.qname, tc.qtype, err)
			}
			if upstream != tc.expected {
				b.Fatalf("Match(%q, %d) = %v, want %v", tc.qname, tc.qtype, upstream, tc.expected)
			}
		}
	}
}
