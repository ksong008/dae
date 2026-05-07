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

type fixedDnsRequestDomainMatcher struct {
	bitmapByDomain map[string][]uint32
}

func (m *fixedDnsRequestDomainMatcher) AddSet(int, []string, consts.RoutingDomainKey) {}

func (m *fixedDnsRequestDomainMatcher) Build() error { return nil }

func (m *fixedDnsRequestDomainMatcher) MatchDomainBitmap(domain string) []uint32 {
	bitmap := append([]uint32(nil), m.bitmapByDomain[domain]...)
	if bitmap == nil {
		return []uint32{0}
	}
	return bitmap
}

func (m *fixedDnsRequestDomainMatcher) MatchDomainBitmapInto(domain string, bitmap []uint32) error {
	for i := range bitmap {
		bitmap[i] = 0
	}
	copy(bitmap, m.bitmapByDomain[domain])
	return nil
}

var (
	_ routing.DomainMatcher     = (*fixedDnsRequestDomainMatcher)(nil)
	_ routing.DomainMatcherInto = (*fixedDnsRequestDomainMatcher)(nil)
)

func TestRequestMatcherRuleSemantics(t *testing.T) {
	domainMatcher := &fixedDnsRequestDomainMatcher{
		bitmapByDomain: map[string][]uint32{
			"example.com": {1},
		},
	}
	matcher := &RequestMatcher{
		domainMatcher:    domainMatcher,
		domainBitmapPool: routing.NewDomainBitmapPool(domainMatcher, 32),
		matches: []requestMatchSet{
			{
				Type:     consts.MatchType_DomainSet,
				Upstream: uint8(consts.DnsRequestOutboundIndex_LogicalAnd),
			},
			{
				Type:     consts.MatchType_QType,
				Value:    1,
				Upstream: uint8(consts.DnsRequestOutboundIndex_LogicalOr),
			},
			{
				Type:     consts.MatchType_QType,
				Value:    28,
				Upstream: 3,
			},
			{
				Type:     consts.MatchType_QType,
				Value:    15,
				Not:      true,
				Upstream: uint8(consts.DnsRequestOutboundIndex_Reject),
			},
			{
				Type:     consts.MatchType_Fallback,
				Upstream: uint8(consts.DnsRequestOutboundIndex_AsIs),
			},
		},
	}

	for _, tc := range []struct {
		name     string
		qname    string
		qtype    uint16
		expected consts.DnsRequestOutboundIndex
	}{
		{
			name:     "domain and first qtype hit primary rule",
			qname:    "example.com",
			qtype:    1,
			expected: consts.DnsRequestOutboundIndex(3),
		},
		{
			name:     "domain and second qtype hit primary rule",
			qname:    "example.com",
			qtype:    28,
			expected: consts.DnsRequestOutboundIndex(3),
		},
		{
			name:     "negated qtype rule rejects when primary rule misses",
			qname:    "miss.example",
			qtype:    16,
			expected: consts.DnsRequestOutboundIndex_Reject,
		},
		{
			name:     "fallback handles negated qtype miss without domain hit",
			qname:    "miss.example",
			qtype:    15,
			expected: consts.DnsRequestOutboundIndex_AsIs,
		},
		{
			name:     "fallback handles primary rule qtype miss even when domain matched",
			qname:    "example.com",
			qtype:    15,
			expected: consts.DnsRequestOutboundIndex_AsIs,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, err := matcher.Match(tc.qname, tc.qtype)
			if err != nil {
				t.Fatalf("Match(%q, %d) error = %v", tc.qname, tc.qtype, err)
			}
			if upstream != tc.expected {
				t.Fatalf("Match(%q, %d) = %v, want %v", tc.qname, tc.qtype, upstream, tc.expected)
			}
		})
	}
}
