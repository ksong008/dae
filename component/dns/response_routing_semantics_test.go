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
	"github.com/daeuniverse/dae/pkg/trie"
)

func TestResponseMatcherRuleSemantics(t *testing.T) {
	domainMatcher := &fixedDnsRequestDomainMatcher{
		bitmapByDomain: map[string][]uint32{
			"example.com": {1},
		},
	}
	ipTrie, err := trie.NewTrieFromPrefixes([]netip.Prefix{
		netip.MustParsePrefix("1.1.1.0/24"),
	})
	if err != nil {
		t.Fatal(err)
	}

	matcher := &ResponseMatcher{
		domainMatcher:    domainMatcher,
		domainBitmapPool: routing.NewDomainBitmapPool(domainMatcher, 32),
		ipSet:            []*trie.Trie{ipTrie},
		matches: []responseMatchSet{
			{
				Type:     consts.MatchType_DomainSet,
				Upstream: uint8(consts.DnsResponseOutboundIndex_LogicalAnd),
			},
			{
				Type:     consts.MatchType_QType,
				Value:    1,
				Upstream: uint8(consts.DnsResponseOutboundIndex_LogicalAnd),
			},
			{
				Type:     consts.MatchType_Upstream,
				Value:    uint16(consts.DnsRequestOutboundIndex(3)),
				Upstream: 7,
			},
			{
				Type:     consts.MatchType_IpSet,
				Value:    0,
				Upstream: uint8(consts.DnsResponseOutboundIndex_Reject),
			},
			{
				Type:     consts.MatchType_Fallback,
				Upstream: uint8(consts.DnsResponseOutboundIndex_Accept),
			},
		},
	}

	for _, tc := range []struct {
		name       string
		qname      string
		qtype      uint16
		ips        []netip.Addr
		upstream   consts.DnsRequestOutboundIndex
		expected   consts.DnsResponseOutboundIndex
	}{
		{
			name:     "domain qtype and upstream hit primary rule",
			qname:    "example.com",
			qtype:    1,
			upstream: consts.DnsRequestOutboundIndex(3),
			expected: consts.DnsResponseOutboundIndex(7),
		},
		{
			name: "ip set rule hits when primary rule misses",
			qname: "miss.example",
			qtype: 15,
			ips: []netip.Addr{
				netip.MustParseAddr("1.1.1.8"),
			},
			upstream: consts.DnsRequestOutboundIndex(9),
			expected: consts.DnsResponseOutboundIndex_Reject,
		},
		{
			name:     "fallback handles total miss",
			qname:    "miss.example",
			qtype:    15,
			upstream: consts.DnsRequestOutboundIndex(9),
			expected: consts.DnsResponseOutboundIndex_Accept,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, err := matcher.Match(tc.qname, tc.qtype, tc.ips, tc.upstream)
			if err != nil {
				t.Fatalf("Match(%q, %d) error = %v", tc.qname, tc.qtype, err)
			}
			if upstream != tc.expected {
				t.Fatalf("Match(%q, %d) = %v, want %v", tc.qname, tc.qtype, upstream, tc.expected)
			}
		})
	}
}
