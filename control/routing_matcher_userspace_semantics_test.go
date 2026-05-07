/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/trie"
)

type fixedRoutingDomainMatcher struct {
	bitmapByDomain map[string][]uint32
}

func (m *fixedRoutingDomainMatcher) AddSet(int, []string, consts.RoutingDomainKey) {}

func (m *fixedRoutingDomainMatcher) Build() error { return nil }

func (m *fixedRoutingDomainMatcher) MatchDomainBitmap(domain string) []uint32 {
	bitmap := append([]uint32(nil), m.bitmapByDomain[domain]...)
	if bitmap == nil {
		return []uint32{0}
	}
	return bitmap
}

func (m *fixedRoutingDomainMatcher) MatchDomainBitmapInto(domain string, bitmap []uint32) error {
	for i := range bitmap {
		bitmap[i] = 0
	}
	copy(bitmap, m.bitmapByDomain[domain])
	return nil
}

var (
	_ routing.DomainMatcher     = (*fixedRoutingDomainMatcher)(nil)
	_ routing.DomainMatcherInto = (*fixedRoutingDomainMatcher)(nil)
)

func encodeIPv4Mapped(ip string) []byte {
	addr := netip.MustParseAddr(ip).As16()
	return addr[:]
}

func processName16(name string) [16]uint8 {
	var out [16]uint8
	copy(out[:], []byte(name))
	return out
}

func TestRoutingMatcherUserspaceRuleSemantics(t *testing.T) {
	destTrie, err := trie.NewTrieFromPrefixes([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	domainMatcher := &fixedRoutingDomainMatcher{
		bitmapByDomain: map[string][]uint32{
			"example.com": {1},
		},
	}
	matcher := &RoutingMatcher{
		lpmMatcher:       []*trie.Trie{destTrie},
		domainMatcher:    domainMatcher,
		domainBitmapPool: routing.NewDomainBitmapPool(domainMatcher, consts.MaxMatchSetLen),
		matches: []bpfMatchSet{
			{
				Type:     uint8(consts.MatchType_DomainSet),
				Outbound: uint8(consts.OutboundLogicalAnd),
			},
			{
				Type:     uint8(consts.MatchType_Port),
				Value:    (_bpfPortRange{PortStart: 443, PortEnd: 443}).Encode(),
				Outbound: uint8(consts.OutboundMustRules),
			},
			{
				Type:     uint8(consts.MatchType_L4Proto),
				Value:    [16]byte{byte(consts.L4ProtoType_TCP)},
				Outbound: uint8(consts.OutboundLogicalAnd),
			},
			{
				Type:     uint8(consts.MatchType_Dscp),
				Value:    [16]byte{46},
				Outbound: 7,
				Mark:     123,
			},
			{
				Type:     uint8(consts.MatchType_IpSet),
				Value:    [16]byte{0, 0, 0, 0},
				Outbound: uint8(consts.OutboundLogicalAnd),
			},
			{
				Type:     uint8(consts.MatchType_ProcessName),
				Value:    [16]byte(processName16("curl")),
				Outbound: 9,
			},
			{
				Type:     uint8(consts.MatchType_Fallback),
				Outbound: 2,
			},
		},
	}

	for _, tc := range []struct {
		name      string
		sourceIP  string
		destIP    string
		sourcePort uint16
		destPort  uint16
		l4proto   consts.L4ProtoType
		domain    string
		process   [16]uint8
		dscp      uint8
		expectedOutbound consts.OutboundIndex
		expectedMark     uint32
		expectedMust     bool
	}{
		{
			name:             "must rule carries into later route",
			sourceIP:         "198.51.100.2",
			destIP:           "198.51.100.9",
			sourcePort:       40000,
			destPort:         443,
			l4proto:          consts.L4ProtoType_TCP,
			domain:           "example.com",
			process:          processName16("curl"),
			dscp:             46,
			expectedOutbound: 7,
			expectedMark:     123,
			expectedMust:     true,
		},
		{
			name:             "dest ip and process name rule hits when must rule misses",
			sourceIP:         "198.51.100.2",
			destIP:           "203.0.113.7",
			sourcePort:       32000,
			destPort:         80,
			l4proto:          consts.L4ProtoType_UDP,
			domain:           "miss.example",
			process:          processName16("curl"),
			dscp:             0,
			expectedOutbound: 9,
			expectedMark:     0,
			expectedMust:     false,
		},
		{
			name:             "fallback handles total miss",
			sourceIP:         "198.51.100.2",
			destIP:           "198.51.100.9",
			sourcePort:       32000,
			destPort:         53,
			l4proto:          consts.L4ProtoType_UDP,
			domain:           "miss.example",
			process:          processName16("dae"),
			dscp:             0,
			expectedOutbound: 2,
			expectedMark:     0,
			expectedMust:     false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outbound, mark, must, err := matcher.Match(
				encodeIPv4Mapped(tc.sourceIP),
				encodeIPv4Mapped(tc.destIP),
				tc.sourcePort,
				tc.destPort,
				consts.IpVersion_4,
				tc.l4proto,
				tc.domain,
				tc.process,
				tc.dscp,
				make([]byte, 16),
			)
			if err != nil {
				t.Fatalf("Match() error = %v", err)
			}
			if outbound != tc.expectedOutbound || mark != tc.expectedMark || must != tc.expectedMust {
				t.Fatalf(
					"Match() = (outbound=%v, mark=%d, must=%v), want (%v, %d, %v)",
					outbound,
					mark,
					must,
					tc.expectedOutbound,
					tc.expectedMark,
					tc.expectedMust,
				)
			}
		})
	}
}
