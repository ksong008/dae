/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/trie"
)

type routingFixtureCondition struct {
	Kind    string    `json:"kind"`
	BitIndex int      `json:"bit_index"`
	SetKind string    `json:"set_kind"`
	SetIndex int      `json:"set_index"`
	Ranges  [][2]uint16 `json:"ranges"`
	Values  []uint8   `json:"values"`
	Mask    uint8     `json:"mask"`
	Names   []string  `json:"names"`
	Not     bool      `json:"not"`
}

type routingFixtureAction struct {
	Kind     string `json:"kind"`
	Outbound uint8  `json:"outbound"`
	Mark     uint32 `json:"mark"`
	Must     bool   `json:"must"`
}

type routingFixtureRule struct {
	Conditions []routingFixtureCondition `json:"conditions"`
	Action     routingFixtureAction      `json:"action"`
}

type routingFixtureSets struct {
	DestIP   [][]string `json:"dest_ip"`
	SourceIP [][]string `json:"source_ip"`
	Mac      [][]string `json:"mac"`
}

type routingFixtureCaseExpected struct {
	Outbound uint8  `json:"outbound"`
	Mark     uint32 `json:"mark"`
	Must     bool   `json:"must"`
}

type routingFixtureCase struct {
	Name       string                   `json:"name"`
	SourceIP   string                   `json:"source_ip"`
	DestIP     string                   `json:"dest_ip"`
	SourcePort uint16                   `json:"source_port"`
	DestPort   uint16                   `json:"dest_port"`
	IPVersion  uint8                    `json:"ip_version"`
	L4Proto    uint8                    `json:"l4proto"`
	Domain     string                   `json:"domain"`
	ProcessName string                  `json:"process_name"`
	Dscp       uint8                    `json:"dscp"`
	Mac        string                   `json:"mac"`
	Expected   routingFixtureCaseExpected `json:"expected"`
}

type routingFixture struct {
	DomainHits map[string][]uint32 `json:"domain_hits"`
	Sets       routingFixtureSets  `json:"sets"`
	Rules      []routingFixtureRule `json:"rules"`
	Cases      []routingFixtureCase `json:"cases"`
}

func TestRoutingMatcherUserspaceSharedFixtureSemantics(t *testing.T) {
	fixture := loadRoutingFixture(t)
	domainMatcher := &fixedRoutingDomainMatcher{bitmapByDomain: fixture.DomainHits}
	matcher := &RoutingMatcher{
		lpmMatcher:       buildRoutingLpmMatchers(t, fixture.Sets),
		domainMatcher:    domainMatcher,
		domainBitmapPool: routing.NewDomainBitmapPool(domainMatcher, consts.MaxMatchSetLen),
		matches:          buildRoutingMatchSets(t, fixture.Rules),
	}

	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			outbound, mark, must, err := matcher.Match(
				encodeIPv4Mapped(tc.SourceIP),
				encodeIPv4Mapped(tc.DestIP),
				tc.SourcePort,
				tc.DestPort,
				consts.IpVersionType(tc.IPVersion),
				consts.L4ProtoType(tc.L4Proto),
				tc.Domain,
				processName16(tc.ProcessName),
				tc.Dscp,
				encodeMac16(tc.Mac),
			)
			if err != nil {
				t.Fatalf("Match() error = %v", err)
			}
			if outbound != consts.OutboundIndex(tc.Expected.Outbound) || mark != tc.Expected.Mark || must != tc.Expected.Must {
				t.Fatalf(
					"Match() = (outbound=%v, mark=%d, must=%v), want (%v, %d, %v)",
					outbound,
					mark,
					must,
					consts.OutboundIndex(tc.Expected.Outbound),
					tc.Expected.Mark,
					tc.Expected.Must,
				)
			}
		})
	}
}

func BenchmarkRoutingMatcherUserspaceSharedFixture(b *testing.B) {
	fixture := loadRoutingFixture(b)
	domainMatcher := &fixedRoutingDomainMatcher{bitmapByDomain: fixture.DomainHits}
	matcher := &RoutingMatcher{
		lpmMatcher:       buildRoutingLpmMatchers(b, fixture.Sets),
		domainMatcher:    domainMatcher,
		domainBitmapPool: routing.NewDomainBitmapPool(domainMatcher, consts.MaxMatchSetLen),
		matches:          buildRoutingMatchSets(b, fixture.Rules),
	}

	type benchmarkCase struct {
		sourceAddr []byte
		destAddr   []byte
		sourcePort uint16
		destPort   uint16
		ipVersion  consts.IpVersionType
		l4proto    consts.L4ProtoType
		domain     string
		process    [16]uint8
		dscp       uint8
		expectedOutbound consts.OutboundIndex
		expectedMark     uint32
		expectedMust     bool
	}
	cases := make([]benchmarkCase, 0, len(fixture.Cases))
	for _, tc := range fixture.Cases {
		cases = append(cases, benchmarkCase{
			sourceAddr: encodeIPv4Mapped(tc.SourceIP),
			destAddr:   encodeIPv4Mapped(tc.DestIP),
			sourcePort: tc.SourcePort,
			destPort:   tc.DestPort,
			ipVersion:  consts.IpVersionType(tc.IPVersion),
			l4proto:    consts.L4ProtoType(tc.L4Proto),
			domain:     tc.Domain,
			process:    processName16(tc.ProcessName),
			dscp:       tc.Dscp,
			expectedOutbound: consts.OutboundIndex(tc.Expected.Outbound),
			expectedMark:     tc.Expected.Mark,
			expectedMust:     tc.Expected.Must,
		})
	}

	mac := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			outbound, mark, must, err := matcher.Match(
				tc.sourceAddr,
				tc.destAddr,
				tc.sourcePort,
				tc.destPort,
				tc.ipVersion,
				tc.l4proto,
				tc.domain,
				tc.process,
				tc.dscp,
				mac,
			)
			if err != nil {
				b.Fatalf("Match() error = %v", err)
			}
			if outbound != tc.expectedOutbound || mark != tc.expectedMark || must != tc.expectedMust {
				b.Fatalf(
					"Match() = (outbound=%v, mark=%d, must=%v), want (%v, %d, %v)",
					outbound,
					mark,
					must,
					tc.expectedOutbound,
					tc.expectedMark,
					tc.expectedMust,
				)
			}
		}
	}
}

func BenchmarkControlPlaneRouteSharedFixture(b *testing.B) {
	fixture := loadRoutingFixture(b)
	domainMatcher := &fixedRoutingDomainMatcher{bitmapByDomain: fixture.DomainHits}
	matcher := &RoutingMatcher{
		lpmMatcher:       buildRoutingLpmMatchers(b, fixture.Sets),
		domainMatcher:    domainMatcher,
		domainBitmapPool: routing.NewDomainBitmapPool(domainMatcher, consts.MaxMatchSetLen),
		matches:          buildRoutingMatchSets(b, fixture.Rules),
	}
	plane := &ControlPlane{routingMatcher: matcher}

	type benchmarkCase struct {
		src      netip.AddrPort
		dst      netip.AddrPort
		domain   string
		l4proto  consts.L4ProtoType
		result   *bpfRoutingResult
		expectedOutbound consts.OutboundIndex
		expectedMark     uint32
		expectedMust     bool
	}
	cases := make([]benchmarkCase, 0, len(fixture.Cases))
	for _, tc := range fixture.Cases {
		var mac [6]uint8
		cases = append(cases, benchmarkCase{
			src:     netip.MustParseAddrPort(tc.SourceIP + ":" + itoaPort(tc.SourcePort)),
			dst:     netip.MustParseAddrPort(tc.DestIP + ":" + itoaPort(tc.DestPort)),
			domain:  tc.Domain,
			l4proto: consts.L4ProtoType(tc.L4Proto),
			result: &bpfRoutingResult{
				Pname: processName16(tc.ProcessName),
				Dscp:  tc.Dscp,
				Mac:   mac,
			},
			expectedOutbound: consts.OutboundIndex(tc.Expected.Outbound),
			expectedMark:     tc.Expected.Mark,
			expectedMust:     false,
		})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			outbound, mark, must, err := plane.Route(tc.src, tc.dst, tc.domain, tc.l4proto, tc.result)
			if err != nil {
				b.Fatalf("Route() error = %v", err)
			}
			if outbound != tc.expectedOutbound || mark != tc.expectedMark || must != tc.expectedMust {
				b.Fatalf(
					"Route() = (outbound=%v, mark=%d, must=%v), want (%v, %d, %v)",
					outbound,
					mark,
					must,
					tc.expectedOutbound,
					tc.expectedMark,
					tc.expectedMust,
				)
			}
		}
	}
}

func buildRoutingMatchSets(t testing.TB, rules []routingFixtureRule) []bpfMatchSet {
	t.Helper()

	var out []bpfMatchSet
	for _, rule := range rules {
		for i, condition := range rule.Conditions {
			terminalOutbound := uint8(consts.OutboundLogicalAnd)
			terminalMark := uint32(0)
			terminalMust := false
			if i == len(rule.Conditions)-1 {
				if rule.Action.Kind == "continue_must" {
					terminalOutbound = uint8(consts.OutboundMustRules)
				} else {
					terminalOutbound = rule.Action.Outbound
					terminalMark = rule.Action.Mark
					terminalMust = rule.Action.Must
				}
			}
			out = append(out, flattenRoutingCondition(t, condition, terminalOutbound, terminalMark, terminalMust)...)
		}
	}
	return out
}

func flattenRoutingCondition(
	t testing.TB,
	condition routingFixtureCondition,
	terminalOutbound uint8,
	terminalMark uint32,
	terminalMust bool,
) []bpfMatchSet {
	t.Helper()

	makeSet := func(typ consts.MatchType) bpfMatchSet {
		return bpfMatchSet{
			Type:     uint8(typ),
			Not:      condition.Not,
			Outbound: terminalOutbound,
			Mark:     terminalMark,
			Must:     terminalMust,
		}
	}

	switch condition.Kind {
	case "domain_bit":
		return []bpfMatchSet{makeSet(consts.MatchType_DomainSet)}
	case "set_any":
		set := makeSet(consts.MatchType_IpSet)
		switch condition.SetKind {
		case "dest_ip":
			set.Type = uint8(consts.MatchType_IpSet)
		case "source_ip":
			set.Type = uint8(consts.MatchType_SourceIpSet)
		case "mac":
			set.Type = uint8(consts.MatchType_Mac)
		default:
			t.Fatalf("unknown set kind: %s", condition.SetKind)
		}
		binary.LittleEndian.PutUint32(set.Value[:], uint32(condition.SetIndex))
		return []bpfMatchSet{set}
	case "dest_port_any":
		out := make([]bpfMatchSet, 0, len(condition.Ranges))
		for i, value := range condition.Ranges {
			set := makeSet(consts.MatchType_Port)
			if i != len(condition.Ranges)-1 {
				set.Outbound = uint8(consts.OutboundLogicalOr)
				set.Mark = 0
				set.Must = false
			}
			set.Value = (_bpfPortRange{PortStart: value[0], PortEnd: value[1]}).Encode()
			out = append(out, set)
		}
		return out
	case "source_port_any":
		out := make([]bpfMatchSet, 0, len(condition.Ranges))
		for i, value := range condition.Ranges {
			set := makeSet(consts.MatchType_SourcePort)
			if i != len(condition.Ranges)-1 {
				set.Outbound = uint8(consts.OutboundLogicalOr)
				set.Mark = 0
				set.Must = false
			}
			set.Value = (_bpfPortRange{PortStart: value[0], PortEnd: value[1]}).Encode()
			out = append(out, set)
		}
		return out
	case "l4proto_mask":
		set := makeSet(consts.MatchType_L4Proto)
		set.Value[0] = condition.Mask
		return []bpfMatchSet{set}
	case "ip_version_mask":
		set := makeSet(consts.MatchType_IpVersion)
		set.Value[0] = condition.Mask
		return []bpfMatchSet{set}
	case "process_name_any":
		out := make([]bpfMatchSet, 0, len(condition.Names))
		for i, name := range condition.Names {
			set := makeSet(consts.MatchType_ProcessName)
			if i != len(condition.Names)-1 {
				set.Outbound = uint8(consts.OutboundLogicalOr)
				set.Mark = 0
				set.Must = false
			}
			pname := processName16(name)
			copy(set.Value[:], pname[:])
			out = append(out, set)
		}
		return out
	case "dscp_any":
		out := make([]bpfMatchSet, 0, len(condition.Values))
		for i, value := range condition.Values {
			set := makeSet(consts.MatchType_Dscp)
			if i != len(condition.Values)-1 {
				set.Outbound = uint8(consts.OutboundLogicalOr)
				set.Mark = 0
				set.Must = false
			}
			set.Value[0] = value
			out = append(out, set)
		}
		return out
	case "fallback":
		return []bpfMatchSet{makeSet(consts.MatchType_Fallback)}
	default:
		t.Fatalf("unknown routing condition kind: %s", condition.Kind)
		return nil
	}
}

func buildRoutingLpmMatchers(t testing.TB, sets routingFixtureSets) []*trie.Trie {
	t.Helper()

	var out []*trie.Trie
	for _, group := range sets.DestIP {
		out = append(out, buildRoutingTrie(t, group))
	}
	for _, group := range sets.SourceIP {
		out = append(out, buildRoutingTrie(t, group))
	}
	for range sets.Mac {
		// current shared fixture does not need MAC sets; keep index layout stable by not allocating extra tries
	}
	return out
}

func buildRoutingTrie(t testing.TB, prefixes []string) *trie.Trie {
	t.Helper()

	parsed := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		parsed = append(parsed, netip.MustParsePrefix(prefix))
	}
	ipTrie, err := trie.NewTrieFromPrefixes(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return ipTrie
}

func loadRoutingFixture(t testing.TB) routingFixture {
	t.Helper()

	path := filepath.Join("..", "rust", "crates", "dae-domain-matcher", "fixtures", "routing_userspace_semantics.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture routingFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func encodeMac16(raw string) []byte {
	var out [16]byte
	return out[:]
}

func itoaPort(port uint16) string {
	return strconv.FormatUint(uint64(port), 10)
}
