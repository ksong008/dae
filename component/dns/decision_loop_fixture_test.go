/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/trie"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type dnsFixtureAction struct {
	Kind  string `json:"kind"`
	Value uint8  `json:"value"`
}

type dnsFixtureCondition struct {
	Kind     string   `json:"kind"`
	Values   []uint16 `json:"values"`
	Not      bool     `json:"not"`
	SetIndex int      `json:"set_index"`
}

type dnsFixtureRequestRule struct {
	Conditions []dnsFixtureCondition `json:"conditions"`
	Action     dnsFixtureAction      `json:"action"`
}

type dnsFixtureRequestCase struct {
	Name     string           `json:"name"`
	QName    string           `json:"qname"`
	QType    uint16           `json:"qtype"`
	Expected dnsFixtureAction `json:"expected"`
}

type dnsFixtureRequest struct {
	DomainHits map[string][]uint32     `json:"domain_hits"`
	Rules      []dnsFixtureRequestRule `json:"rules"`
	Cases      []dnsFixtureRequestCase `json:"cases"`
}

type dnsFixtureResponseCondition struct {
	Kind        string   `json:"kind"`
	QTypeValues []uint16 `json:"qtype_values"`
	Values      []int16  `json:"values"`
	BitIndex    int      `json:"bit_index"`
	SetIndex    int      `json:"set_index"`
	Not         bool     `json:"not"`
}

type dnsFixtureResponseRule struct {
	Conditions []dnsFixtureResponseCondition `json:"conditions"`
	Action     dnsFixtureAction              `json:"action"`
}

type dnsFixtureResponseCase struct {
	Name            string           `json:"name"`
	QName           string           `json:"qname"`
	QType           uint16           `json:"qtype"`
	IPs             []string         `json:"ips"`
	RequestUpstream int16            `json:"request_upstream"`
	Expected        dnsFixtureAction `json:"expected"`
}

type dnsFixtureResponse struct {
	DomainHits map[string][]uint32      `json:"domain_hits"`
	IPSets     [][]string               `json:"ip_sets"`
	Rules      []dnsFixtureResponseRule `json:"rules"`
	Cases      []dnsFixtureResponseCase `json:"cases"`
}

func (f dnsFixtureResponse) IPSetsToPrefixes(t testing.TB) [][]netip.Prefix {
	t.Helper()

	out := make([][]netip.Prefix, 0, len(f.IPSets))
	for _, group := range f.IPSets {
		prefixes := make([]netip.Prefix, 0, len(group))
		for _, prefix := range group {
			prefixes = append(prefixes, netip.MustParsePrefix(prefix))
		}
		out = append(out, prefixes)
	}
	return out
}

func TestRequestMatcherSharedFixtureSemantics(t *testing.T) {
	fixture := loadDNSRequestFixture(t, "dns_request_semantics.json")
	domainMatcher := &fixedDnsRequestDomainMatcher{bitmapByDomain: fixture.DomainHits}
	matcher := &RequestMatcher{
		domainMatcher:    domainMatcher,
		domainBitmapPool: routing.NewDomainBitmapPool(domainMatcher, 32),
		matches:          buildRequestMatchSets(t, fixture.Rules),
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

func TestResponseMatcherSharedFixtureSemantics(t *testing.T) {
	fixture := loadDNSResponseFixture(t, "dns_response_semantics.json")
	domainMatcher := &fixedDnsRequestDomainMatcher{bitmapByDomain: fixture.DomainHits}
	matcher := &ResponseMatcher{
		domainMatcher:    domainMatcher,
		domainBitmapPool: routing.NewDomainBitmapPool(domainMatcher, 32),
		ipSet:            buildDNSIPSets(t, fixture.IPSets),
		matches:          buildResponseMatchSets(t, fixture.Rules),
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

func BenchmarkRequestMatcherSharedFixture(b *testing.B) {
	fixture := loadDNSRequestFixture(b, "dns_request_semantics.json")
	domainMatcher := &fixedDnsRequestDomainMatcher{bitmapByDomain: fixture.DomainHits}
	matcher := &RequestMatcher{
		domainMatcher:    domainMatcher,
		domainBitmapPool: routing.NewDomainBitmapPool(domainMatcher, 32),
		matches:          buildRequestMatchSets(b, fixture.Rules),
	}

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

func BenchmarkResponseMatcherSharedFixture(b *testing.B) {
	fixture := loadDNSResponseFixture(b, "dns_response_semantics.json")
	domainMatcher := &fixedDnsRequestDomainMatcher{bitmapByDomain: fixture.DomainHits}
	matcher := &ResponseMatcher{
		domainMatcher:    domainMatcher,
		domainBitmapPool: routing.NewDomainBitmapPool(domainMatcher, 32),
		ipSet:            buildDNSIPSets(b, fixture.IPSets),
		matches:          buildResponseMatchSets(b, fixture.Rules),
	}

	cases := make([]struct {
		name            string
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
			name            string
			qname           string
			qtype           uint16
			ips             []netip.Addr
			requestUpstream consts.DnsRequestOutboundIndex
			expected        consts.DnsResponseOutboundIndex
		}{
			name:            tc.Name,
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

func BenchmarkDnsRequestSelectSharedFixture(b *testing.B) {
	routingConfig := &config.Dns{
		Upstream: []config.KeyableString{
			"test:udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "test",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}
	routing, err := New(routingConfig, &NewOption{Logger: logrus.New()})
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer routing.Close()
	qname := "example.com."
	qtype := uint16(dnsmessage.TypeA)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		upstream, _, err := routing.RequestSelect(qname, qtype)
		if err != nil {
			b.Fatalf("RequestSelect() error = %v", err)
		}
		if upstream != 0 {
			b.Fatalf("RequestSelect() upstream = %v, want 0", upstream)
		}
	}
}

func BenchmarkDnsPlanRequestSharedFixture(b *testing.B) {
	routingConfig := &config.Dns{
		Upstream: []config.KeyableString{
			"test:udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "test",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}
	routing, err := New(routingConfig, &NewOption{
		Logger:             logrus.New(),
		RequestQTypePrefer: uint16(dnsmessage.TypeAAAA),
	})
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer routing.Close()
	qname := "example.com."
	qtype := uint16(dnsmessage.TypeA)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plan, err := routing.PlanRequest(qname, qtype)
		if err != nil {
			b.Fatalf("PlanRequest() error = %v", err)
		}
		if plan.Requested.UpstreamIndex != 0 {
			b.Fatalf("PlanRequest() requested upstream = %v, want 0", plan.Requested.UpstreamIndex)
		}
		if plan.Preferred == nil || plan.Preferred.UpstreamIndex != 0 {
			b.Fatalf("PlanRequest() preferred plan = %+v, want upstream 0", plan.Preferred)
		}
	}
}

func BenchmarkDnsResponseSelectSharedFixture(b *testing.B) {
	routingConfig := &config.Dns{
		Upstream: []config.KeyableString{
			"test:udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "test",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}
	routing, err := New(routingConfig, &NewOption{Logger: logrus.New()})
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer routing.Close()
	msg := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{Response: true},
		Question: []dnsmessage.Question{{
			Name:  "example.com.",
			Qtype: uint16(dnsmessage.TypeA),
		}},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		upstream, _, err := routing.ResponseSelect(msg, nil)
		if err != nil {
			b.Fatalf("ResponseSelect() error = %v", err)
		}
		if upstream != consts.DnsResponseOutboundIndex_Accept {
			b.Fatalf("ResponseSelect() upstream = %v, want accept", upstream)
		}
	}
}

func BenchmarkDnsPlanResponseSharedFixture(b *testing.B) {
	routingConfig := &config.Dns{
		Upstream: []config.KeyableString{
			"test:udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "test",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}
	routing, err := New(routingConfig, &NewOption{Logger: logrus.New()})
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer routing.Close()
	msg := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{Response: true},
		Question: []dnsmessage.Question{{
			Name:  "example.com.",
			Qtype: uint16(dnsmessage.TypeA),
		}},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision, err := routing.PlanResponse(msg, nil)
		if err != nil {
			b.Fatalf("PlanResponse() error = %v", err)
		}
		if decision.Kind != DnsResponseDecisionAccept {
			b.Fatalf("PlanResponse() decision = %+v, want accept", decision)
		}
	}
}

func BenchmarkDnsResolveResponseChainSharedFixture(b *testing.B) {
	routingConfig := &config.Dns{
		Upstream: []config.KeyableString{
			"test:udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "test",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}
	routing, err := New(routingConfig, &NewOption{Logger: logrus.New()})
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer routing.Close()
	upstream := &Upstream{
		Scheme:   UpstreamScheme_UDP,
		Hostname: "1.1.1.1",
		Port:     53,
		Index:    consts.DnsRequestOutboundIndex(0),
		Ip46:     &netutils.Ip46{Ip4: netip.MustParseAddr("1.1.1.1")},
	}
	msg := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{Response: true},
		Question: []dnsmessage.Question{{
			Name:  "example.com.",
			Qtype: uint16(dnsmessage.TypeA),
		}},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, decision, err := routing.ResolveResponseChain(upstream, 0, 3, func(*Upstream) (*dnsmessage.Msg, error) {
			return msg, nil
		})
		if err != nil {
			b.Fatalf("ResolveResponseChain() error = %v", err)
		}
		if decision.Kind != DnsResponseDecisionAccept {
			b.Fatalf("ResolveResponseChain() decision = %+v, want accept", decision)
		}
	}
}

func BenchmarkDnsResolveResponseExchangeChainSharedFixture(b *testing.B) {
	routingConfig := &config.Dns{
		Upstream: []config.KeyableString{
			"test:tcp+udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "test",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}
	routing, err := New(routingConfig, &NewOption{Logger: logrus.New()})
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer routing.Close()
	upstream := &Upstream{
		Scheme:   UpstreamScheme_TCP_UDP,
		Hostname: "1.1.1.1",
		Port:     53,
		Index:    consts.DnsRequestOutboundIndex(0),
		Ip46:     &netutils.Ip46{Ip4: netip.MustParseAddr("1.1.1.1")},
	}
	req := new(dnsmessage.Msg)
	req.Id = 1234
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	udpResp := new(dnsmessage.Msg)
	udpResp.SetReply(req)
	udpResp.Id = req.Id
	udpResp.Truncated = true
	udpResp.Answer = []dnsmessage.RR{newTestResponseARecord("example.com.", "1.1.1.1")}
	tcpResp := new(dnsmessage.Msg)
	tcpResp.SetReply(req)
	tcpResp.Id = req.Id
	tcpResp.Answer = []dnsmessage.RR{newTestResponseARecord("example.com.", "1.1.1.1")}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, decision, meta, err := routing.ResolveResponseExchangeChain(req, upstream, netip.AddrPort{}, 0, 3, func(current *Upstream) (*dnsmessage.Msg, DnsExchangeMeta, error) {
			if current.Scheme == UpstreamScheme_TCP_UDP {
				return udpResp, DnsExchangeMeta{L4Proto: consts.L4ProtoStr_UDP, UpstreamName: current.String()}, nil
			}
			return tcpResp, DnsExchangeMeta{L4Proto: consts.L4ProtoStr_TCP, UpstreamName: current.String()}, nil
		})
		if err != nil {
			b.Fatalf("ResolveResponseExchangeChain() error = %v", err)
		}
		if decision.Kind != DnsResponseDecisionAccept {
			b.Fatalf("ResolveResponseExchangeChain() decision = %+v, want accept", decision)
		}
		if !meta.RetriedOverTCP {
			b.Fatalf("ResolveResponseExchangeChain() meta = %+v, want retried over tcp", meta)
		}
	}
}

func buildRequestMatchSets(t testing.TB, rules []dnsFixtureRequestRule) []requestMatchSet {
	t.Helper()

	var out []requestMatchSet
	for _, rule := range rules {
		for i, condition := range rule.Conditions {
			terminal := uint8(consts.DnsRequestOutboundIndex_LogicalAnd)
			if i == len(rule.Conditions)-1 {
				terminal = uint8(requestActionToIndex(t, rule.Action))
			}
			out = append(out, flattenRequestCondition(t, condition, terminal)...)
		}
	}
	return out
}

func flattenRequestCondition(t testing.TB, condition dnsFixtureCondition, terminal uint8) []requestMatchSet {
	t.Helper()

	switch condition.Kind {
	case "domain_bit":
		return []requestMatchSet{{
			Type:     consts.MatchType_DomainSet,
			Not:      condition.Not,
			Upstream: terminal,
		}}
	case "qtype_any":
		out := make([]requestMatchSet, 0, len(condition.Values))
		for i, value := range condition.Values {
			upstream := uint8(consts.DnsRequestOutboundIndex_LogicalOr)
			if i == len(condition.Values)-1 {
				upstream = terminal
			}
			out = append(out, requestMatchSet{
				Type:     consts.MatchType_QType,
				Value:    value,
				Not:      condition.Not,
				Upstream: upstream,
			})
		}
		return out
	case "fallback":
		return []requestMatchSet{{
			Type:     consts.MatchType_Fallback,
			Upstream: terminal,
		}}
	default:
		t.Fatalf("unknown request condition kind: %s", condition.Kind)
		return nil
	}
}

func buildResponseMatchSets(t testing.TB, rules []dnsFixtureResponseRule) []responseMatchSet {
	t.Helper()

	var out []responseMatchSet
	for _, rule := range rules {
		for i, condition := range rule.Conditions {
			terminal := uint8(consts.DnsResponseOutboundIndex_LogicalAnd)
			if i == len(rule.Conditions)-1 {
				terminal = uint8(responseActionToIndex(t, rule.Action))
			}
			out = append(out, flattenResponseCondition(t, condition, terminal)...)
		}
	}
	return out
}

func flattenResponseCondition(t testing.TB, condition dnsFixtureResponseCondition, terminal uint8) []responseMatchSet {
	t.Helper()

	switch condition.Kind {
	case "domain_bit":
		return []responseMatchSet{{
			Type:     consts.MatchType_DomainSet,
			Not:      condition.Not,
			Upstream: terminal,
		}}
	case "qtype_any":
		out := make([]responseMatchSet, 0, len(condition.QTypeValues))
		for i, value := range condition.QTypeValues {
			upstream := uint8(consts.DnsResponseOutboundIndex_LogicalOr)
			if i == len(condition.QTypeValues)-1 {
				upstream = terminal
			}
			out = append(out, responseMatchSet{
				Type:     consts.MatchType_QType,
				Value:    value,
				Not:      condition.Not,
				Upstream: upstream,
			})
		}
		return out
	case "upstream_any":
		out := make([]responseMatchSet, 0, len(condition.Values))
		for i, value := range condition.Values {
			upstream := uint8(consts.DnsResponseOutboundIndex_LogicalOr)
			if i == len(condition.Values)-1 {
				upstream = terminal
			}
			out = append(out, responseMatchSet{
				Type:     consts.MatchType_Upstream,
				Value:    uint16(value),
				Not:      condition.Not,
				Upstream: upstream,
			})
		}
		return out
	case "ip_in_set":
		return []responseMatchSet{{
			Type:     consts.MatchType_IpSet,
			Value:    uint16(condition.SetIndex),
			Not:      condition.Not,
			Upstream: terminal,
		}}
	case "fallback":
		return []responseMatchSet{{
			Type:     consts.MatchType_Fallback,
			Upstream: terminal,
		}}
	default:
		t.Fatalf("unknown response condition kind: %s", condition.Kind)
		return nil
	}
}

func requestActionToIndex(t testing.TB, action dnsFixtureAction) consts.DnsRequestOutboundIndex {
	t.Helper()

	switch action.Kind {
	case "user_defined":
		return consts.DnsRequestOutboundIndex(action.Value)
	case "reject":
		return consts.DnsRequestOutboundIndex_Reject
	case "asis":
		return consts.DnsRequestOutboundIndex_AsIs
	default:
		t.Fatalf("unknown request action kind: %s", action.Kind)
		return 0
	}
}

func responseActionToIndex(t testing.TB, action dnsFixtureAction) consts.DnsResponseOutboundIndex {
	t.Helper()

	switch action.Kind {
	case "user_defined":
		return consts.DnsResponseOutboundIndex(action.Value)
	case "reject":
		return consts.DnsResponseOutboundIndex_Reject
	case "accept":
		return consts.DnsResponseOutboundIndex_Accept
	default:
		t.Fatalf("unknown response action kind: %s", action.Kind)
		return 0
	}
}

func buildDNSIPSets(t testing.TB, raw [][]string) []*trie.Trie {
	t.Helper()

	out := make([]*trie.Trie, 0, len(raw))
	for _, prefixes := range raw {
		parsed := make([]netip.Prefix, 0, len(prefixes))
		for _, prefix := range prefixes {
			parsed = append(parsed, netip.MustParsePrefix(prefix))
		}
		ipTrie, err := trie.NewTrieFromPrefixes(parsed)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ipTrie)
	}
	return out
}

func loadDNSRequestFixture(t testing.TB, name string) dnsFixtureRequest {
	t.Helper()
	var fixture dnsFixtureRequest
	loadDNSFixture(t, name, &fixture)
	return fixture
}

func loadDNSResponseFixture(t testing.TB, name string) dnsFixtureResponse {
	t.Helper()
	var fixture dnsFixtureResponse
	loadDNSFixture(t, name, &fixture)
	return fixture
}

func loadDNSFixture(t testing.TB, name string, target any) {
	t.Helper()

	path := filepath.Join("..", "..", "rust", "crates", "dae-domain-matcher", "fixtures", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}
