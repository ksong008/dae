/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestDnsPlanResponseRetryDecision(t *testing.T) {
	routing, err := New(&config.Dns{
		Upstream: []config.KeyableString{
			"first:udp://1.1.1.1:53",
			"second:udp://2.2.2.2:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "first",
			},
			Response: config.DnsResponseRouting{
				Rules: []*config_parser.RoutingRule{
					{
						AndFunctions: []*config_parser.Function{
							{
								Name: string(consts.Function_Upstream),
								Params: []*config_parser.Param{
									{Val: "first"},
								},
							},
						},
						Outbound: config_parser.Function{Name: "second"},
					},
				},
				Fallback: "accept",
			},
		},
	}, &NewOption{
		Logger: logrus.New(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer routing.Close()

	firstUpstream := fixedTestUpstreamResolver(t, "udp://1.1.1.1:53", consts.DnsRequestOutboundIndex(0))
	secondUpstream := fixedTestUpstreamResolver(t, "udp://2.2.2.2:53", consts.DnsRequestOutboundIndex(1))
	routing.upstream = []*UpstreamResolver{firstUpstream, secondUpstream}

	decision, err := routing.PlanResponse(&dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{Response: true},
		Question: []dnsmessage.Question{{
			Name:  "example.com.",
			Qtype: uint16(dnsmessage.TypeA),
		}},
	}, firstUpstream.upstream)
	if err != nil {
		t.Fatalf("PlanResponse() error = %v", err)
	}
	if decision.Kind != DnsResponseDecisionRetry {
		t.Fatalf("PlanResponse() kind = %v, want retry", decision.Kind)
	}
	if decision.UpstreamIndex != consts.DnsResponseOutboundIndex(1) {
		t.Fatalf("PlanResponse() upstream index = %v, want 1", decision.UpstreamIndex)
	}
	if decision.Upstream == nil || decision.Upstream.Index != consts.DnsRequestOutboundIndex(1) {
		t.Fatalf("PlanResponse() upstream = %+v, want upstream 1", decision.Upstream)
	}
}

func fixedTestUpstreamResolver(t testing.TB, raw string, index consts.DnsRequestOutboundIndex) *UpstreamResolver {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", raw, err)
	}
	scheme, _, port, path, err := ParseRawUpstream(u)
	if err != nil {
		t.Fatalf("ParseRawUpstream(%q) error = %v", raw, err)
	}
	upstream := &Upstream{
		Scheme:   scheme,
		Hostname: u.Hostname(),
		Port:     port,
		Path:     path,
		Index:    index,
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr(u.Hostname()),
		},
	}
	return &UpstreamResolver{
		Raw:         u,
		Network:     "udp",
		upstream:    upstream,
		init:        true,
		nextRefresh: time.Now().Add(time.Hour),
	}
}
