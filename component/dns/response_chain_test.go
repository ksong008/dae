/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func newTestResponseARecord(qname, ip string) *dnsmessage.A {
	return &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   dnsmessage.CanonicalName(qname),
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP(ip).To4(),
	}
}

func TestDnsResolveResponseChainReroutesUntilAccept(t *testing.T) {
	routing, err := New(&config.Dns{
		Upstream: []config.KeyableString{
			"first:udp://1.1.1.1:53",
			"second:udp://2.2.2.2:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{Fallback: "first"},
			Response: config.DnsResponseRouting{
				Rules: []*config_parser.RoutingRule{
					{
						AndFunctions: []*config_parser.Function{{
							Name: string(consts.Function_Upstream),
							Params: []*config_parser.Param{
								{Val: "first"},
							},
						}},
						Outbound: config_parser.Function{Name: "second"},
					},
				},
				Fallback: "accept",
			},
		},
	}, &NewOption{Logger: logrus.New()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer routing.Close()

	first := fixedTestUpstreamResolver(t, "udp://1.1.1.1:53", consts.DnsRequestOutboundIndex(0))
	second := fixedTestUpstreamResolver(t, "udp://2.2.2.2:53", consts.DnsRequestOutboundIndex(1))
	routing.upstream = []*UpstreamResolver{first, second}

	var forwarded []string
	respMsg, finalUpstream, decision, err := routing.ResolveResponseChain(first.upstream, 0, 3, func(upstream *Upstream) (*dnsmessage.Msg, error) {
		forwarded = append(forwarded, upstream.Hostname)
		switch upstream.Hostname {
		case "1.1.1.1":
			return &dnsmessage.Msg{
				MsgHdr: dnsmessage.MsgHdr{Response: true},
				Question: []dnsmessage.Question{{
					Name:  "example.com.",
					Qtype: uint16(dnsmessage.TypeA),
				}},
				Answer: []dnsmessage.RR{newTestResponseARecord("example.com.", "1.1.1.1")},
			}, nil
		case "2.2.2.2":
			return &dnsmessage.Msg{
				MsgHdr: dnsmessage.MsgHdr{Response: true},
				Question: []dnsmessage.Question{{
					Name:  "example.com.",
					Qtype: uint16(dnsmessage.TypeA),
				}},
				Answer: []dnsmessage.RR{newTestResponseARecord("example.com.", "2.2.2.2")},
			}, nil
		default:
			t.Fatalf("unexpected upstream: %s", upstream.Hostname)
			return nil, nil
		}
	})
	if err != nil {
		t.Fatalf("ResolveResponseChain() error = %v", err)
	}
	if len(forwarded) != 2 || forwarded[0] != "1.1.1.1" || forwarded[1] != "2.2.2.2" {
		t.Fatalf("unexpected forwarded order: %v", forwarded)
	}
	if finalUpstream == nil || finalUpstream.Hostname != "2.2.2.2" {
		t.Fatalf("final upstream = %+v, want second", finalUpstream)
	}
	if decision.Kind != DnsResponseDecisionAccept {
		t.Fatalf("decision = %+v, want accept", decision)
	}
	if len(respMsg.Answer) != 1 {
		t.Fatalf("expected final response answer, got %v", respMsg.Answer)
	}
}

func TestDnsResolveResponseChainStopsAtDepthLimit(t *testing.T) {
	routing, err := New(&config.Dns{
		Upstream: []config.KeyableString{
			"first:udp://1.1.1.1:53",
			"second:udp://2.2.2.2:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{Fallback: "first"},
			Response: config.DnsResponseRouting{
				Rules: []*config_parser.RoutingRule{
					{
						AndFunctions: []*config_parser.Function{{
							Name: string(consts.Function_Upstream),
							Params: []*config_parser.Param{
								{Val: "first"},
							},
						}},
						Outbound: config_parser.Function{Name: "second"},
					},
					{
						AndFunctions: []*config_parser.Function{{
							Name: string(consts.Function_Upstream),
							Params: []*config_parser.Param{
								{Val: "second"},
							},
						}},
						Outbound: config_parser.Function{Name: "first"},
					},
				},
				Fallback: "accept",
			},
		},
	}, &NewOption{Logger: logrus.New()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer routing.Close()

	first := fixedTestUpstreamResolver(t, "udp://1.1.1.1:53", consts.DnsRequestOutboundIndex(0))
	second := fixedTestUpstreamResolver(t, "udp://2.2.2.2:53", consts.DnsRequestOutboundIndex(1))
	routing.upstream = []*UpstreamResolver{first, second}

	attempts := 0
	_, _, _, err = routing.ResolveResponseChain(first.upstream, 0, 3, func(upstream *Upstream) (*dnsmessage.Msg, error) {
		attempts++
		ip := "1.1.1.1"
		if upstream.Hostname == "2.2.2.2" {
			ip = "2.2.2.2"
		}
		return &dnsmessage.Msg{
			MsgHdr: dnsmessage.MsgHdr{Response: true},
			Question: []dnsmessage.Question{{
				Name:  "example.com.",
				Qtype: uint16(dnsmessage.TypeA),
			}},
			Answer: []dnsmessage.RR{newTestResponseARecord("example.com.", ip)},
		}, nil
	})
	if err == nil {
		t.Fatal("expected depth-limit error")
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts before depth stop, got %d", attempts)
	}
}

func TestDnsResolveResponseExchangeChainNormalizesAsIsUpstream(t *testing.T) {
	routing, err := New(&config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: "asis"},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	}, &NewOption{Logger: logrus.New()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer routing.Close()

	req := new(dnsmessage.Msg)
	req.Id = 1234
	req.SetQuestion("example.com.", dnsmessage.TypeA)

	var seen *Upstream
	respMsg, finalUpstream, decision, meta, err := routing.ResolveResponseExchangeChain(
		req,
		nil,
		netip.MustParseAddrPort("8.8.8.8:53"),
		0,
		3,
		func(upstream *Upstream) (*dnsmessage.Msg, DnsExchangeMeta, error) {
			seen = upstream
			resp := new(dnsmessage.Msg)
			resp.SetReply(req)
			resp.Id = req.Id
			resp.Answer = []dnsmessage.RR{newTestResponseARecord("example.com.", "8.8.8.8")}
			return resp, DnsExchangeMeta{
				L4Proto:      consts.L4ProtoStr_UDP,
				UpstreamName: upstream.String(),
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("ResolveResponseExchangeChain() error = %v", err)
	}
	if seen == nil || seen.Hostname != "8.8.8.8" || seen.Port != 53 || seen.Scheme != UpstreamScheme_UDP {
		t.Fatalf("unexpected synthesized as-is upstream: %+v", seen)
	}
	if finalUpstream == nil || finalUpstream.Hostname != "8.8.8.8" {
		t.Fatalf("final upstream = %+v, want synthesized as-is upstream", finalUpstream)
	}
	if decision.Kind != DnsResponseDecisionAccept {
		t.Fatalf("decision = %+v, want accept", decision)
	}
	if meta.UpstreamName == "" || meta.L4Proto != consts.L4ProtoStr_UDP {
		t.Fatalf("unexpected exchange meta: %+v", meta)
	}
	if len(respMsg.Answer) != 1 {
		t.Fatalf("expected final response answer, got %v", respMsg.Answer)
	}
}

func TestDnsResolveResponseExchangeChainRetriesTruncatedTcpUdpOverTcp(t *testing.T) {
	routing, err := New(&config.Dns{
		Upstream: []config.KeyableString{
			"test:tcp+udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{Fallback: "test"},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}, &NewOption{Logger: logrus.New()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer routing.Close()

	upstream := fixedTestUpstreamResolver(t, "tcp+udp://1.1.1.1:53", consts.DnsRequestOutboundIndex(0)).upstream
	req := new(dnsmessage.Msg)
	req.Id = 4321
	req.SetQuestion("example.com.", dnsmessage.TypeA)

	var seenSchemes []UpstreamScheme
	respMsg, finalUpstream, decision, meta, err := routing.ResolveResponseExchangeChain(
		req,
		upstream,
		netip.AddrPort{},
		0,
		3,
		func(current *Upstream) (*dnsmessage.Msg, DnsExchangeMeta, error) {
			seenSchemes = append(seenSchemes, current.Scheme)
			resp := new(dnsmessage.Msg)
			resp.SetReply(req)
			resp.Id = req.Id
			resp.Answer = []dnsmessage.RR{newTestResponseARecord("example.com.", "1.1.1.1")}
			switch current.Scheme {
			case UpstreamScheme_TCP_UDP:
				resp.Truncated = true
				return resp, DnsExchangeMeta{
					L4Proto:      consts.L4ProtoStr_UDP,
					UpstreamName: current.String(),
				}, nil
			case UpstreamScheme_TCP:
				return resp, DnsExchangeMeta{
					L4Proto:      consts.L4ProtoStr_TCP,
					UpstreamName: current.String(),
				}, nil
			default:
				t.Fatalf("unexpected scheme: %v", current.Scheme)
				return nil, DnsExchangeMeta{}, nil
			}
		},
	)
	if err != nil {
		t.Fatalf("ResolveResponseExchangeChain() error = %v", err)
	}
	if len(seenSchemes) != 2 || seenSchemes[0] != UpstreamScheme_TCP_UDP || seenSchemes[1] != UpstreamScheme_TCP {
		t.Fatalf("unexpected exchange scheme sequence: %v", seenSchemes)
	}
	if finalUpstream == nil || finalUpstream.Scheme != UpstreamScheme_TCP_UDP {
		t.Fatalf("final upstream = %+v, want policy upstream tcp+udp", finalUpstream)
	}
	if decision.Kind != DnsResponseDecisionAccept {
		t.Fatalf("decision = %+v, want accept", decision)
	}
	if !meta.RetriedOverTCP || meta.L4Proto != consts.L4ProtoStr_TCP {
		t.Fatalf("unexpected exchange meta after truncated retry: %+v", meta)
	}
	if len(respMsg.Answer) != 1 {
		t.Fatalf("expected final response answer, got %v", respMsg.Answer)
	}
}
