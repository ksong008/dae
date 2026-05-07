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
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestRustDnsResponseRuntimeDnsNewIntegration(t *testing.T) {
	routing, err := New(&config.Dns{
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
	}, &NewOption{
		Logger: logrus.New(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer routing.Close()

	if routing.rustRouting == nil {
		t.Fatal("expected Rust DNS routing runtime to be installed on Dns")
	}
	if routing.reqMatcher != nil || routing.respMatcher != nil {
		t.Fatalf("expected Go dns matcher shells to be bypassed, got req=%T resp=%T", routing.reqMatcher, routing.respMatcher)
	}

	responseUpstream, _, err := routing.ResponseSelect(&dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{Response: true},
		Question: []dnsmessage.Question{{
			Name:  "example.com.",
			Qtype: uint16(dnsmessage.TypeA),
		}},
	}, nil)
	if err != nil {
		t.Fatalf("ResponseSelect() error = %v", err)
	}
	if responseUpstream != consts.DnsResponseOutboundIndex_Accept {
		t.Fatalf("ResponseSelect() upstream = %v, want accept", responseUpstream)
	}

	decision, err := routing.PlanResponse(&dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{Response: true},
		Question: []dnsmessage.Question{{
			Name:  "example.com.",
			Qtype: uint16(dnsmessage.TypeA),
		}},
	}, nil)
	if err != nil {
		t.Fatalf("PlanResponse() error = %v", err)
	}
	if decision.Kind != DnsResponseDecisionAccept {
		t.Fatalf("PlanResponse() decision = %+v, want accept", decision)
	}
}

func BenchmarkRustDnsRoutingResponseSelectSharedFixture(b *testing.B) {
	routing, err := New(&config.Dns{
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
	}, &NewOption{
		Logger: logrus.New(),
	})
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

func BenchmarkRustDnsRoutingPlanResponseSharedFixture(b *testing.B) {
	routing, err := New(&config.Dns{
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
	}, &NewOption{
		Logger: logrus.New(),
	})
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

func BenchmarkRustDnsResolveResponseChainSharedFixture(b *testing.B) {
	routing, err := New(&config.Dns{
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
	}, &NewOption{
		Logger: logrus.New(),
	})
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

func BenchmarkRustDnsResolveResponseExchangeChainSharedFixture(b *testing.B) {
	routing, err := New(&config.Dns{
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
	}, &NewOption{
		Logger: logrus.New(),
	})
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
