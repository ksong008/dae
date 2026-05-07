//go:build rust_dns_request_matcher && rust_userspace_routing && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	outboundpkg "github.com/daeuniverse/dae/component/outbound"
	outbounddialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type recordingNetproxyDialer struct {
	conn    netproxy.Conn
	network string
	address string
}

func (d *recordingNetproxyDialer) DialContext(_ context.Context, network string, address string) (netproxy.Conn, error) {
	d.network = network
	d.address = address
	return d.conn, nil
}

type rustCombinedRuntimeHarness struct {
	plane           *ControlPlane
	controller      *DnsController
	matcher         *RoutingMatcher
	recordingDialer *recordingNetproxyDialer
	group           *outboundpkg.DialerGroup
	left            net.Conn
	right           net.Conn
}

func newRustCombinedRuntimeHarness(tb testing.TB) *rustCombinedRuntimeHarness {
	tb.Helper()
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	routing, err := componentdns.New(&config.Dns{
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
	}, &componentdns.NewOption{
		Logger: logger,
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	if err != nil {
		tb.Fatalf("dns.New() error = %v", err)
	}

	controller, err := NewDnsController(routing, &DnsControllerOption{
		Log:                 logger,
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) {
			return &dialArgument{l4proto: consts.L4ProtoStr_UDP}, nil
		},
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		tb.Fatalf("NewDnsController() error = %v", err)
	}
	controller.forwarderFactory = func(*componentdns.Upstream, dialArgument) (DnsForwarder, error) {
		return &fakeDnsForwarder{
			forward: func(_ context.Context, data []byte) (*dnsmessage.Msg, error) {
				req := new(dnsmessage.Msg)
				if err := req.Unpack(data); err != nil {
					return nil, err
				}
				resp := new(dnsmessage.Msg)
				resp.SetReply(req)
				switch req.Question[0].Qtype {
				case dnsmessage.TypeA:
					resp.Answer = []dnsmessage.RR{newTestARecord("example.com.", "1.1.1.1")}
				case dnsmessage.TypeAAAA:
					resp.Answer = []dnsmessage.RR{newTestAAAARecord("example.com.", "2001:db8::1")}
				}
				return resp, nil
			},
		}, nil
	}

	builder, err := NewRoutingMatcherBuilder(
		logger,
		[]*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{
					{
						Name: consts.Function_Domain,
						Params: []*config_parser.Param{
							{Key: string(consts.RoutingDomainKey_Full), Val: "example.com"},
						},
					},
				},
				Outbound: config_parser.Function{Name: "proxy"},
			},
		},
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
			"proxy":                        uint8(consts.OutboundUserDefinedMin),
		},
		nil,
		config.FunctionOrString(consts.OutboundDirect.String()),
	)
	if err != nil {
		tb.Fatalf("NewRoutingMatcherBuilder() error = %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		tb.Fatalf("BuildUserspace() error = %v", err)
	}
	if matcher.rustMatcher == nil {
		tb.Fatal("expected Rust userspace routing runtime to be installed")
	}

	left, right := net.Pipe()
	recordingDialer := &recordingNetproxyDialer{conn: left}
	dialerOption := &outbounddialer.GlobalOption{Log: logger}
	d := outbounddialer.NewDialer(recordingDialer, dialerOption, outbounddialer.InstanceOption{DisableCheck: true}, &outbounddialer.Property{})
	group := outboundpkg.NewDialerGroup(
		dialerOption,
		"proxy",
		[]*outbounddialer.Dialer{d},
		[]*outbounddialer.Annotation{{}},
		outboundpkg.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *outbounddialer.NetworkType, bool) {},
	)

	outbounds := make([]*outboundpkg.DialerGroup, int(consts.OutboundUserDefinedMin)+1)
	outbounds[consts.OutboundUserDefinedMin] = group

	plane := &ControlPlane{
		log:             logger,
		dns:             &dnsService{controller: controller},
		routingMatcher:  matcher,
		dialMode:        consts.DialMode_Domain,
		realDomainCache: make(map[string]realDomainCacheEntry),
		outbounds:       outbounds,
	}

	return &rustCombinedRuntimeHarness{
		plane:           plane,
		controller:      controller,
		matcher:         matcher,
		recordingDialer: recordingDialer,
		group:           group,
		left:            left,
		right:           right,
	}
}

func (h *rustCombinedRuntimeHarness) Close() {
	if h.group != nil {
		_ = h.group.Close()
	}
	if h.left != nil {
		_ = h.left.Close()
	}
	if h.right != nil {
		_ = h.right.Close()
	}
	if h.matcher != nil {
		h.matcher.Close()
	}
	if h.controller != nil {
		_ = h.controller.Close()
	}
}

func TestRustControlPlaneCombinedDnsAndRoutingIntegration(t *testing.T) {
	h := newRustCombinedRuntimeHarness(t)
	defer h.Close()

	ip46, err4, err6 := h.controller.ResolveIp46ForPacket(
		context.Background(),
		netip.MustParseAddrPort("192.0.2.10:12345"),
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("192.0.2.10:12345"),
		&bpfRoutingResult{},
		"example.com",
	)
	if err4 != nil || err6 != nil {
		t.Fatalf("ResolveIp46ForPacket() errors = (%v, %v)", err4, err6)
	}
	if !ip46.Ip4.IsValid() || !ip46.Ip6.IsValid() {
		t.Fatalf("expected both A and AAAA answers from Rust DNS runtime path, got %+v", ip46)
	}

	target, shouldReroute, dialIP := h.plane.ChooseDialTarget(
		context.Background(),
		netip.MustParseAddrPort("192.0.2.10:12345"),
		&bpfRoutingResult{},
		consts.OutboundUserDefinedMin,
		netip.MustParseAddrPort("1.1.1.1:443"),
		"example.com",
	)
	if target != "example.com:443" || shouldReroute || dialIP {
		t.Fatalf("ChooseDialTarget() = (%q, %v, %v), want (example.com:443, false, false)", target, shouldReroute, dialIP)
	}

	outbound, mark, must, err := h.plane.Route(
		netip.MustParseAddrPort("192.0.2.10:12345"),
		netip.MustParseAddrPort("203.0.113.20:443"),
		"example.com",
		consts.L4ProtoType_TCP,
		&bpfRoutingResult{},
	)
	if err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	if outbound != consts.OutboundUserDefinedMin || mark != 0 || must {
		t.Fatalf("Route() = (outbound=%v, mark=%d, must=%v), want (%v, 0, false)", outbound, mark, must, consts.OutboundUserDefinedMin)
	}

	conn, err := h.plane.RouteDialTcp(RouteDialParam{
		Ctx:      context.Background(),
		Outbound: consts.OutboundControlPlaneRouting,
		Domain:   "example.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:12345"),
		Dest:     netip.MustParseAddrPort("1.1.1.1:443"),
	})
	if err != nil {
		t.Fatalf("RouteDialTcp() error = %v", err)
	}
	defer conn.Close()
	if h.recordingDialer.address != "example.com:443" {
		t.Fatalf("RouteDialTcp() dial target = %q, want example.com:443", h.recordingDialer.address)
	}
}

func BenchmarkRustControlPlaneCombinedRouteDialTcp(b *testing.B) {
	h := newRustCombinedRuntimeHarness(b)
	defer h.Close()

	b.ReportAllocs()
	param := RouteDialParam{
		Ctx:      context.Background(),
		Outbound: consts.OutboundControlPlaneRouting,
		Domain:   "example.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:12345"),
		Dest:     netip.MustParseAddrPort("1.1.1.1:443"),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := h.plane.RouteDialTcp(param)
		if err != nil {
			b.Fatalf("RouteDialTcp() error = %v", err)
		}
		_ = conn.Close()
	}
}
