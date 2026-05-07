//go:build rust_userspace_routing && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestRustUserspaceRoutingRuntimeSharedFixtureBuildAndMatch(t *testing.T) {
	fixture := loadRoutingFixture(t)
	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		[]*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{
					{
						Name: consts.Function_Domain,
						Params: []*config_parser.Param{
							{Key: string(consts.RoutingDomainKey_Full), Val: "example.com"},
						},
					},
					{
						Name:   consts.Function_Port,
						Params: []*config_parser.Param{{Val: "443"}},
					},
				},
				Outbound: config_parser.Function{Name: consts.OutboundMustRules.String()},
			},
			{
				AndFunctions: []*config_parser.Function{
					{
						Name:   consts.Function_L4Proto,
						Params: []*config_parser.Param{{Val: "tcp"}},
					},
					{
						Name:   consts.Function_Dscp,
						Params: []*config_parser.Param{{Val: "46"}},
					},
				},
				Outbound: config_parser.Function{Name: "proxy", Params: []*config_parser.Param{{Key: consts.OutboundParam_Mark, Val: "123"}}},
			},
			{
				AndFunctions: []*config_parser.Function{
					{
						Name:   consts.Function_Ip,
						Params: []*config_parser.Param{{Val: "203.0.113.0/24"}},
					},
					{
						Name:   consts.Function_ProcessName,
						Params: []*config_parser.Param{{Val: "curl"}},
					},
				},
				Outbound: config_parser.Function{Name: "proxy2"},
			},
		},
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
			"fallback":                     2,
			"proxy":                        7,
			"proxy2":                       9,
		},
		nil,
		config.FunctionOrString("fallback"),
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilder() error = %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace() error = %v", err)
	}
	defer matcher.Close()
	if matcher.rustMatcher == nil {
		t.Fatal("expected Rust userspace routing runtime to be installed")
	}
	if matcher.domainMatcher != nil {
		t.Fatalf("expected Go userspace routing shell to bypass domain matcher, got %T", matcher.domainMatcher)
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

func BenchmarkRustUserspaceRoutingRuntimeSharedFixture(b *testing.B) {
	fixture := loadRoutingFixture(b)
	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		[]*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{
					{
						Name: consts.Function_Domain,
						Params: []*config_parser.Param{
							{Key: string(consts.RoutingDomainKey_Full), Val: "example.com"},
						},
					},
					{
						Name:   consts.Function_Port,
						Params: []*config_parser.Param{{Val: "443"}},
					},
				},
				Outbound: config_parser.Function{Name: consts.OutboundMustRules.String()},
			},
			{
				AndFunctions: []*config_parser.Function{
					{
						Name:   consts.Function_L4Proto,
						Params: []*config_parser.Param{{Val: "tcp"}},
					},
					{
						Name:   consts.Function_Dscp,
						Params: []*config_parser.Param{{Val: "46"}},
					},
				},
				Outbound: config_parser.Function{Name: "proxy", Params: []*config_parser.Param{{Key: consts.OutboundParam_Mark, Val: "123"}}},
			},
			{
				AndFunctions: []*config_parser.Function{
					{
						Name:   consts.Function_Ip,
						Params: []*config_parser.Param{{Val: "203.0.113.0/24"}},
					},
					{
						Name:   consts.Function_ProcessName,
						Params: []*config_parser.Param{{Val: "curl"}},
					},
				},
				Outbound: config_parser.Function{Name: "proxy2"},
			},
		},
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
			"fallback":                     2,
			"proxy":                        7,
			"proxy2":                       9,
		},
		nil,
		config.FunctionOrString("fallback"),
	)
	if err != nil {
		b.Fatalf("NewRoutingMatcherBuilder() error = %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		b.Fatalf("BuildUserspace() error = %v", err)
	}
	defer matcher.Close()

	type benchmarkCase struct {
		sourceAddr       []byte
		destAddr         []byte
		sourcePort       uint16
		destPort         uint16
		ipVersion        consts.IpVersionType
		l4proto          consts.L4ProtoType
		domain           string
		process          [16]uint8
		dscp             uint8
		expectedOutbound consts.OutboundIndex
		expectedMark     uint32
		expectedMust     bool
	}
	cases := make([]benchmarkCase, 0, len(fixture.Cases))
	for _, tc := range fixture.Cases {
		cases = append(cases, benchmarkCase{
			sourceAddr:       encodeIPv4Mapped(tc.SourceIP),
			destAddr:         encodeIPv4Mapped(tc.DestIP),
			sourcePort:       tc.SourcePort,
			destPort:         tc.DestPort,
			ipVersion:        consts.IpVersionType(tc.IPVersion),
			l4proto:          consts.L4ProtoType(tc.L4Proto),
			domain:           tc.Domain,
			process:          processName16(tc.ProcessName),
			dscp:             tc.Dscp,
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

func BenchmarkRustControlPlaneRouteSharedFixture(b *testing.B) {
	fixture := loadRoutingFixture(b)
	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		[]*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{
					{
						Name: consts.Function_Domain,
						Params: []*config_parser.Param{
							{Key: string(consts.RoutingDomainKey_Full), Val: "example.com"},
						},
					},
					{
						Name:   consts.Function_Port,
						Params: []*config_parser.Param{{Val: "443"}},
					},
				},
				Outbound: config_parser.Function{Name: consts.OutboundMustRules.String()},
			},
			{
				AndFunctions: []*config_parser.Function{
					{
						Name:   consts.Function_L4Proto,
						Params: []*config_parser.Param{{Val: "tcp"}},
					},
					{
						Name:   consts.Function_Dscp,
						Params: []*config_parser.Param{{Val: "46"}},
					},
				},
				Outbound: config_parser.Function{Name: "proxy", Params: []*config_parser.Param{{Key: consts.OutboundParam_Mark, Val: "123"}}},
			},
			{
				AndFunctions: []*config_parser.Function{
					{
						Name:   consts.Function_Ip,
						Params: []*config_parser.Param{{Val: "203.0.113.0/24"}},
					},
					{
						Name:   consts.Function_ProcessName,
						Params: []*config_parser.Param{{Val: "curl"}},
					},
				},
				Outbound: config_parser.Function{Name: "proxy2"},
			},
		},
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
			"fallback":                     2,
			"proxy":                        7,
			"proxy2":                       9,
		},
		nil,
		config.FunctionOrString("fallback"),
	)
	if err != nil {
		b.Fatalf("NewRoutingMatcherBuilder() error = %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		b.Fatalf("BuildUserspace() error = %v", err)
	}
	defer matcher.Close()
	plane := &ControlPlane{routingMatcher: matcher}

	type benchmarkCase struct {
		src              netip.AddrPort
		dst              netip.AddrPort
		domain           string
		l4proto          consts.L4ProtoType
		result           *bpfRoutingResult
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
