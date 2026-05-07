//go:build rust_domain_matcher && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestRustDomainMatcherRoutingUserspaceIntegration(t *testing.T) {
	const proxyOutbound = uint8(consts.OutboundUserDefinedMin)

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
				},
				Outbound: config_parser.Function{Name: "proxy"},
			},
		},
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
			"proxy":                        proxyOutbound,
		},
		nil,
		config.FunctionOrString(consts.OutboundDirect.String()),
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilder() error = %v", err)
	}

	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace() error = %v", err)
	}
	defer matcher.Close()

	if _, ok := matcher.domainMatcher.(*domain_matcher.RustDomainMatcher); !ok {
		t.Fatalf("routing matcher domain matcher type = %T, want *domain_matcher.RustDomainMatcher", matcher.domainMatcher)
	}

	src := netip.MustParseAddr("192.0.2.10").As16()
	dst := netip.MustParseAddr("203.0.113.20").As16()
	mac := net.IPv6zero.To16()
	outbound, _, _, err := matcher.Match(
		src[:],
		dst[:],
		12345,
		443,
		consts.IpVersion_4,
		consts.L4ProtoType_TCP,
		"example.com",
		[16]uint8{},
		0,
		mac,
	)
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if outbound != consts.OutboundIndex(proxyOutbound) {
		t.Fatalf("outbound = %v, want %v", outbound, proxyOutbound)
	}
}
