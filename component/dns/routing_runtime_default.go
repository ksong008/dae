//go:build !rust_dns_request_matcher || !cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
)

type rustDnsRoutingRuntime struct{}

func newRustDnsRoutingRuntime(_ *RequestMatcherBuilder, _ *ResponseMatcherBuilder) (*rustDnsRoutingRuntime, error) {
	return nil, nil
}

func (m *rustDnsRoutingRuntime) RequestMatch(string, uint16) (consts.DnsRequestOutboundIndex, error) {
	return 0, fmt.Errorf("rust dns routing runtime is unavailable in this build")
}

func (m *rustDnsRoutingRuntime) PlanRequest(string, uint16, uint16) (rustDnsRequestPlan, error) {
	return rustDnsRequestPlan{}, fmt.Errorf("rust dns routing runtime is unavailable in this build")
}

func (m *rustDnsRoutingRuntime) ResponseMatch(string, uint16, []netip.Addr, consts.DnsRequestOutboundIndex) (consts.DnsResponseOutboundIndex, error) {
	return 0, fmt.Errorf("rust dns routing runtime is unavailable in this build")
}

func (m *rustDnsRoutingRuntime) PlanResponse(string, uint16, []netip.Addr, consts.DnsRequestOutboundIndex) (rustDnsResponseDecision, error) {
	return rustDnsResponseDecision{}, fmt.Errorf("rust dns routing runtime is unavailable in this build")
}

func (m *rustDnsRoutingRuntime) Close() {}
