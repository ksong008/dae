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
	"github.com/daeuniverse/dae/component/routing"
)

type rustDnsResponseMatcherRuntime struct{}

func (m *rustDnsResponseMatcherRuntime) Match(string, uint16, []netip.Addr, consts.DnsRequestOutboundIndex) (consts.DnsResponseOutboundIndex, error) {
	return 0, fmt.Errorf("rust dns response matcher runtime is unavailable in this build")
}

func (m *rustDnsResponseMatcherRuntime) Close() {}

func newResponseMatcherRuntime(_ int, _ []routing.DomainSet, _ [][]netip.Prefix, _ []responseMatchSet) (*rustDnsResponseMatcherRuntime, error) {
	return nil, nil
}
