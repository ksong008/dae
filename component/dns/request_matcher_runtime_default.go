//go:build !rust_dns_request_matcher || !cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"fmt"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

type rustDnsRequestMatcherRuntime struct{}

func (m *rustDnsRequestMatcherRuntime) Match(string, uint16) (consts.DnsRequestOutboundIndex, error) {
	return 0, fmt.Errorf("rust dns request matcher runtime is unavailable in this build")
}

func (m *rustDnsRequestMatcherRuntime) Close() {}

func newRequestMatcherRuntime(_ int, _ []routing.DomainSet, _ []requestMatchSet) (*rustDnsRequestMatcherRuntime, error) {
	return nil, nil
}
