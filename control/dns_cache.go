/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package control

import (
	"net/netip"

	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

type DnsCache = componentdns.DnsCache

func summarizeDNSAnswers(answers []dnsmessage.RR) (ips []netip.Addr, hasAnyIP bool) {
	return componentdns.SummarizeDNSAnswers(answers)
}
