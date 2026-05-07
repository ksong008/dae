/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package control

import (
	"context"
	"net/http"

	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

type DnsForwarder = componentdns.DnsForwarder

const doHMediaType = componentdns.DoHMediaType
const doHGetMaxEncodedQueryBytes = componentdns.DoHGetMaxEncodedQueryBytes

func dnsForwarderPath(dialArgument dialArgument) componentdns.ForwarderPath {
	return componentdns.ForwarderPath{
		Dialer:     dialArgument.bestDialer,
		BestTarget: dialArgument.bestTarget,
		Mark:       dialArgument.mark,
		MPTCP:      dialArgument.mptcp,
		L4Proto:    dialArgument.l4proto,
	}
}

func dnsForwarderHooks() componentdns.ForwarderHooks {
	return componentdns.ForwarderHooks{
		OnUDPRetry: func() {
			recordDnsUDPRetry()
		},
		OnDoHStatusFailure: func() {
			recordDoHStatusFailure()
		},
		OnDoHContentTypeError: func() {
			recordDoHContentTypeFailure()
		},
	}
}

func dnsForwarderReusable(upstream *componentdns.Upstream, dialArgument dialArgument) bool {
	return componentdns.ForwarderReusable(upstream, dnsForwarderPath(dialArgument))
}

func newDnsForwarder(upstream *componentdns.Upstream, dialArgument dialArgument) (DnsForwarder, error) {
	return componentdns.NewForwarder(upstream, dnsForwarderPath(dialArgument), dnsForwarderHooks())
}

func dnsDataWithZeroID(data []byte) []byte {
	return componentdns.DnsDataWithZeroID(data)
}

func buildDoHRequest(ctx context.Context, target string, upstream *componentdns.Upstream, data []byte) (*http.Request, error) {
	return componentdns.BuildDoHRequest(ctx, target, upstream, data)
}

func validateDoHResponse(resp *http.Response) error {
	return componentdns.ValidateDoHResponse(resp)
}

func sendHttpDNS(ctx context.Context, client *http.Client, target string, upstream *componentdns.Upstream, data []byte) (*dnsmessage.Msg, error) {
	return componentdns.SendHttpDNSWithHooks(ctx, client, target, upstream, data, dnsForwarderHooks())
}
