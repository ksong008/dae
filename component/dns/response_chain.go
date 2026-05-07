/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"fmt"
	"net/netip"

	dnsmessage "github.com/miekg/dns"
)

func (s *Dns) ResolveResponseChain(
	initialUpstream *Upstream,
	invokingDepth int,
	maxDepth int,
	exchange func(upstream *Upstream) (*dnsmessage.Msg, error),
) (respMsg *dnsmessage.Msg, finalUpstream *Upstream, decision DnsResponseDecision, err error) {
	currentUpstream := initialUpstream
	for depth := invokingDepth; ; depth++ {
		if depth >= maxDepth {
			return nil, currentUpstream, DnsResponseDecision{}, fmt.Errorf(
				"too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing",
				maxDepth,
			)
		}
		respMsg, err = exchange(currentUpstream)
		if err != nil {
			return nil, currentUpstream, DnsResponseDecision{}, err
		}
		decision, err = s.PlanResponse(respMsg, currentUpstream)
		if err != nil {
			return nil, currentUpstream, DnsResponseDecision{}, err
		}
		if decision.Kind != DnsResponseDecisionRetry {
			return respMsg, currentUpstream, decision, nil
		}
		if decision.Upstream == nil {
			return nil, currentUpstream, decision, fmt.Errorf("dns response retry decision missing upstream")
		}
		currentUpstream = decision.Upstream
	}
}

func (s *Dns) ResolveResponseExchangeChain(
	reqMsg *dnsmessage.Msg,
	initialUpstream *Upstream,
	realDst netip.AddrPort,
	invokingDepth int,
	maxDepth int,
	exchange func(upstream *Upstream) (*dnsmessage.Msg, DnsExchangeMeta, error),
) (respMsg *dnsmessage.Msg, finalUpstream *Upstream, decision DnsResponseDecision, meta DnsExchangeMeta, err error) {
	currentUpstream := initialUpstream
	if currentUpstream == nil {
		currentUpstream = AsIsUpstream(realDst)
	}
	for depth := invokingDepth; ; depth++ {
		if depth >= maxDepth {
			return nil, currentUpstream, DnsResponseDecision{}, DnsExchangeMeta{}, fmt.Errorf(
				"too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing",
				maxDepth,
			)
		}
		respMsg, meta, err = exchange(currentUpstream)
		if err != nil {
			return nil, currentUpstream, DnsResponseDecision{}, meta, err
		}
		if err := ValidateResponseForRequest(reqMsg, respMsg, ShouldValidateResponseID(currentUpstream)); err != nil {
			return nil, currentUpstream, DnsResponseDecision{}, meta, err
		}
		if ShouldRetryTruncatedResponseOverTCP(respMsg, currentUpstream, meta.L4Proto) {
			tcpUpstream := *currentUpstream
			tcpUpstream.Scheme = UpstreamScheme_TCP
			respMsg, meta, err = exchange(&tcpUpstream)
			if err != nil {
				return nil, currentUpstream, DnsResponseDecision{}, meta, err
			}
			meta.RetriedOverTCP = true
			if err := ValidateResponseForRequest(reqMsg, respMsg, ShouldValidateResponseID(&tcpUpstream)); err != nil {
				return nil, currentUpstream, DnsResponseDecision{}, meta, err
			}
		}
		decision, err = s.PlanResponse(respMsg, currentUpstream)
		if err != nil {
			return nil, currentUpstream, DnsResponseDecision{}, meta, err
		}
		if decision.Kind != DnsResponseDecisionRetry {
			return respMsg, currentUpstream, decision, meta, nil
		}
		if decision.Upstream == nil {
			return nil, currentUpstream, decision, meta, fmt.Errorf("dns response retry decision missing upstream")
		}
		currentUpstream = decision.Upstream
	}
}
