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

type ResponseServiceRuntime struct {
	routing *Dns
	handler *ResponseHandlerRuntime
}

type ResponseServiceOutcome struct {
	Response       *dnsmessage.Msg
	Decision       DnsResponseDecision
	ExchangeMeta   DnsExchangeMeta
	FinalUpstream  *Upstream
	PackedResponse []byte
}

func NewResponseServiceRuntime(routing *Dns, cache *DnsCacheRuntime) *ResponseServiceRuntime {
	return &ResponseServiceRuntime{
		routing: routing,
		handler: NewResponseHandlerRuntime(cache),
	}
}

func (r *ResponseServiceRuntime) HandleExchange(
	reqMsg *dnsmessage.Msg,
	initialUpstream *Upstream,
	realDst netip.AddrPort,
	invokingDepth int,
	maxDepth int,
	needResp bool,
	exchange func(upstream *Upstream) (*dnsmessage.Msg, DnsExchangeMeta, error),
) (ResponseServiceOutcome, error) {
	if reqMsg == nil {
		return ResponseServiceOutcome{}, fmt.Errorf("dns request is nil")
	}
	respMsg, finalUpstream, decision, exchangeMeta, err := r.routing.ResolveResponseExchangeChain(
		reqMsg,
		initialUpstream,
		realDst,
		invokingDepth,
		maxDepth,
		exchange,
	)
	if err != nil {
		return ResponseServiceOutcome{}, err
	}
	finalized, err := r.handler.FinalizeResponse(respMsg, decision, reqMsg.Id, needResp)
	if err != nil {
		return ResponseServiceOutcome{}, err
	}
	return ResponseServiceOutcome{
		Response:       respMsg,
		Decision:       decision,
		ExchangeMeta:   exchangeMeta,
		FinalUpstream:  finalUpstream,
		PackedResponse: finalized.PackedResponse,
	}, nil
}
