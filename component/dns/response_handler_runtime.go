/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import dnsmessage "github.com/miekg/dns"

type ResponseHandlerRuntime struct {
	cache *DnsCacheRuntime
}

type ResponseHandlerOutcome struct {
	PackedResponse []byte
}

func NewResponseHandlerRuntime(cache *DnsCacheRuntime) *ResponseHandlerRuntime {
	return &ResponseHandlerRuntime{cache: cache}
}

func (r *ResponseHandlerRuntime) FinalizeResponse(
	respMsg *dnsmessage.Msg,
	decision DnsResponseDecision,
	requestID uint16,
	needResp bool,
) (ResponseHandlerOutcome, error) {
	if decision.Kind == DnsResponseDecisionReject {
		respMsg.Answer = nil
	}
	if r.cache != nil {
		if err := r.cache.NormalizeAndCacheResponse(respMsg); err != nil {
			return ResponseHandlerOutcome{}, err
		}
	}
	if !needResp {
		return ResponseHandlerOutcome{}, nil
	}
	respMsg.Id = requestID
	respMsg.Compress = true
	data, err := respMsg.Pack()
	if err != nil {
		return ResponseHandlerOutcome{}, err
	}
	return ResponseHandlerOutcome{PackedResponse: data}, nil
}
