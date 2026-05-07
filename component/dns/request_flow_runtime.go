/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

type RequestFlowRuntime struct {
	handling sync.Map
}

type requestHandlingState struct {
	mu  sync.Mutex
	ref uint32
}

type RequestFlowHooks struct {
	LookupCache   func(msg *dnsmessage.Msg, cacheKey string, ignoreFixedTtl bool) []byte
	RemoveCache   func(cacheKey string)
	ExecuteLookup func(msg *dnsmessage.Msg, lookup DnsRequestLookupPlan, needResp bool) error
}

type RequestFlowOutcome struct {
	Reject         bool
	CachedResponse []byte
}

func NewRequestFlowRuntime() *RequestFlowRuntime {
	return &RequestFlowRuntime{}
}

func (r *RequestFlowRuntime) HandlePlannedRequest(
	msg *dnsmessage.Msg,
	lookup DnsRequestLookupPlan,
	cacheKey string,
	needResp bool,
	allowAsIs bool,
	hooks RequestFlowHooks,
) (RequestFlowOutcome, error) {
	qtype := uint16(0)
	if len(msg.Question) != 0 {
		qtype = msg.Question[0].Qtype
	}
	if lookup.QType != qtype {
		return RequestFlowOutcome{}, fmt.Errorf("planned dns request qtype mismatch: got %d want %d", lookup.QType, qtype)
	}

	if !allowAsIs && lookup.UpstreamIndex == consts.DnsRequestOutboundIndex_AsIs {
		return RequestFlowOutcome{}, fmt.Errorf("dns request routing cannot use %q for locally bound dns listener; configure an explicit upstream instead", consts.DnsRequestOutboundIndex_AsIs.String())
	}

	if lookup.UpstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		if hooks.RemoveCache != nil {
			hooks.RemoveCache(cacheKey)
		}
		if !needResp {
			return RequestFlowOutcome{}, nil
		}
		return RequestFlowOutcome{Reject: true}, nil
	}

	handlingStateAny, _ := r.handling.LoadOrStore(cacheKey, new(requestHandlingState))
	handlingState := handlingStateAny.(*requestHandlingState)
	atomic.AddUint32(&handlingState.ref, 1)
	handlingState.mu.Lock()
	defer func() {
		handlingState.mu.Unlock()
		atomic.AddUint32(&handlingState.ref, ^uint32(0))
		if atomic.LoadUint32(&handlingState.ref) == 0 {
			r.handling.Delete(cacheKey)
		}
	}()

	if hooks.LookupCache != nil {
		if resp := hooks.LookupCache(msg, cacheKey, false); resp != nil {
			if needResp {
				return RequestFlowOutcome{CachedResponse: resp}, nil
			}
			return RequestFlowOutcome{}, nil
		}
	}

	if hooks.ExecuteLookup == nil {
		return RequestFlowOutcome{}, fmt.Errorf("dns request flow has no lookup executor")
	}
	if err := hooks.ExecuteLookup(msg, lookup, needResp); err != nil {
		return RequestFlowOutcome{}, err
	}
	return RequestFlowOutcome{}, nil
}
