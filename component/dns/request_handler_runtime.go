/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"fmt"

	dnsmessage "github.com/miekg/dns"
)

type RequestHandlerRuntime struct {
	requests *RequestRuntime
	planned  *RequestFlowRuntime
}

type RequestHandlerHooks struct {
	LookupCacheEntry func(cacheKey string, ignoreFixedTtl bool) *DnsCache
	LookupCacheResp  func(msg *dnsmessage.Msg, cacheKey string, ignoreFixedTtl bool) []byte
	RemoveCache      func(cacheKey string)
	ExecuteLookup    func(msg *dnsmessage.Msg, lookup DnsRequestLookupPlan, needResp bool) error
	NextMessageID    func() uint16
	OnReject         func() error
	OnCachedResponse func(resp []byte) error
}

func NewRequestHandlerRuntime() *RequestHandlerRuntime {
	return &RequestHandlerRuntime{
		requests: NewRequestRuntime(),
		planned:  NewRequestFlowRuntime(),
	}
}

func (r *RequestHandlerRuntime) ServeRequest(
	msg *dnsmessage.Msg,
	plan DnsRequestPlan,
	needResp bool,
	allowAsIs bool,
	hooks RequestHandlerHooks,
) error {
	outcome, err := r.requests.HandleRequest(
		msg,
		plan,
		needResp,
		allowAsIs,
		RequestRuntimeHooks{
			LookupCacheEntry: hooks.LookupCacheEntry,
			LookupCacheResp:  hooks.LookupCacheResp,
			RemoveCache:      hooks.RemoveCache,
			ExecuteLookup: func(msg *dnsmessage.Msg, lookup DnsRequestLookupPlan, needResp bool) error {
				return r.servePlannedRequest(msg, lookup, needResp, allowAsIs, hooks)
			},
			NextMessageID: hooks.NextMessageID,
		},
	)
	if err != nil {
		return err
	}
	return r.finishOutcome(RequestRuntimeOutcome{
		Reject:         outcome.Reject,
		CachedResponse: outcome.CachedResponse,
	}, hooks)
}

func (r *RequestHandlerRuntime) servePlannedRequest(
	msg *dnsmessage.Msg,
	lookup DnsRequestLookupPlan,
	needResp bool,
	allowAsIs bool,
	hooks RequestHandlerHooks,
) error {
	qname, qtype := requestQuestion(msg)
	cacheKey := dnsmessage.CanonicalName(qname) + fmt.Sprintf("%d", qtype)
	outcome, err := r.planned.HandlePlannedRequest(
		msg,
		lookup,
		cacheKey,
		needResp,
		allowAsIs,
		RequestFlowHooks{
			LookupCache:   hooks.LookupCacheResp,
			RemoveCache:   hooks.RemoveCache,
			ExecuteLookup: hooks.ExecuteLookup,
		},
	)
	if err != nil {
		return err
	}
	return r.finishOutcome(RequestRuntimeOutcome{
		Reject:         outcome.Reject,
		CachedResponse: outcome.CachedResponse,
	}, hooks)
}

func (r *RequestHandlerRuntime) finishOutcome(outcome RequestRuntimeOutcome, hooks RequestHandlerHooks) error {
	if outcome.Reject {
		if hooks.OnReject != nil {
			return hooks.OnReject()
		}
		return nil
	}
	if len(outcome.CachedResponse) != 0 && hooks.OnCachedResponse != nil {
		return hooks.OnCachedResponse(outcome.CachedResponse)
	}
	return nil
}
