/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"errors"
	"fmt"

	dnsmessage "github.com/miekg/dns"
)

type RequestRuntime struct {
	flow *RequestFlowRuntime
}

type RequestRuntimeHooks struct {
	LookupCacheEntry func(cacheKey string, ignoreFixedTtl bool) *DnsCache
	LookupCacheResp  func(msg *dnsmessage.Msg, cacheKey string, ignoreFixedTtl bool) []byte
	RemoveCache      func(cacheKey string)
	ExecuteLookup    func(msg *dnsmessage.Msg, lookup DnsRequestLookupPlan, needResp bool) error
	NextMessageID    func() uint16
}

type RequestRuntimeOutcome struct {
	Reject         bool
	CachedResponse []byte
}

func NewRequestRuntime() *RequestRuntime {
	return &RequestRuntime{flow: NewRequestFlowRuntime()}
}

func (r *RequestRuntime) HandleRequest(
	msg *dnsmessage.Msg,
	plan DnsRequestPlan,
	needResp bool,
	allowAsIs bool,
	hooks RequestRuntimeHooks,
) (RequestRuntimeOutcome, error) {
	qname, qtype := requestQuestion(msg)
	cacheKey := dnsmessage.CanonicalName(qname) + fmt.Sprintf("%d", qtype)

	if plan.Preferred == nil {
		outcome, err := r.flow.HandlePlannedRequest(
			msg, plan.Requested, cacheKey, needResp, allowAsIs,
			RequestFlowHooks{
				LookupCache:   hooks.LookupCacheResp,
				RemoveCache:   hooks.RemoveCache,
				ExecuteLookup: hooks.ExecuteLookup,
			},
		)
		if err != nil {
			return RequestRuntimeOutcome{}, err
		}
		return RequestRuntimeOutcome{
			Reject:         outcome.Reject,
			CachedResponse: outcome.CachedResponse,
		}, nil
	}

	if hooks.NextMessageID == nil {
		return RequestRuntimeOutcome{}, fmt.Errorf("dns request runtime requires NextMessageID for preferred lookup path")
	}

	preferredMsg := msg.Copy()
	preferredMsg.Id = hooks.NextMessageID()
	preferredMsg.Question[0].Qtype = plan.Preferred.QType

	preferredErrCh := make(chan error, 1)
	requestedErrCh := make(chan error, 1)
	go func() {
		_, err := r.flow.HandlePlannedRequest(
			preferredMsg,
			*plan.Preferred,
			dnsmessage.CanonicalName(qname)+fmt.Sprintf("%d", plan.Preferred.QType),
			false,
			true,
			RequestFlowHooks{
				LookupCache:   hooks.LookupCacheResp,
				RemoveCache:   hooks.RemoveCache,
				ExecuteLookup: hooks.ExecuteLookup,
			},
		)
		preferredErrCh <- err
	}()
	go func() {
		_, err := r.flow.HandlePlannedRequest(
			msg,
			plan.Requested,
			cacheKey,
			false,
			allowAsIs,
			RequestFlowHooks{
				LookupCache:   hooks.LookupCacheResp,
				RemoveCache:   hooks.RemoveCache,
				ExecuteLookup: hooks.ExecuteLookup,
			},
		)
		requestedErrCh <- err
	}()

	preferredErr := <-preferredErrCh
	if hooks.LookupCacheEntry != nil {
		preferredCache := hooks.LookupCacheEntry(dnsmessage.CanonicalName(qname)+fmt.Sprintf("%d", plan.Preferred.QType), true)
		if preferredCache != nil && preferredCache.IncludeAnyIp() {
			return RequestRuntimeOutcome{Reject: true}, nil
		}
	}

	requestedErr := <-requestedErrCh
	if hooks.LookupCacheResp != nil {
		if resp := hooks.LookupCacheResp(msg, cacheKey, true); resp != nil {
			return RequestRuntimeOutcome{CachedResponse: resp}, nil
		}
	}

	if requestedErr != nil && preferredErr != nil {
		return RequestRuntimeOutcome{}, errors.Join(requestedErr, preferredErr)
	}
	if requestedErr != nil {
		return RequestRuntimeOutcome{}, requestedErr
	}
	if preferredErr != nil {
		return RequestRuntimeOutcome{}, preferredErr
	}
	return RequestRuntimeOutcome{Reject: true}, nil
}

func requestQuestion(msg *dnsmessage.Msg) (qname string, qtype uint16) {
	if len(msg.Question) == 0 {
		return "", 0
	}
	return msg.Question[0].Name, msg.Question[0].Qtype
}
