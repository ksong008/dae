/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	dnsmessage "github.com/miekg/dns"
)

type Runtime[K comparable, M any, I any] struct {
	routing    *Dns
	cache      *DnsCacheRuntime
	forwarders *ForwarderExchangeRuntime[K, M, I]
	query      *QueryRuntime
	response   *ResponseServiceRuntime
}

type RuntimeRequestHooks struct {
	ExecuteLookup    func(msg *dnsmessage.Msg, lookup DnsRequestLookupPlan, needResp bool) error
	NextMessageID    func() uint16
	OnReject         func() error
	OnCachedResponse func(resp []byte) error
}

type RuntimeResolveHooks struct {
	ExecuteLookup func(ctx context.Context, msg *dnsmessage.Msg, lookup DnsRequestLookupPlan, needResp bool) error
	NextMessageID func() uint16
}

type RuntimeResponseExchangeHooks struct {
	Exchange            func(upstream *Upstream) (*dnsmessage.Msg, DnsExchangeMeta, error)
	WritePackedResponse func(resp []byte) error
}

type RuntimeServeHooks struct {
	ExecuteLookup        func(msg *dnsmessage.Msg, lookup DnsRequestLookupPlan, needResp bool) error
	NextMessageID        func() uint16
	WritePackedResponse  func(resp []byte) error
	WriteMessageResponse func(msg *dnsmessage.Msg) error
}

func NewRuntime[K comparable, M any, I any](
	routing *Dns,
	cache *DnsCacheRuntime,
	forwarders *ForwarderExchangeRuntime[K, M, I],
) *Runtime[K, M, I] {
	return &Runtime[K, M, I]{
		routing:    routing,
		cache:      cache,
		forwarders: forwarders,
		query:      NewQueryRuntime(routing, cache),
		response:   NewResponseServiceRuntime(routing, cache),
	}
}

func (r *Runtime[K, M, I]) Cache() *DnsCacheRuntime {
	return r.cache
}

func (r *Runtime[K, M, I]) Forwarders() *ForwarderExchangeRuntime[K, M, I] {
	return r.forwarders
}

func (r *Runtime[K, M, I]) Close() []ForwarderCacheCloseError[K] {
	if r.routing != nil {
		r.routing.Close()
	}
	if r.forwarders == nil {
		return nil
	}
	return r.forwarders.CloseAll()
}

func (r *Runtime[K, M, I]) SweepCache(now time.Time) {
	if r.cache != nil {
		r.cache.Sweep(now)
	}
}

func (r *Runtime[K, M, I]) SweepForwarders(now time.Time, enforceLimit bool) []ForwarderCacheCloseError[K] {
	if r.forwarders == nil {
		return nil
	}
	return r.forwarders.Sweep(now, enforceLimit)
}

func (r *Runtime[K, M, I]) RemoveCache(key string) {
	r.cache.Remove(key)
}

func (r *Runtime[K, M, I]) LookupCache(key string, ignoreFixedTtl bool) *DnsCache {
	return r.cache.Lookup(key, ignoreFixedTtl)
}

func (r *Runtime[K, M, I]) LookupCacheKey(key DnsCacheKey, ignoreFixedTtl bool) *DnsCache {
	return r.cache.LookupKey(key, ignoreFixedTtl)
}

func (r *Runtime[K, M, I]) LookupCacheIntoMessage(msg *dnsmessage.Msg, key string, ignoreFixedTtl bool) []byte {
	return r.cache.LookupIntoMessage(msg, key, ignoreFixedTtl)
}

func (r *Runtime[K, M, I]) NormalizeAndCacheResponse(msg *dnsmessage.Msg) error {
	return r.cache.NormalizeAndCacheResponse(msg)
}

func (r *Runtime[K, M, I]) UpdateCacheWithDeadlineFunc(
	host string,
	dnsTyp uint16,
	answers []dnsmessage.RR,
	deadlineFunc func(time.Time, string) (time.Time, time.Time),
) error {
	return r.cache.UpdateWithDeadlineFunc(host, dnsTyp, answers, deadlineFunc)
}

func (r *Runtime[K, M, I]) UpdateCacheDeadline(host string, dnsTyp uint16, answers []dnsmessage.RR, deadline time.Time) error {
	return r.cache.UpdateDeadline(host, dnsTyp, answers, deadline)
}

func (r *Runtime[K, M, I]) UpdateCacheTTL(host string, dnsTyp uint16, answers []dnsmessage.RR, ttl int) error {
	return r.cache.UpdateTTL(host, dnsTyp, answers, ttl)
}

func (r *Runtime[K, M, I]) SnapshotCache() map[string]*DnsCache {
	return r.cache.SnapshotClone()
}

func (r *Runtime[K, M, I]) CountLiveCacheEntries() int {
	return r.cache.CountLive()
}

func (r *Runtime[K, M, I]) CountForwarderEntries() int {
	if r.forwarders == nil {
		return 0
	}
	return r.forwarders.Len()
}

func (r *Runtime[K, M, I]) InsertForwarder(key K, value DnsForwarder, lastUsed time.Time, refs int) {
	r.forwarders.Insert(key, value, lastUsed, refs)
}

func (r *Runtime[K, M, I]) HasForwarder(key K) bool {
	return r.forwarders.Has(key)
}

func (r *Runtime[K, M, I]) GetForwarder(upstream *Upstream, selected SelectedForwarder[K, M]) (DnsForwarder, ForwarderCacheLease[K, DnsForwarder], bool, error) {
	return r.forwarders.GetForwarder(upstream, selected)
}

func (r *Runtime[K, M, I]) ReleaseForwarder(lease ForwarderCacheLease[K, DnsForwarder], forwarder DnsForwarder, reusable bool, failed bool) error {
	return r.forwarders.ReleaseForwarder(lease, forwarder, reusable, failed)
}

func (r *Runtime[K, M, I]) ExchangeForwarder(ctx context.Context, input I, data []byte, upstream *Upstream) (*dnsmessage.Msg, SelectedForwarder[K, M], error) {
	return r.forwarders.Exchange(ctx, input, data, upstream)
}

func (r *Runtime[K, M, I]) ExchangeForwarderResult(ctx context.Context, input I, data []byte, upstream *Upstream) (ForwarderExchangeResult[K, M], error) {
	return r.forwarders.ExchangeResult(ctx, input, data, upstream)
}

func (r *Runtime[K, M, I]) HandleRequest(
	msg *dnsmessage.Msg,
	needResp bool,
	allowAsIs bool,
	hooks RequestHandlerHooks,
) error {
	return r.query.HandleRequest(msg, needResp, allowAsIs, hooks)
}

func (r *Runtime[K, M, I]) ServeRequest(
	msg *dnsmessage.Msg,
	needResp bool,
	allowAsIs bool,
	hooks RuntimeRequestHooks,
) error {
	return r.query.HandleRequest(
		msg,
		needResp,
		allowAsIs,
		RequestHandlerHooks{
			LookupCacheEntry: r.cache.Lookup,
			LookupCacheResp:  r.cache.LookupIntoMessage,
			RemoveCache:      r.cache.Remove,
			ExecuteLookup:    hooks.ExecuteLookup,
			NextMessageID:    hooks.NextMessageID,
			OnReject:         hooks.OnReject,
			OnCachedResponse: hooks.OnCachedResponse,
		},
	)
}

func (r *Runtime[K, M, I]) ServeRequestIO(
	msg *dnsmessage.Msg,
	needResp bool,
	allowAsIs bool,
	hooks RuntimeServeHooks,
) error {
	return r.ServeRequest(
		msg,
		needResp,
		allowAsIs,
		RuntimeRequestHooks{
			ExecuteLookup: hooks.ExecuteLookup,
			NextMessageID: hooks.NextMessageID,
			OnReject: func() error {
				return writeRuntimeRejectResponse(msg, hooks.WriteMessageResponse, hooks.WritePackedResponse)
			},
			OnCachedResponse: func(resp []byte) error {
				return writeRuntimeResponse(resp, hooks.WriteMessageResponse, hooks.WritePackedResponse)
			},
		},
	)
}

func (r *Runtime[K, M, I]) ResolveIp46(
	ctx context.Context,
	host string,
	execute func(context.Context, *dnsmessage.Msg) error,
) (*netutils.Ip46, error, error) {
	return r.query.ResolveIp46(ctx, host, execute)
}

func (r *Runtime[K, M, I]) ResolveIp46WithHooks(
	ctx context.Context,
	host string,
	hooks RuntimeResolveHooks,
) (*netutils.Ip46, error, error) {
	return r.query.ResolveIp46(ctx, host, func(lookupCtx context.Context, msg *dnsmessage.Msg) error {
		return r.ServeRequest(
			msg,
			false,
			true,
			RuntimeRequestHooks{
				ExecuteLookup: func(msg *dnsmessage.Msg, lookup DnsRequestLookupPlan, needResp bool) error {
					return hooks.ExecuteLookup(lookupCtx, msg, lookup, needResp)
				},
				NextMessageID: hooks.NextMessageID,
			},
		)
	})
}

func (r *Runtime[K, M, I]) HandleResponseExchange(
	reqMsg *dnsmessage.Msg,
	initialUpstream *Upstream,
	realDst netip.AddrPort,
	invokingDepth int,
	maxDepth int,
	needResp bool,
	exchange func(upstream *Upstream) (*dnsmessage.Msg, DnsExchangeMeta, error),
) (ResponseServiceOutcome, error) {
	return r.response.HandleExchange(reqMsg, initialUpstream, realDst, invokingDepth, maxDepth, needResp, exchange)
}

func (r *Runtime[K, M, I]) HandlePackedResponseExchange(
	data []byte,
	initialUpstream *Upstream,
	realDst netip.AddrPort,
	invokingDepth int,
	maxDepth int,
	needResp bool,
	exchange func(upstream *Upstream) (*dnsmessage.Msg, DnsExchangeMeta, error),
) (ResponseServiceOutcome, error) {
	reqMsg := new(dnsmessage.Msg)
	if err := reqMsg.Unpack(data); err != nil {
		return ResponseServiceOutcome{}, err
	}
	return r.response.HandleExchange(reqMsg, initialUpstream, realDst, invokingDepth, maxDepth, needResp, exchange)
}

func (r *Runtime[K, M, I]) HandlePackedResponseExchangeIO(
	data []byte,
	initialUpstream *Upstream,
	realDst netip.AddrPort,
	invokingDepth int,
	maxDepth int,
	needResp bool,
	hooks RuntimeResponseExchangeHooks,
) (ResponseServiceOutcome, error) {
	outcome, err := r.HandlePackedResponseExchange(
		data,
		initialUpstream,
		realDst,
		invokingDepth,
		maxDepth,
		needResp,
		hooks.Exchange,
	)
	if err != nil {
		return ResponseServiceOutcome{}, err
	}
	if needResp && hooks.WritePackedResponse != nil {
		if err := hooks.WritePackedResponse(outcome.PackedResponse); err != nil {
			return ResponseServiceOutcome{}, err
		}
	}
	return outcome, nil
}

func writeRuntimeRejectResponse(
	req *dnsmessage.Msg,
	writeMessage func(*dnsmessage.Msg) error,
	writePacked func([]byte) error,
) error {
	resp := *req
	resp.Answer = nil
	resp.Rcode = dnsmessage.RcodeSuccess
	resp.Response = true
	resp.RecursionAvailable = true
	resp.Truncated = false
	resp.Compress = true
	if writeMessage != nil {
		return writeMessage(&resp)
	}
	if writePacked == nil {
		return nil
	}
	data, err := resp.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	return writePacked(data)
}

func writeRuntimeResponse(
	resp []byte,
	writeMessage func(*dnsmessage.Msg) error,
	writePacked func([]byte) error,
) error {
	if writeMessage != nil {
		var msg dnsmessage.Msg
		if err := msg.Unpack(resp); err != nil {
			return fmt.Errorf("failed to unpack DNS response: %w", err)
		}
		return writeMessage(&msg)
	}
	if writePacked != nil {
		return writePacked(resp)
	}
	return nil
}
