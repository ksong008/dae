/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"context"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

type ForwarderExchangeRuntime[K comparable, M any, I any] struct {
	forwarders *ForwarderRuntime[K, M]
	selectFn   func(I, *Upstream) (SelectedForwarder[K, M], error)
	onFailure  func(M, error)
}

type ForwarderExchangeResult[K comparable, M any] struct {
	Response     *dnsmessage.Msg
	Selected     SelectedForwarder[K, M]
	UpstreamName string
}

func NewForwarderExchangeRuntime[K comparable, M any, I any](
	idleTimeout time.Duration,
	maxEntries int,
	now func() time.Time,
	hooks ForwarderHooks,
	factory func(upstream *Upstream, selected SelectedForwarder[K, M], hooks ForwarderHooks) (DnsForwarder, error),
	selectFn func(I, *Upstream) (SelectedForwarder[K, M], error),
	onFailure func(M, error),
) *ForwarderExchangeRuntime[K, M, I] {
	return &ForwarderExchangeRuntime[K, M, I]{
		forwarders: NewForwarderRuntime[K, M](idleTimeout, maxEntries, now, hooks, factory),
		selectFn:   selectFn,
		onFailure:  onFailure,
	}
}

func (r *ForwarderExchangeRuntime[K, M, I]) Len() int {
	return r.forwarders.Len()
}

func (r *ForwarderExchangeRuntime[K, M, I]) Has(key K) bool {
	return r.forwarders.Has(key)
}

func (r *ForwarderExchangeRuntime[K, M, I]) Insert(key K, value DnsForwarder, lastUsed time.Time, refs int) {
	r.forwarders.Insert(key, value, lastUsed, refs)
}

func (r *ForwarderExchangeRuntime[K, M, I]) Sweep(now time.Time, enforceLimit bool) []ForwarderCacheCloseError[K] {
	return r.forwarders.Sweep(now, enforceLimit)
}

func (r *ForwarderExchangeRuntime[K, M, I]) CloseAll() []ForwarderCacheCloseError[K] {
	return r.forwarders.CloseAll()
}

func (r *ForwarderExchangeRuntime[K, M, I]) GetForwarder(upstream *Upstream, selected SelectedForwarder[K, M]) (DnsForwarder, ForwarderCacheLease[K, DnsForwarder], bool, error) {
	return r.forwarders.GetForwarder(upstream, selected)
}

func (r *ForwarderExchangeRuntime[K, M, I]) ReleaseForwarder(
	lease ForwarderCacheLease[K, DnsForwarder],
	forwarder DnsForwarder,
	reusable bool,
	failed bool,
) error {
	return r.forwarders.ReleaseForwarder(lease, forwarder, reusable, failed)
}

func (r *ForwarderExchangeRuntime[K, M, I]) Exchange(
	ctx context.Context,
	input I,
	data []byte,
	upstream *Upstream,
) (respMsg *dnsmessage.Msg, selected SelectedForwarder[K, M], err error) {
	result, err := r.ExchangeResult(ctx, input, data, upstream)
	if err != nil {
		return nil, SelectedForwarder[K, M]{}, err
	}
	return result.Response, result.Selected, nil
}

func (r *ForwarderExchangeRuntime[K, M, I]) ExchangeResult(
	ctx context.Context,
	input I,
	data []byte,
	upstream *Upstream,
) (result ForwarderExchangeResult[K, M], err error) {
	var selected SelectedForwarder[K, M]
	selected, err = r.selectFn(input, upstream)
	if err != nil {
		return ForwarderExchangeResult[K, M]{}, err
	}
	result.Selected = selected
	result.UpstreamName = "asis"
	if upstream != nil {
		result.UpstreamName = upstream.String()
	}

	forwarder, lease, reusable, err := r.forwarders.GetForwarder(upstream, selected)
	if err != nil {
		return ForwarderExchangeResult[K, M]{}, err
	}
	releaseForwarder := func(failed bool) error {
		if forwarder == nil {
			return nil
		}
		releaseErr := r.forwarders.ReleaseForwarder(lease, forwarder, reusable, failed)
		forwarder = nil
		return releaseErr
	}
	defer func() {
		if forwarder != nil {
			if releaseErr := releaseForwarder(err != nil); err == nil && releaseErr != nil {
				err = releaseErr
			}
		}
	}()

	ctxDial, cancel := context.WithTimeout(contextOrBackground(ctx), consts.DefaultDialTimeout)
	defer cancel()
	respMsg, err := forwarder.ForwardDNS(ctxDial, data)
	if err != nil {
		if r.onFailure != nil && shouldReportForwarderDialFailure(err) {
			r.onFailure(selected.Meta, err)
		}
		return ForwarderExchangeResult[K, M]{}, err
	}
	result.Response = respMsg
	return result, nil
}
