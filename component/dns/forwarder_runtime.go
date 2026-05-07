/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

type SelectedForwarder[K comparable, M any] struct {
	Key  K
	Path ForwarderPath
	Meta M
}

type ForwarderRuntime[K comparable, M any] struct {
	cache   *ForwarderCache[K, DnsForwarder]
	hooks   ForwarderHooks
	factory func(upstream *Upstream, selected SelectedForwarder[K, M], hooks ForwarderHooks) (DnsForwarder, error)
}

func NewForwarderRuntime[K comparable, M any](
	idleTimeout time.Duration,
	maxEntries int,
	now func() time.Time,
	hooks ForwarderHooks,
	factory func(upstream *Upstream, selected SelectedForwarder[K, M], hooks ForwarderHooks) (DnsForwarder, error),
) *ForwarderRuntime[K, M] {
	return &ForwarderRuntime[K, M]{
		cache:   NewForwarderCache[K, DnsForwarder](idleTimeout, maxEntries, now),
		hooks:   hooks,
		factory: factory,
	}
}

func (r *ForwarderRuntime[K, M]) Len() int {
	return r.cache.Len()
}

func (r *ForwarderRuntime[K, M]) Has(key K) bool {
	return r.cache.Has(key)
}

func (r *ForwarderRuntime[K, M]) Insert(key K, value DnsForwarder, lastUsed time.Time, refs int) {
	r.cache.Insert(key, value, lastUsed, refs)
}

func (r *ForwarderRuntime[K, M]) Sweep(now time.Time, enforceLimit bool) []ForwarderCacheCloseError[K] {
	return r.cache.Sweep(now, enforceLimit)
}

func (r *ForwarderRuntime[K, M]) CloseAll() []ForwarderCacheCloseError[K] {
	return r.cache.CloseAll()
}

func (r *ForwarderRuntime[K, M]) GetForwarder(
	upstream *Upstream,
	selected SelectedForwarder[K, M],
) (forwarder DnsForwarder, lease ForwarderCacheLease[K, DnsForwarder], reusable bool, err error) {
	if !ForwarderReusable(upstream, selected.Path) {
		forwarder, err = r.factory(upstream, selected, r.hooks)
		return forwarder, ForwarderCacheLease[K, DnsForwarder]{}, false, err
	}

	now := time.Now()
	if forwarder, lease, ok := r.cache.TryAcquire(selected.Key); ok {
		return forwarder, lease, true, nil
	}

	for _, closeErr := range r.cache.Sweep(now, true) {
		_ = closeErr
	}
	if forwarder, lease, ok := r.cache.TryAcquire(selected.Key); ok {
		return forwarder, lease, true, nil
	}
	forwarder, err = r.factory(upstream, selected, r.hooks)
	if err != nil {
		return nil, ForwarderCacheLease[K, DnsForwarder]{}, false, err
	}
	forwarder, lease = r.cache.StoreNew(selected.Key, forwarder)
	return forwarder, lease, true, nil
}

func (r *ForwarderRuntime[K, M]) ReleaseForwarder(
	lease ForwarderCacheLease[K, DnsForwarder],
	forwarder DnsForwarder,
	reusable bool,
	failed bool,
) error {
	if !reusable {
		if forwarder == nil {
			return nil
		}
		return forwarder.Close()
	}
	if forwarder == nil {
		return nil
	}
	return lease.Release(failed)
}

func (r *ForwarderRuntime[K, M]) Exchange(
	ctx context.Context,
	data []byte,
	upstream *Upstream,
	selectForwarder func(*Upstream) (SelectedForwarder[K, M], error),
	onFailure func(M, error),
) (respMsg *dnsmessage.Msg, selected SelectedForwarder[K, M], err error) {
	selected, err = selectForwarder(upstream)
	if err != nil {
		return nil, selected, err
	}

	forwarder, lease, reusable, err := r.GetForwarder(upstream, selected)
	if err != nil {
		return nil, selected, err
	}
	releaseForwarder := func(failed bool) error {
		if forwarder == nil {
			return nil
		}
		releaseErr := r.ReleaseForwarder(lease, forwarder, reusable, failed)
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
	respMsg, err = forwarder.ForwardDNS(ctxDial, data)
	if err != nil {
		if onFailure != nil && shouldReportForwarderDialFailure(err) {
			onFailure(selected.Meta, err)
		}
		return nil, selected, err
	}
	return respMsg, selected, nil
}

func shouldReportForwarderDialFailure(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func contextOrBackground(ctx context.Context) context.Context {
	if ctx != nil {
		return ctx
	}
	return context.Background()
}
