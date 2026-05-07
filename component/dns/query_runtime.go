/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"context"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/dae/common/netutils"
	dnsmessage "github.com/miekg/dns"
)

type QueryRuntime struct {
	requests *RequestServiceRuntime
	cache    *DnsCacheRuntime
}

func NewQueryRuntime(routing *Dns, cache *DnsCacheRuntime) *QueryRuntime {
	return &QueryRuntime{
		requests: NewRequestServiceRuntime(routing),
		cache:    cache,
	}
}

func (r *QueryRuntime) HandleRequest(
	msg *dnsmessage.Msg,
	needResp bool,
	allowAsIs bool,
	hooks RequestHandlerHooks,
) error {
	return r.requests.Handle(msg, needResp, allowAsIs, hooks)
}

func (r *QueryRuntime) ResolveIp46(
	ctx context.Context,
	host string,
	execute func(context.Context, *dnsmessage.Msg) error,
) (ipv46 *netutils.Ip46, err4, err6 error) {
	fqdn := dnsmessage.CanonicalName(host)
	ipv46 = &netutils.Ip46{}
	var ip4, ip6 netip.Addr

	runLookup := func(lookupCtx context.Context, qtype uint16) (netip.Addr, error) {
		msg := new(dnsmessage.Msg)
		msg.SetQuestion(fqdn, qtype)
		if err := execute(lookupCtx, msg); err != nil {
			return netip.Addr{}, err
		}
		cacheKey := fqdn + strconv.Itoa(int(qtype))
		cache := r.cache.Lookup(cacheKey, true)
		if cache == nil {
			return netip.Addr{}, nil
		}
		for _, ip := range cache.CachedIPs() {
			switch qtype {
			case dnsmessage.TypeA:
				if ip.Is4() || ip.Is4In6() {
					return ip.Unmap(), nil
				}
			case dnsmessage.TypeAAAA:
				if ip.Is6() && !ip.Is4In6() {
					return ip, nil
				}
			}
		}
		return netip.Addr{}, nil
	}

	ctx4, cancel4 := context.WithCancel(contextOrBackground(ctx))
	defer cancel4()
	ctx6, cancel6 := context.WithCancel(contextOrBackground(ctx))
	defer cancel6()

	done4 := make(chan struct{})
	done6 := make(chan struct{})
	go func() {
		defer close(done4)
		ip, err := runLookup(ctx4, dnsmessage.TypeA)
		if err != nil && err != context.Canceled {
			err4 = err
			return
		}
		ip4 = ip
	}()
	go func() {
		defer close(done6)
		ip, err := runLookup(ctx6, dnsmessage.TypeAAAA)
		if err != nil && err != context.Canceled {
			err6 = err
			return
		}
		ip6 = ip
	}()
	<-done4
	<-done6
	ipv46.Ip4 = ip4
	ipv46.Ip6 = ip6
	return ipv46, err4, err6
}
