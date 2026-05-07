/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"sync"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var ErrBadUpstreamFormat = fmt.Errorf("bad upstream format")

const dnsInitUpstreamConcurrency = 16

type Dns struct {
	log                *logrus.Logger
	upstream           []*UpstreamResolver
	requestQTypePrefer uint16
	rustRouting        *rustDnsRoutingRuntime
	reqMatcher         *RequestMatcher
	respMatcher        *ResponseMatcher
}

type NewOption struct {
	Logger                  *logrus.Logger
	LocationFinder          *assets.LocationFinder
	UpstreamReadyCallback   func(dnsUpstream *Upstream) (err error)
	RequestQTypePrefer      uint16
	UpstreamResolverNetwork string
	ResolverDialer          netproxy.Dialer
	ResolverDNS             netip.AddrPort
}

func New(dns *config.Dns, opt *NewOption) (s *Dns, err error) {
	s = &Dns{
		log:                opt.Logger,
		requestQTypePrefer: opt.RequestQTypePrefer,
	}
	// Parse upstream.
	upstreamName2Id := map[string]uint8{}
	for i, upstreamRaw := range dns.Upstream {
		if i >= int(consts.DnsRequestOutboundIndex_UserDefinedMax) ||
			i >= int(consts.DnsResponseOutboundIndex_UserDefinedMax) {
			return nil, fmt.Errorf("too many upstreams")
		}

		tag, link := common.GetTagFromLinkLikePlaintext(string(upstreamRaw))
		if tag == "" {
			return nil, fmt.Errorf("%w: '%v' has no tag", ErrBadUpstreamFormat, upstreamRaw)
		}
		var u *url.URL
		u, err = url.Parse(link)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadUpstreamFormat, err)
		}
		r := &UpstreamResolver{
			Raw:     u,
			Network: opt.UpstreamResolverNetwork,
			Resolve: func(ctx context.Context, upstream *url.URL, resolverNetwork string) (*Upstream, error) {
				return NewUpstreamWithResolver(ctx, upstream, resolverNetwork, opt.ResolverDialer, opt.ResolverDNS)
			},
			FinishInitCallback: func(i int) func(raw *url.URL, upstream *Upstream) (err error) {
				return func(raw *url.URL, upstream *Upstream) (err error) {
					upstream.Index = consts.DnsRequestOutboundIndex(i)
					if opt != nil && opt.UpstreamReadyCallback != nil {
						if err = opt.UpstreamReadyCallback(upstream); err != nil {
							return err
						}
					}
					return nil
				}
			}(i),
			mu:       sync.Mutex{},
			upstream: nil,
			init:     false,
		}
		if _, exists := upstreamName2Id[tag]; exists {
			return nil, fmt.Errorf("%w: duplicated upstream tag %q", ErrBadUpstreamFormat, tag)
		}
		upstreamName2Id[tag] = uint8(len(s.upstream))
		s.upstream = append(s.upstream, r)
	}
	// Optimize routings.
	if dns.Routing.Request.Rules, err = routing.ApplyRulesOptimizers(dns.Routing.Request.Rules,
		&routing.DatReaderOptimizer{Logger: opt.Logger, LocationFinder: opt.LocationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, err
	}
	if dns.Routing.Response.Rules, err = routing.ApplyRulesOptimizers(dns.Routing.Response.Rules,
		&routing.DatReaderOptimizer{Logger: opt.Logger, LocationFinder: opt.LocationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, err
	}
	// Parse request routing.
	reqMatcherBuilder, err := NewRequestMatcherBuilder(opt.Logger, dns.Routing.Request.Rules, upstreamName2Id, dns.Routing.Request.Fallback)
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS request routing: %w", err)
	}
	// Parse response routing.
	respMatcherBuilder, err := NewResponseMatcherBuilder(opt.Logger, dns.Routing.Response.Rules, upstreamName2Id, dns.Routing.Response.Fallback)
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS response routing: %w", err)
	}
	s.rustRouting, err = newRustDnsRoutingRuntime(reqMatcherBuilder, respMatcherBuilder)
	if err != nil {
		return nil, fmt.Errorf("failed to build rust dns routing runtime: %w", err)
	}
	if s.rustRouting == nil {
		s.reqMatcher, err = reqMatcherBuilder.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build DNS request routing: %w", err)
		}
		s.respMatcher, err = respMatcherBuilder.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build DNS response routing: %w", err)
		}
	}
	if len(dns.Upstream) == 0 && opt != nil && opt.UpstreamReadyCallback != nil {
		// Immediately ready.
		go opt.UpstreamReadyCallback(nil)
	}
	return s, nil
}

func (s *Dns) Close() {
	if s == nil {
		return
	}
	if s.rustRouting != nil {
		s.rustRouting.Close()
	}
	if s.reqMatcher != nil {
		s.reqMatcher.Close()
	}
	if s.respMatcher != nil {
		s.respMatcher.Close()
	}
}

func (s *Dns) CheckUpstreamsFormat() error {
	for _, upstream := range s.upstream {
		_, _, _, _, err := ParseRawUpstream(upstream.Raw)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Dns) InitUpstreams() {
	workerCount := len(s.upstream)
	if workerCount == 0 {
		return
	}
	if workerCount > dnsInitUpstreamConcurrency {
		workerCount = dnsInitUpstreamConcurrency
	}
	jobs := make(chan *UpstreamResolver)
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for upstream := range jobs {
				_, err := upstream.GetUpstream()
				if err != nil {
					s.log.WithError(err).Debugln("Dns.GetUpstream")
				}
			}
		}()
	}
	for _, upstream := range s.upstream {
		jobs <- upstream
	}
	close(jobs)
	wg.Wait()
}

func (s *Dns) RequestSelect(qname string, qtype uint16) (upstreamIndex consts.DnsRequestOutboundIndex, upstream *Upstream, err error) {
	// Route.
	if s.rustRouting != nil {
		upstreamIndex, err = s.rustRouting.RequestMatch(qname, qtype)
	} else {
		upstreamIndex, err = s.reqMatcher.Match(qname, qtype)
	}
	if err != nil {
		return 0, nil, err
	}
	return s.resolveRequestSelection(upstreamIndex)
}

func (s *Dns) resolveRequestSelection(upstreamIndex consts.DnsRequestOutboundIndex) (_ consts.DnsRequestOutboundIndex, upstream *Upstream, err error) {
	// nil indicates AsIs.
	if upstreamIndex == consts.DnsRequestOutboundIndex_AsIs ||
		upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		return upstreamIndex, nil, nil
	}
	if int(upstreamIndex) >= len(s.upstream) {
		return 0, nil, fmt.Errorf("bad upstream index: %v not in [0, %v]", upstreamIndex, len(s.upstream)-1)
	}
	// Get corresponding upstream.
	upstream, err = s.upstream[upstreamIndex].GetUpstream()
	if err != nil {
		return 0, nil, err
	}
	return upstreamIndex, upstream, nil
}

func (s *Dns) ResponseSelect(msg *dnsmessage.Msg, fromUpstream *Upstream) (upstreamIndex consts.DnsResponseOutboundIndex, upstream *Upstream, err error) {
	qname, qtype, ips, from, err := responseRoutingInputFromMsg(msg, fromUpstream)
	if err != nil {
		return 0, nil, err
	}
	upstreamIndex, err = s.matchResponse(qname, qtype, ips, from)
	if err != nil {
		return 0, nil, err
	}
	upstream, err = s.resolveResponseSelection(upstreamIndex)
	return upstreamIndex, upstream, err
}

func (s *Dns) matchResponse(qname string, qtype uint16, ips []netip.Addr, from consts.DnsRequestOutboundIndex) (consts.DnsResponseOutboundIndex, error) {
	if s.rustRouting != nil {
		return s.rustRouting.ResponseMatch(qname, qtype, ips, from)
	}
	return s.respMatcher.Match(qname, qtype, ips, from)
}

func (s *Dns) resolveResponseSelection(upstreamIndex consts.DnsResponseOutboundIndex) (upstream *Upstream, err error) {
	if upstreamIndex == consts.DnsResponseOutboundIndex_Accept ||
		upstreamIndex == consts.DnsResponseOutboundIndex_Reject {
		return nil, nil
	}
	if upstreamIndex.IsReserved() {
		return nil, fmt.Errorf("bad reserved response upstream index: %v", upstreamIndex)
	}
	if int(upstreamIndex) >= len(s.upstream) {
		return nil, fmt.Errorf("bad upstream index: %v not in [0, %v]", upstreamIndex, len(s.upstream)-1)
	}
	return s.upstream[upstreamIndex].GetUpstream()
}
