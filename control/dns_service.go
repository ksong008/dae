/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type dnsService struct {
	controller *DnsController
	listener   *DNSListener
}

func newDNSService(log *logrus.Logger, bind string, controller *DnsController) (*dnsService, error) {
	service := &dnsService{controller: controller}
	if bind == "" {
		return service, nil
	}
	listener, err := NewDNSListener(log, bind, controller)
	if err != nil {
		return nil, err
	}
	service.listener = listener
	return service, nil
}

func (s *dnsService) Close() error {
	var errs []error
	if s.listener != nil {
		if err := s.listener.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.controller != nil {
		if err := s.controller.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *dnsService) StartListener() error {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Start()
}

func (s *dnsService) StopListener() error {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Stop()
}

func (s *dnsService) HandlePacketRequest(
	dnsMessage *dnsmessage.Msg,
	reqCtx context.Context,
	realSrc netip.AddrPort,
	realDst netip.AddrPort,
	src netip.AddrPort,
	lConn *net.UDPConn,
	routingResult *bpfRoutingResult,
) error {
	return s.controller.HandlePacketRequest(dnsMessage, reqCtx, realSrc, realDst, src, lConn, routingResult)
}

func (s *dnsService) SnapshotCache() map[string]*DnsCache {
	if s == nil || s.controller == nil {
		return nil
	}
	return s.controller.SnapshotCache()
}

func (s *dnsService) RestoreCacheSnapshot(snapshot map[string]*DnsCache) {
	if s == nil || s.controller == nil {
		return
	}
	s.controller.RestoreCacheSnapshot(snapshot)
}

func (s *dnsService) PrimeUpstreamAddressCache(upstream *componentdns.Upstream, deadline time.Time) error {
	if s == nil || s.controller == nil {
		return nil
	}
	return s.controller.PrimeUpstreamAddressCache(upstream, deadline)
}

func (s *dnsService) HasCachedDomainAddress(domain string, addr netip.Addr) bool {
	if s == nil || s.controller == nil {
		return false
	}
	return s.controller.HasCachedDomainAddress(domain, addr)
}

func (s *dnsService) DomainHasAnyResolvedIPForPacket(
	ctx context.Context,
	realSrc netip.AddrPort,
	realDst netip.AddrPort,
	src netip.AddrPort,
	routingResult *bpfRoutingResult,
	host string,
) bool {
	if s == nil || s.controller == nil {
		return false
	}
	return s.controller.DomainHasAnyResolvedIPForPacket(ctx, realSrc, realDst, src, routingResult, host)
}

func (s *dnsService) CacheStats() (int, int) {
	if s == nil || s.controller == nil {
		return 0, 0
	}
	return s.controller.CacheStats()
}
