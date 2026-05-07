/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	MaxDnsLookupDepth           = 3
	dnsCacheSweepInterval       = time.Minute
	dnsCacheMaxEntries          = 4096
	dnsForwarderSweepInterval   = 5 * time.Minute
	dnsForwarderIdleTimeout     = 15 * time.Minute
	dnsForwarderCacheMaxEntries = 128
)

type IpVersionPrefer int

const (
	IpVersionPrefer_No IpVersionPrefer = 0
	IpVersionPrefer_4  IpVersionPrefer = 4
	IpVersionPrefer_6  IpVersionPrefer = 6
)

var (
	ErrUnsupportedQuestionType = fmt.Errorf("unsupported question type")
)

var (
	UnspecifiedAddressA    = netip.MustParseAddr("0.0.0.0")
	UnspecifiedAddressAAAA = netip.MustParseAddr("::")
)

type DnsControllerOption struct {
	Log                   *logrus.Logger
	AnyfromPool           *AnyfromPool
	CacheAccessCallback   func(cache *DnsCache) (err error)
	CacheRemoveCallback   func(cache *DnsCache) (err error)
	NewCache              func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	BestDialerChooser     func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	TimeoutExceedCallback func(dialArgument *dialArgument, err error)
	FixedDomainTtl        map[string]int
}

type DnsController struct {
	log              *logrus.Logger
	anyfromPool      *AnyfromPool
	now              func() time.Time
	forwarderFactory func(upstream *dns.Upstream, dialArgument dialArgument) (DnsForwarder, error)
	ctx              context.Context
	cancel           context.CancelFunc
	cleanupWg        sync.WaitGroup
	runtime          *dns.Runtime[dnsForwarderKey, *dialArgument, *udpRequest]
}

type dnsForwarderLease = dns.ForwarderCacheLease[dnsForwarderKey, DnsForwarder]

func parseIpVersionPreference(prefer int) (uint16, error) {
	switch prefer := IpVersionPrefer(prefer); prefer {
	case IpVersionPrefer_No:
		return 0, nil
	case IpVersionPrefer_4:
		return dnsmessage.TypeA, nil
	case IpVersionPrefer_6:
		return dnsmessage.TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown preference: %v", prefer)
	}
}

func NewDnsController(routing *dns.Dns, option *DnsControllerOption) (c *DnsController, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	nowFn := time.Now
	cacheAccess := option.CacheAccessCallback
	cacheRemove := option.CacheRemoveCallback
	newCache := option.NewCache
	fixedDomainTTL := option.FixedDomainTtl
	forwarderFactory := newDnsForwarder

	c = &DnsController{
		log:              option.Log,
		anyfromPool:      option.AnyfromPool,
		now:              nowFn,
		forwarderFactory: forwarderFactory,
		ctx:              ctx,
		cancel:           cancel,
		cleanupWg:        sync.WaitGroup{},
	}
	cacheRuntime := dns.NewDnsCacheRuntime(
		c.log,
		dnsCacheMaxEntries,
		fixedDomainTTL,
		dns.DnsCacheHooks{
			OnAccess: cacheAccess,
			OnRemove: cacheRemove,
			NewCache: newCache,
			OnHit: func() {
				recordDnsCacheHit()
			},
			OnExpire: func(removed int) {
				recordDnsCacheExpiredRemovals(removed)
			},
		},
		func() time.Time { return c.now() },
	)
	forwarderRuntime := dns.NewForwarderExchangeRuntime[dnsForwarderKey, *dialArgument, *udpRequest](
		dnsForwarderIdleTimeout,
		dnsForwarderCacheMaxEntries,
		func() time.Time { return c.now() },
		dns.ForwarderHooks{
			OnUDPRetry: func() {
				recordDnsUDPRetry()
			},
			OnDoHStatusFailure: func() {
				recordDoHStatusFailure()
			},
			OnDoHContentTypeError: func() {
				recordDoHContentTypeFailure()
			},
		},
		func(upstream *dns.Upstream, selected dns.SelectedForwarder[dnsForwarderKey, *dialArgument], hooks dns.ForwarderHooks) (DnsForwarder, error) {
			if selected.Meta == nil {
				return nil, fmt.Errorf("nil dns dial argument")
			}
			if c.forwarderFactory != nil {
				return c.forwarderFactory(upstream, *selected.Meta)
			}
			return dns.NewForwarder(upstream, selected.Path, hooks)
		},
		func(req *udpRequest, up *dns.Upstream) (dns.SelectedForwarder[dnsForwarderKey, *dialArgument], error) {
			dArg, err := option.BestDialerChooser(req, up)
			if err != nil {
				return dns.SelectedForwarder[dnsForwarderKey, *dialArgument]{}, err
			}
			return dns.SelectedForwarder[dnsForwarderKey, *dialArgument]{
				Key:  newDnsForwarderKey(up, *dArg),
				Path: dnsForwarderPath(*dArg),
				Meta: dArg,
			}, nil
		},
		func(meta *dialArgument, err error) {
			if meta != nil && option.TimeoutExceedCallback != nil {
				option.TimeoutExceedCallback(meta, err)
			}
		},
	)
	c.runtime = dns.NewRuntime[dnsForwarderKey, *dialArgument, *udpRequest](routing, cacheRuntime, forwarderRuntime)
	c.startBackgroundCleanup()
	return c, nil
}

func (c *DnsController) cacheKey(qname string, qtype uint16) string {
	return c.cacheLookupKey(qname, qtype).String()
}

func (c *DnsController) cacheLookupKey(qname string, qtype uint16) dns.DnsCacheKey {
	return dns.NewDnsCacheKey(qname, qtype)
}

func (c *DnsController) cacheExpiresAt(cache *DnsCache) time.Time {
	if cache == nil {
		return time.Time{}
	}
	if cache.Deadline.After(cache.OriginalDeadline) {
		return cache.Deadline
	}
	return cache.OriginalDeadline
}

func (c *DnsController) startBackgroundCleanup() {
	c.cleanupWg.Add(2)
	go func() {
		defer c.cleanupWg.Done()
		ticker := time.NewTicker(dnsCacheSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.sweepDnsCache(c.now())
			}
		}
	}()
	go func() {
		defer c.cleanupWg.Done()
		ticker := time.NewTicker(dnsForwarderSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.sweepDnsForwarderCache(c.now(), false)
			}
		}
	}()
}

func (c *DnsController) sweepDnsCache(now time.Time) {
	c.runtime.SweepCache(now)
}

func (c *DnsController) sweepDnsForwarderCache(now time.Time, enforceLimit bool) {
	for _, closeErr := range c.runtime.SweepForwarders(now, enforceLimit) {
		c.log.Warnf("failed to close evicted dns forwarder: %v", closeErr.Err)
	}
}

func (c *DnsController) RemoveDnsRespCache(cacheKey string) {
	c.runtime.RemoveCache(cacheKey)
}
func (c *DnsController) LookupDnsRespCache(cacheKey string, ignoreFixedTtl bool) (cache *DnsCache) {
	return c.runtime.LookupCache(cacheKey, ignoreFixedTtl)
}

// LookupDnsRespCache_ will modify the msg in place.
func (c *DnsController) LookupDnsRespCache_(msg *dnsmessage.Msg, cacheKey string, ignoreFixedTtl bool) (resp []byte) {
	return c.runtime.LookupCacheIntoMessage(msg, cacheKey, ignoreFixedTtl)
}

func minDNSAnswerTTL(answers []dnsmessage.RR) (ttl uint32, ok bool) {
	if len(answers) == 0 {
		return 0, false
	}
	ttl = answers[0].Header().Ttl
	for i := 1; i < len(answers); i++ {
		if ansTTL := answers[i].Header().Ttl; ansTTL < ttl {
			ttl = ansTTL
		}
	}
	return ttl, true
}

func canonicalDnsQuestionName(name string) string {
	if name == "" {
		return ""
	}
	return dnsmessage.CanonicalName(name)
}

func dnsQuestionsEqual(a, b dnsmessage.Question) bool {
	return canonicalDnsQuestionName(a.Name) == canonicalDnsQuestionName(b.Name) &&
		a.Qtype == b.Qtype &&
		a.Qclass == b.Qclass
}

func formatDnsQuestion(q dnsmessage.Question) string {
	return fmt.Sprintf("%s %s class=%d", strings.ToLower(canonicalDnsQuestionName(q.Name)), QtypeToString(q.Qtype), q.Qclass)
}

func validateDnsResponseForRequest(reqMsg *dnsmessage.Msg, respMsg *dnsmessage.Msg, requireMatchingID bool) error {
	return dns.ValidateResponseForRequest(reqMsg, respMsg, requireMatchingID)
}

func shouldValidateDnsResponseID(upstream *dns.Upstream, dialArgument *dialArgument) bool {
	if dialArgument == nil {
		return false
	}
	return dns.ShouldValidateResponseID(upstream)
}

func (c *DnsController) NormalizeAndCacheDnsResp_(msg *dnsmessage.Msg) (err error) {
	return c.runtime.NormalizeAndCacheResponse(msg)
}

type daedlineFunc func(now time.Time, host string) (deadline time.Time, originalDeadline time.Time)

func (c *DnsController) __updateDnsCacheDeadline(host string, dnsTyp uint16, answers []dnsmessage.RR, deadlineFunc daedlineFunc) (err error) {
	return c.runtime.UpdateCacheWithDeadlineFunc(host, dnsTyp, answers, deadlineFunc)
}

func (c *DnsController) UpdateDnsCacheDeadline(host string, dnsTyp uint16, answers []dnsmessage.RR, deadline time.Time) (err error) {
	return c.runtime.UpdateCacheDeadline(host, dnsTyp, answers, deadline)
}

func (c *DnsController) UpdateDnsCacheTtl(host string, dnsTyp uint16, answers []dnsmessage.RR, ttl int) (err error) {
	return c.runtime.UpdateCacheTTL(host, dnsTyp, answers, ttl)
}

type udpRequest struct {
	ctx           context.Context
	realSrc       netip.AddrPort
	realDst       netip.AddrPort
	src           netip.AddrPort
	lConn         *net.UDPConn
	routingResult *bpfRoutingResult
}

type dialArgument struct {
	l4proto      consts.L4ProtoStr
	ipversion    consts.IpVersionStr
	bestDialer   *dialer.Dialer
	bestOutbound *outbound.DialerGroup
	bestTarget   netip.AddrPort
	mark         uint32
	mptcp        bool
}

type dnsForwarderKey struct {
	upstream     string
	scheme       dns.UpstreamScheme
	hostname     string
	port         uint16
	path         string
	dialArgument dialArgument
}

func newDnsForwarderKey(upstream *dns.Upstream, dialArgument dialArgument) dnsForwarderKey {
	return dnsForwarderKey{
		scheme:       upstream.Scheme,
		hostname:     upstream.Hostname,
		port:         upstream.Port,
		path:         upstream.Path,
		dialArgument: dialArgument,
	}
}

func (k dnsForwarderKey) String() string {
	if k.upstream != "" {
		return k.upstream
	}
	return string(k.scheme) + "://" + net.JoinHostPort(k.hostname, strconv.Itoa(int(k.port))) + k.path
}

func newControlPlaneDnsRoutingResult() *bpfRoutingResult {
	return &bpfRoutingResult{
		Outbound: uint8(consts.OutboundControlPlaneRouting),
		Mark:     0,
		Must:     0,
		Mac:      [6]uint8{},
		Pname:    [16]uint8{},
		Pid:      0,
		Dscp:     0,
	}
}

func (c *DnsController) newPacketRequest(
	ctx context.Context,
	realSrc netip.AddrPort,
	realDst netip.AddrPort,
	src netip.AddrPort,
	lConn *net.UDPConn,
	routingResult *bpfRoutingResult,
) *udpRequest {
	return &udpRequest{
		ctx:           ctx,
		realSrc:       realSrc,
		realDst:       realDst,
		src:           src,
		lConn:         lConn,
		routingResult: routingResult,
	}
}

func (c *DnsController) newLocalRequest(
	ctx context.Context,
	clientSrc netip.AddrPort,
	localDst netip.AddrPort,
) *udpRequest {
	return c.newPacketRequest(ctx, clientSrc, localDst, clientSrc, nil, newControlPlaneDnsRoutingResult())
}

func (c *DnsController) Handle_(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	return c.HandleWithResponseWriter_(dnsMessage, req, nil)
}

func (c *DnsController) HandlePacketRequest(
	dnsMessage *dnsmessage.Msg,
	reqCtx context.Context,
	realSrc netip.AddrPort,
	realDst netip.AddrPort,
	src netip.AddrPort,
	lConn *net.UDPConn,
	routingResult *bpfRoutingResult,
) error {
	return c.HandleWithResponseWriter_(dnsMessage, c.newPacketRequest(reqCtx, realSrc, realDst, src, lConn, routingResult), nil)
}

func (c *DnsController) HandleLocalRequestWithResponseWriter(
	dnsMessage *dnsmessage.Msg,
	clientSrc netip.AddrPort,
	localDst netip.AddrPort,
	responseWriter dnsmessage.ResponseWriter,
) error {
	reqCtx, cancel := context.WithCancel(contextOrBackground(c.ctx))
	defer cancel()
	return c.HandleWithResponseWriter_(dnsMessage, c.newLocalRequest(reqCtx, clientSrc, localDst), responseWriter)
}

func (c *DnsController) ResolveIp46ForPacket(
	ctx context.Context,
	realSrc netip.AddrPort,
	realDst netip.AddrPort,
	src netip.AddrPort,
	routingResult *bpfRoutingResult,
	host string,
) (*netutils.Ip46, error, error) {
	return c.ResolveIp46(ctx, c.newPacketRequest(ctx, realSrc, realDst, src, nil, routingResult), host)
}

func (c *DnsController) HandleWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	if c.log.IsLevelEnabled(logrus.TraceLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		c.log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.realSrc, req.realDst.Addr()), req.realDst.String(), strings.ToLower(q.Name), QtypeToString(q.Qtype),
		)
	}

	if dnsMessage.Response {
		return fmt.Errorf("DNS request expected but DNS response received")
	}
	return c.handleWithResponseWriter_(dnsMessage, req, true, responseWriter)
}

func (c *DnsController) handle_(
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	needResp bool,
) (err error) {
	return c.handleWithResponseWriter_(dnsMessage, req, needResp, nil)
}

func (c *DnsController) handleWithResponseWriter_(
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	needResp bool,
	responseWriter dnsmessage.ResponseWriter,
) (err error) {
	return c.runtime.ServeRequestIO(
		dnsMessage,
		needResp,
		responseWriter == nil,
		dns.RuntimeServeHooks{
			ExecuteLookup: func(msg *dnsmessage.Msg, lookup dns.DnsRequestLookupPlan, needResp bool) error {
				return c.executeLookup(req, msg, lookup, needResp)
			},
			NextMessageID: c.nextMessageID,
			WritePackedResponse: func(resp []byte) error {
				return sendPkt(c.anyfromPool, c.log, resp, req.realDst, req.realSrc, req.src, req.lConn)
			},
			WriteMessageResponse: func(msg *dnsmessage.Msg) error {
				if responseWriter == nil {
					return nil
				}
				return responseWriter.WriteMsg(msg)
			},
		},
	)
}

func (c *DnsController) ResolveIp46(ctx context.Context, req *udpRequest, host string) (ipv46 *netutils.Ip46, err4, err6 error) {
	return c.runtime.ResolveIp46WithHooks(ctx, host, dns.RuntimeResolveHooks{
		ExecuteLookup: func(lookupCtx context.Context, msg *dnsmessage.Msg, lookup dns.DnsRequestLookupPlan, needResp bool) error {
			reqCopy := *req
			reqCopy.ctx = lookupCtx
			return c.executeLookup(&reqCopy, msg, lookup, needResp)
		},
		NextMessageID: c.nextMessageID,
	})
}

func (c *DnsController) nextMessageID() uint16 {
	return uint16(fastrand.Intn(math.MaxUint16))
}

func (c *DnsController) executeLookup(
	req *udpRequest,
	msg *dnsmessage.Msg,
	lookup dns.DnsRequestLookupPlan,
	needResp bool,
) error {
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		upstreamName := lookup.UpstreamIndex.String()
		if lookup.Upstream != nil {
			upstreamName = lookup.Upstream.String()
		}
		c.log.WithFields(logrus.Fields{
			"question": msg.Question,
			"upstream": upstreamName,
		}).Traceln("Request to DNS upstream")
	}
	data, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	return c.dialSend(0, req, data, lookup.Upstream, needResp)
}

func (c *DnsController) getDnsForwarder(upstream *dns.Upstream, dArg *dialArgument) (forwarder DnsForwarder, lease dnsForwarderLease, reusable bool, err error) {
	if dArg == nil {
		return nil, dnsForwarderLease{}, false, fmt.Errorf("nil dns dial argument")
	}
	selected := dns.SelectedForwarder[dnsForwarderKey, *dialArgument]{
		Key:  newDnsForwarderKey(upstream, *dArg),
		Path: dnsForwarderPath(*dArg),
		Meta: dArg,
	}
	return c.runtime.GetForwarder(upstream, selected)
}

func (c *DnsController) releaseDnsForwarder(lease dnsForwarderLease, forwarder DnsForwarder, reusable bool, failed bool) error {
	return c.runtime.ReleaseForwarder(lease, forwarder, reusable, failed)
}

func shouldReportDnsDialFailure(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func dialArgumentNetworkType(dialArgument *dialArgument) *dialer.NetworkType {
	return &dialer.NetworkType{
		L4Proto:   dialArgument.l4proto,
		IpVersion: dialArgument.ipversion,
		IsDns:     true,
	}
}

func (c *DnsController) Close() error {
	c.cancel()
	c.cleanupWg.Wait()
	var errs []error
	for _, closeErr := range c.runtime.Close() {
		errs = append(errs, fmt.Errorf("close dns forwarder %q: %w", closeErr.Key.String(), closeErr.Err))
	}
	return errors.Join(errs...)
}

func (c *DnsController) CacheStats() (dnsCacheEntries int, dnsForwarderCacheEntries int) {
	dnsCacheEntries = c.runtime.CountLiveCacheEntries()
	dnsForwarderCacheEntries = c.runtime.CountForwarderEntries()
	return dnsCacheEntries, dnsForwarderCacheEntries
}

func (c *DnsController) SnapshotCache() map[string]*DnsCache {
	return c.runtime.SnapshotCache()
}

func (c *DnsController) HasCachedDomainAddress(domain string, addr netip.Addr) bool {
	qtype := common.AddrToDnsType(addr)
	if qtype == 0 {
		return false
	}
	return c.runtime.LookupCacheKey(c.cacheLookupKey(domain, qtype), true) != nil
}

func (c *DnsController) DomainHasAnyResolvedIPForPacket(
	ctx context.Context,
	realSrc netip.AddrPort,
	realDst netip.AddrPort,
	src netip.AddrPort,
	routingResult *bpfRoutingResult,
	host string,
) bool {
	ip46, _, _ := c.ResolveIp46ForPacket(ctx, realSrc, realDst, src, routingResult, host)
	return ip46.Ip4.IsValid() || ip46.Ip6.IsValid()
}

func (c *DnsController) RestoreCacheSnapshot(snapshot map[string]*DnsCache) {
	for cacheKey, cache := range snapshot {
		lastDot := strings.LastIndex(cacheKey, ".")
		if lastDot == -1 || lastDot == len(cacheKey)-1 {
			c.log.Warnln("Invalid cache key:", cacheKey)
			continue
		}
		host := cacheKey[:lastDot]
		typText := cacheKey[lastDot+1:]
		typ, err := strconv.ParseUint(typText, 10, 16)
		if err != nil {
			c.log.WithError(err).Warnln("Invalid cache qtype:", cacheKey)
			continue
		}
		answers := cache.AnswersForHostQType(host, uint16(typ))
		if len(answers) == 0 {
			continue
		}
		if err := c.__updateDnsCacheDeadline(host, uint16(typ), answers, func(_ time.Time, _ string) (time.Time, time.Time) {
			return cache.Deadline, cache.OriginalDeadline
		}); err != nil {
			c.log.WithError(err).Warnf("Failed to restore DNS cache for %s", host)
		}
	}
}

func (c *DnsController) PrimeUpstreamAddressCache(dnsUpstream *dns.Upstream, deadline time.Time) error {
	if dnsUpstream == nil {
		return nil
	}
	fqdn := dnsmessage.CanonicalName(dnsUpstream.Hostname)

	if dnsUpstream.Ip4.IsValid() {
		typ := dnsmessage.TypeA
		answers := []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   fqdn,
				Rrtype: typ,
				Class:  dnsmessage.ClassINET,
				Ttl:    0,
			},
			A: dnsUpstream.Ip4.AsSlice(),
		}}
		if err := c.UpdateDnsCacheDeadline(dnsUpstream.Hostname, typ, answers, deadline); err != nil {
			return err
		}
	}

	if dnsUpstream.Ip6.IsValid() {
		typ := dnsmessage.TypeAAAA
		answers := []dnsmessage.RR{&dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{
				Name:   fqdn,
				Rrtype: typ,
				Class:  dnsmessage.ClassINET,
				Ttl:    0,
			},
			AAAA: dnsUpstream.Ip6.AsSlice(),
		}}
		if err := c.UpdateDnsCacheDeadline(dnsUpstream.Hostname, typ, answers, deadline); err != nil {
			return err
		}
	}
	return nil
}

func (c *DnsController) dialSend(invokingDepth int, req *udpRequest, data []byte, upstream *dns.Upstream, needResp bool) (err error) {
	if invokingDepth >= MaxDnsLookupDepth {
		return fmt.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
	}
	var (
		lastExchange     dns.ForwarderExchangeResult[dnsForwarderKey, *dialArgument]
		haveLastExchange bool
	)
	outcome, err := c.runtime.HandlePackedResponseExchangeIO(
		data,
		upstream,
		req.realDst,
		invokingDepth,
		MaxDnsLookupDepth,
		needResp,
		dns.RuntimeResponseExchangeHooks{
			Exchange: func(currentUpstream *dns.Upstream) (*dnsmessage.Msg, dns.DnsExchangeMeta, error) {
				exchange, err := c.runtime.ExchangeForwarderResult(contextOrBackground(req.ctx), req, data, currentUpstream)
				if err != nil {
					return nil, dns.DnsExchangeMeta{}, err
				}
				lastExchange = exchange
				haveLastExchange = true
				if exchange.Selected.Meta == nil {
					return nil, dns.DnsExchangeMeta{}, fmt.Errorf("dns exchange finished without dial argument")
				}
				return exchange.Response, dns.DnsExchangeMeta{
					L4Proto:      exchange.Selected.Meta.l4proto,
					UpstreamName: exchange.UpstreamName,
				}, nil
			},
			WritePackedResponse: func(resp []byte) error {
				return sendPkt(c.anyfromPool, c.log, resp, req.realDst, req.realSrc, req.src, req.lConn)
			},
		},
	)
	if err != nil {
		return err
	}
	if !haveLastExchange || lastExchange.Selected.Meta == nil {
		return fmt.Errorf("dns exchange finished without final exchange metadata")
	}
	upstreamName := lastExchange.UpstreamName
	dialArgument := lastExchange.Selected.Meta
	networkType := dialArgumentNetworkType(dialArgument)
	if outcome.ExchangeMeta.RetriedOverTCP {
		recordDnsTruncatedTcpFallback()
		if c.log.IsLevelEnabled(logrus.TraceLevel) && len(outcome.Response.Question) > 0 {
			c.log.WithFields(logrus.Fields{
				"question": outcome.Response.Question,
				"upstream": upstreamName,
			}).Traceln("Retry truncated UDP DNS response over TCP")
		}
	}
	switch outcome.Decision.Kind {
	case dns.DnsResponseDecisionAccept:
		// Accept.
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": outcome.Response.Question,
				"upstream": upstreamName,
			}).Traceln("Accept")
		}
	case dns.DnsResponseDecisionReject:
		// Reject the request with empty answer.
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": outcome.Response.Question,
				"upstream": upstreamName,
			}).Traceln("Reject with empty answer")
		}
	default:
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question":      outcome.Response.Question,
				"last_upstream": upstreamName,
				"next_upstream": outcome.Decision.Upstream.String(),
			}).Traceln("Change DNS upstream and resend")
		}
		return fmt.Errorf("unexpected retry decision after response service resolution: %+v", outcome.Decision)
	}
	if outcome.Decision.UpstreamIndex.IsReserved() && c.log.IsLevelEnabled(logrus.InfoLevel) {
		var (
			qname string
			qtype string
		)
		if len(outcome.Response.Question) > 0 {
			q := outcome.Response.Question[0]
			qname = strings.ToLower(q.Name)
			qtype = QtypeToString(q.Qtype)
		}
		fields := logrus.Fields{
			"network":  networkType.String(),
			"outbound": dialArgument.bestOutbound.Name,
			"policy":   dialArgument.bestOutbound.GetSelectionPolicy(),
			"dialer":   dialArgument.bestDialer.Property().Name,
			"_qname":   qname,
			"qtype":    qtype,
			"pid":      req.routingResult.Pid,
			"dscp":     req.routingResult.Dscp,
			"pname":    ProcessName2String(req.routingResult.Pname[:]),
			"mac":      Mac2String(req.routingResult.Mac[:]),
		}
		switch outcome.Decision.Kind {
		case dns.DnsResponseDecisionAccept:
			c.log.WithFields(fields).Infof("%v <-> %v", RefineSourceToShow(req.realSrc, req.realDst.Addr()), RefineAddrPortToShow(dialArgument.bestTarget))
		case dns.DnsResponseDecisionReject:
			c.log.WithFields(fields).Infof("%v -> reject", RefineSourceToShow(req.realSrc, req.realDst.Addr()))
		default:
			return fmt.Errorf("unknown dns response decision: %+v", outcome.Decision)
		}
	}
	return nil
}
