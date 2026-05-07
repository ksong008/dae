/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"net/netip"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type DnsCacheHooks struct {
	OnAccess func(cache *DnsCache) error
	OnRemove func(cache *DnsCache) error
	NewCache func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error)
	OnHit    func()
	OnExpire func(removed int)
}

type DnsCacheRuntime struct {
	log            *logrus.Logger
	store          *DnsCacheStore
	hooks          DnsCacheHooks
	fixedDomainTTL map[string]int
	now            func() time.Time
}

func NewDnsCacheRuntime(
	log *logrus.Logger,
	maxEntries int,
	fixedDomainTTL map[string]int,
	hooks DnsCacheHooks,
	now func() time.Time,
) *DnsCacheRuntime {
	if now == nil {
		now = time.Now
	}
	return &DnsCacheRuntime{
		log:            log,
		store:          NewDnsCacheStore(maxEntries, now),
		hooks:          hooks,
		fixedDomainTTL: fixedDomainTTL,
		now:            now,
	}
}

func (r *DnsCacheRuntime) Insert(key string, cache *DnsCache) {
	parsed, err := ParseDnsCacheKey(key)
	if err != nil {
		r.warnf("failed to parse dns cache key for insert: %v", err)
		return
	}
	r.store.Insert(parsed, cache)
}

func (r *DnsCacheRuntime) Has(key string) bool {
	parsed, err := ParseDnsCacheKey(key)
	if err != nil {
		return false
	}
	return r.store.Has(parsed)
}

func (r *DnsCacheRuntime) HasKey(key DnsCacheKey) bool {
	return r.store.Has(key)
}

func (r *DnsCacheRuntime) Len() int {
	return r.store.Len()
}

func (r *DnsCacheRuntime) CountLive() int {
	return r.store.CountLive(r.now())
}

func (r *DnsCacheRuntime) SnapshotClone() map[string]*DnsCache {
	return r.store.SnapshotClone()
}

func (r *DnsCacheRuntime) Sweep(now time.Time) {
	removed := r.store.Sweep(now)
	if len(removed) > 0 && r.hooks.OnExpire != nil {
		r.hooks.OnExpire(len(removed))
	}
	for _, cache := range removed {
		r.onRemove(cache)
	}
}

func (r *DnsCacheRuntime) Remove(key string) {
	parsed, err := ParseDnsCacheKey(key)
	if err != nil {
		return
	}
	cache, ok := r.store.Remove(parsed)
	if ok {
		r.onRemove(cache)
	}
}

func (r *DnsCacheRuntime) Lookup(key string, ignoreFixedTtl bool) *DnsCache {
	parsed, err := ParseDnsCacheKey(key)
	if err != nil {
		return nil
	}
	return r.LookupKey(parsed, ignoreFixedTtl)
}

func (r *DnsCacheRuntime) LookupKey(key DnsCacheKey, ignoreFixedTtl bool) *DnsCache {
	cache, expiredRemoved := r.store.Lookup(key, ignoreFixedTtl)
	if expiredRemoved != nil {
		if r.hooks.OnExpire != nil {
			r.hooks.OnExpire(1)
		}
		r.onRemove(expiredRemoved)
		return nil
	}
	if cache == nil {
		return nil
	}
	if !r.onAccess(cache) {
		return nil
	}
	if r.hooks.OnHit != nil {
		r.hooks.OnHit()
	}
	return cache
}

func (r *DnsCacheRuntime) LookupIntoMessage(msg *dnsmessage.Msg, key string, ignoreFixedTtl bool) (resp []byte) {
	parsed, err := ParseDnsCacheKey(key)
	if err != nil {
		return nil
	}
	return r.LookupIntoMessageKey(msg, parsed, ignoreFixedTtl)
}

func (r *DnsCacheRuntime) LookupIntoMessageKey(msg *dnsmessage.Msg, key DnsCacheKey, ignoreFixedTtl bool) (resp []byte) {
	cache := r.LookupKey(key, ignoreFixedTtl)
	if cache != nil {
		if packed := cache.FillPackedResponse(msg.Id); packed != nil {
			return packed
		}
		cache.FillInto(msg)
		msg.Compress = true
		b, err := msg.Pack()
		if err != nil {
			r.warnf("failed to pack: %v", err)
			return nil
		}
		return b
	}
	return nil
}

func (r *DnsCacheRuntime) UpdateDeadline(
	host string,
	dnsTyp uint16,
	answers []dnsmessage.RR,
	deadline time.Time,
) error {
	return r.UpdateWithDeadlineFunc(host, dnsTyp, answers, func(_ time.Time, _ string) (time.Time, time.Time) {
		return deadline, deadline
	})
}

func (r *DnsCacheRuntime) UpdateTTL(
	host string,
	dnsTyp uint16,
	answers []dnsmessage.RR,
	ttl int,
) error {
	return r.UpdateWithDeadlineFunc(host, dnsTyp, answers, func(now time.Time, host string) (time.Time, time.Time) {
		originalDeadline := now.Add(time.Duration(ttl) * time.Second)
		if fixedTTL, ok := r.fixedDomainTTL[host]; ok {
			return now.Add(time.Duration(fixedTTL) * time.Second), originalDeadline
		}
		return originalDeadline, originalDeadline
	})
}

func (r *DnsCacheRuntime) UpdateWithDeadlineFunc(
	host string,
	dnsTyp uint16,
	answers []dnsmessage.RR,
	deadlineFunc func(now time.Time, host string) (deadline time.Time, originalDeadline time.Time),
) error {
	fqdn, trimmedHost := normalizeCacheHost(host)
	if fqdn == "" {
		return nil
	}
	if _, err := netip.ParseAddr(trimmedHost); err == nil {
		return nil
	}

	now := r.now()
	deadline, originalDeadline := deadlineFunc(now, trimmedHost)
	key := DnsCacheKey{Host: trimmedHost, QType: dnsTyp}
	ips, hasAnyIP := SummarizeDNSAnswers(answers)

	cache, evicted, _, err := r.store.Upsert(
		key,
		func() (*DnsCache, error) {
			if r.hooks.NewCache == nil {
				cache := &DnsCache{
					Answer:           answers,
					IPs:              ips,
					HasAnyIP:         hasAnyIP,
					Deadline:         deadline,
					OriginalDeadline: originalDeadline,
				}
				cache.RouteOwnerKey = key.String()
				r.packCacheResponse(cache, fqdn, dnsTyp)
				return cache, nil
			}
			cache, err := r.hooks.NewCache(fqdn, answers, deadline, originalDeadline)
			if err != nil {
				return nil, err
			}
			cache.RouteOwnerKey = key.String()
			r.packCacheResponse(cache, fqdn, dnsTyp)
			return cache, nil
		},
		func(cache *DnsCache) {
			cache.Answer = answers
			cache.IPs = ips
			cache.HasAnyIP = hasAnyIP
			cache.Deadline = deadline
			cache.OriginalDeadline = originalDeadline
			cache.RouteOwnerKey = key.String()
			cache.PackedResponse = nil
			r.packCacheResponse(cache, fqdn, dnsTyp)
		},
	)
	if err != nil {
		return err
	}
	for _, removed := range evicted {
		r.onRemove(removed)
	}
	r.onAccess(cache)
	return nil
}

func (r *DnsCacheRuntime) NormalizeAndCacheResponse(msg *dnsmessage.Msg) error {
	if !msg.Response || len(msg.Question) == 0 {
		return nil
	}
	q := msg.Question[0]
	if msg.Rcode != dnsmessage.RcodeSuccess {
		return nil
	}
	if len(msg.Answer) == 0 {
		return nil
	}

	ttl, ok := minDNSAnswerTTL(msg.Answer)
	if !ok {
		return nil
	}

	switch q.Qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		return r.UpdateTTL(q.Name, q.Qtype, msg.Answer, int(ttl))
	}

	for i := range msg.Answer {
		msg.Answer[i].Header().Ttl = 0
	}

	var reqIPRecord bool
	for i := range msg.Question {
		switch msg.Question[i].Qtype {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			reqIPRecord = true
			break
		}
	}
	if !reqIPRecord {
		return r.UpdateTTL(q.Name, q.Qtype, msg.Answer, int(ttl))
	}
	return r.UpdateTTL(q.Name, q.Qtype, msg.Answer, int(ttl))
}

func normalizeCacheHost(host string) (fqdn string, trimmedHost string) {
	trimmedHost = canonicalCacheHost(host)
	if trimmedHost == "" {
		return "", ""
	}
	return trimmedHost + ".", trimmedHost
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

func (r *DnsCacheRuntime) packCacheResponse(cache *DnsCache, qname string, qtype uint16) {
	if cache == nil || len(cache.Answer) == 0 {
		cache.PackedResponse = nil
		return
	}
	msg := new(dnsmessage.Msg)
	msg.SetQuestion(qname, qtype)
	cache.FillInto(msg)
	msg.Compress = true
	packed, err := msg.Pack()
	if err != nil {
		r.warnf("failed to pre-pack dns cache response: %v", err)
		cache.PackedResponse = nil
		return
	}
	cache.PackedResponse = packed
	cache.Answer = nil
}

func (r *DnsCacheRuntime) onAccess(cache *DnsCache) bool {
	if r.hooks.OnAccess == nil {
		return true
	}
	if err := r.hooks.OnAccess(cache); err != nil {
		r.warnf("failed to BatchUpdateDomainRouting: %v", err)
		return false
	}
	return true
}

func (r *DnsCacheRuntime) onRemove(cache *DnsCache) {
	if r.hooks.OnRemove == nil {
		return
	}
	if err := r.hooks.OnRemove(cache); err != nil {
		r.warnf("failed to remove domain routing cache: %v", err)
	}
}

func (r *DnsCacheRuntime) warnf(format string, args ...any) {
	if r.log != nil {
		r.log.Warnf(format, args...)
	}
}
