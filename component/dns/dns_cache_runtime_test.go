/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"net/netip"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestDnsCacheRuntimeLookupHitRunsOnAccess(t *testing.T) {
	now := time.Now()
	accessed := 0
	runtime := NewDnsCacheRuntime(logrus.New(), 8, nil, DnsCacheHooks{
		OnAccess: func(*DnsCache) error {
			accessed++
			return nil
		},
	}, func() time.Time { return now })

	runtime.Insert("example.com.1", &DnsCache{
		Deadline:         now.Add(time.Minute),
		OriginalDeadline: now.Add(time.Minute),
	})

	cache := runtime.Lookup("example.com.1", false)
	if cache == nil {
		t.Fatal("expected cache hit")
	}
	if accessed != 1 {
		t.Fatalf("expected one access callback, got %d", accessed)
	}
}

func TestDnsCacheRuntimeLookupExpiredRunsOnRemove(t *testing.T) {
	now := time.Now()
	removed := 0
	runtime := NewDnsCacheRuntime(logrus.New(), 8, nil, DnsCacheHooks{
		OnRemove: func(*DnsCache) error {
			removed++
			return nil
		},
	}, func() time.Time { return now })

	runtime.Insert("example.com.1", &DnsCache{
		Deadline:         now.Add(-time.Second),
		OriginalDeadline: now.Add(-time.Second),
	})

	cache := runtime.Lookup("example.com.1", false)
	if cache != nil {
		t.Fatal("expected expired cache miss")
	}
	if removed != 1 {
		t.Fatalf("expected one remove callback, got %d", removed)
	}
}

func BenchmarkDnsCacheRuntimeLookupHit(b *testing.B) {
	now := time.Now()
	runtime := NewDnsCacheRuntime(logrus.New(), 8, nil, DnsCacheHooks{}, func() time.Time { return now })
	runtime.Insert("example.com.1", &DnsCache{
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: netip.MustParseAddr("1.1.1.1").AsSlice(),
		}},
		IPs:              []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		HasAnyIP:         true,
		Deadline:         now.Add(time.Minute),
		OriginalDeadline: now.Add(time.Minute),
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache := runtime.Lookup("example.com.1", false)
		if cache == nil {
			b.Fatal("expected cache hit")
		}
	}
}
