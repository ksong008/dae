/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func findKeysForShard(prefix string, shard uint32, count int) []DnsCacheKey {
	keys := make([]DnsCacheKey, 0, count)
	for candidate := 0; len(keys) < count; candidate++ {
		key := DnsCacheKey{Host: prefix + strconv.Itoa(candidate), QType: 0}
		if dnsCacheStoreShardIndex(key) == shard {
			keys = append(keys, key)
		}
	}
	return keys
}

func findKeyOutsideShard(prefix string, shard uint32) DnsCacheKey {
	for candidate := 0; ; candidate++ {
		key := DnsCacheKey{Host: prefix + strconv.Itoa(candidate), QType: 0}
		if dnsCacheStoreShardIndex(key) != shard {
			return key
		}
	}
}

func TestDnsCacheStoreLookupRemovesExpiredEntry(t *testing.T) {
	now := time.Now()
	store := NewDnsCacheStore(4, func() time.Time { return now })
	key := DnsCacheKey{Host: "example.com", QType: dnsmessage.TypeA}
	store.Insert(key, &DnsCache{
		Deadline:         now.Add(-time.Second),
		OriginalDeadline: now.Add(-time.Second),
	})

	cache, removed := store.Lookup(key, false)
	if cache != nil {
		t.Fatal("expected expired cache lookup to miss")
	}
	if removed == nil {
		t.Fatal("expected expired cache to be removed")
	}
	if store.Has(key) {
		t.Fatal("expected expired cache entry to be deleted")
	}
}

func TestDnsCacheStoreUpsertEvictsOldestEntryWhenFull(t *testing.T) {
	now := time.Now()
	store := NewDnsCacheStore(dnsCacheStoreShardCount, func() time.Time { return now })

	base := "full-same-shard-"
	targetShard := dnsCacheStoreShardIndex(DnsCacheKey{Host: base + "0"})
	keys := findKeysForShard(base, targetShard, 3)

	store.Insert(keys[0], &DnsCache{
		Deadline:         now.Add(1 * time.Second),
		OriginalDeadline: now.Add(1 * time.Second),
	})
	store.Insert(keys[1], &DnsCache{
		Deadline:         now.Add(2 * time.Second),
		OriginalDeadline: now.Add(2 * time.Second),
	})

	cache, evicted, created, err := store.Upsert(keys[2], func() (*DnsCache, error) {
		return &DnsCache{
			Deadline:         now.Add(10 * time.Second),
			OriginalDeadline: now.Add(10 * time.Second),
		}, nil
	}, func(*DnsCache) {})
	if err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}
	if !created || cache == nil {
		t.Fatalf("expected created cache, got created=%v cache=%v", created, cache)
	}
	if len(evicted) != 1 {
		t.Fatalf("expected one evicted cache, got %d", len(evicted))
	}
	if store.Has(keys[0]) {
		t.Fatal("expected oldest cache entry to be evicted")
	}
	if !store.Has(keys[1]) || !store.Has(keys[2]) {
		t.Fatal("expected newer and inserted cache entries to remain")
	}
}

func TestDnsCacheStoreUpsertEvictsOldestEntryWithinShardWhenShardQuotaFull(t *testing.T) {
	now := time.Now()
	store := NewDnsCacheStore(dnsCacheStoreShardCount, func() time.Time { return now })

	base := "same-shard-"
	targetShard := dnsCacheStoreShardIndex(DnsCacheKey{Host: base + "0"})
	keys := findKeysForShard(base, targetShard, 3)

	store.Insert(keys[0], &DnsCache{
		Deadline:         now.Add(1 * time.Second),
		OriginalDeadline: now.Add(1 * time.Second),
	})
	store.Insert(keys[1], &DnsCache{
		Deadline:         now.Add(2 * time.Second),
		OriginalDeadline: now.Add(2 * time.Second),
	})

	cache, evicted, created, err := store.Upsert(keys[2], func() (*DnsCache, error) {
		return &DnsCache{
			Deadline:         now.Add(10 * time.Second),
			OriginalDeadline: now.Add(10 * time.Second),
		}, nil
	}, func(*DnsCache) {})
	if err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}
	if !created || cache == nil {
		t.Fatalf("expected created cache, got created=%v cache=%v", created, cache)
	}
	if len(evicted) != 1 {
		t.Fatalf("expected one shard-local eviction, got %d", len(evicted))
	}
	if store.Has(keys[0]) {
		t.Fatal("expected oldest entry in same shard to be evicted")
	}
	if !store.Has(keys[1]) || !store.Has(keys[2]) {
		t.Fatal("expected newer entry in same shard to remain")
	}
}

func TestDnsCacheStoreUpsertDoesNotEvictFromOtherShard(t *testing.T) {
	now := time.Now()
	store := NewDnsCacheStore(dnsCacheStoreShardCount, func() time.Time { return now })

	keyA := DnsCacheKey{Host: "alpha-0"}
	shardA := dnsCacheStoreShardIndex(keyA)
	keyB0 := findKeyOutsideShard("beta-", shardA)
	shardB := dnsCacheStoreShardIndex(keyB0)
	keysB := findKeysForShard("gamma-", shardB, 2)
	keyB0 = keysB[0]
	keyB1 := keysB[1]

	store.Insert(keyA, &DnsCache{
		Deadline:         now.Add(1 * time.Second),
		OriginalDeadline: now.Add(1 * time.Second),
	})
	store.Insert(keyB0, &DnsCache{
		Deadline:         now.Add(2 * time.Second),
		OriginalDeadline: now.Add(2 * time.Second),
	})

	cache, evicted, created, err := store.Upsert(keyB1, func() (*DnsCache, error) {
		return &DnsCache{
			Deadline:         now.Add(10 * time.Second),
			OriginalDeadline: now.Add(10 * time.Second),
		}, nil
	}, func(*DnsCache) {})
	if err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}
	if !created || cache == nil {
		t.Fatalf("expected created cache, got created=%v cache=%v", created, cache)
	}
	if len(evicted) != 1 {
		t.Fatalf("expected one eviction from target shard, got %d", len(evicted))
	}
	if !store.Has(keyA) {
		t.Fatal("expected other-shard entry to remain untouched")
	}
	if !store.Has(keyB1) {
		t.Fatal("expected inserted same-shard entry to remain")
	}
}

func BenchmarkDnsCacheStoreLookupHit(b *testing.B) {
	now := time.Now()
	store := NewDnsCacheStore(8, func() time.Time { return now })
	key := DnsCacheKey{Host: "example.com", QType: dnsmessage.TypeA}
	store.Insert(key, &DnsCache{
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
		cache, removed := store.Lookup(key, false)
		if removed != nil {
			b.Fatal("expected no removed cache on hit")
		}
		if cache == nil {
			b.Fatal("expected cache hit")
		}
	}
}

func BenchmarkDnsCacheStoreLookupHitParallel(b *testing.B) {
	now := time.Now()
	store := NewDnsCacheStore(8, func() time.Time { return now })
	key := DnsCacheKey{Host: "example.com", QType: dnsmessage.TypeA}
	store.Insert(key, &DnsCache{
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
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache, removed := store.Lookup(key, false)
			if removed != nil {
				b.Fatal("expected no removed cache on hit")
			}
			if cache == nil {
				b.Fatal("expected cache hit")
			}
		}
	})
}
