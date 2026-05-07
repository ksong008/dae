/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"sync"
	"time"
)

const dnsCacheStoreShardCount = 64

type DnsCacheStore struct {
	shards     [dnsCacheStoreShardCount]dnsCacheStoreShard
	maxEntries int
	now        func() time.Time
}

type dnsCacheStoreShard struct {
	mu      sync.RWMutex
	entries map[DnsCacheKey]*DnsCache
	size    int
}

func (s *DnsCacheStore) shardCapacity() int {
	if s.maxEntries <= 0 {
		return 0
	}
	perShard := s.maxEntries / dnsCacheStoreShardCount
	if s.maxEntries%dnsCacheStoreShardCount != 0 {
		perShard++
	}
	if perShard < 1 {
		return 1
	}
	return perShard
}

func NewDnsCacheStore(maxEntries int, now func() time.Time) *DnsCacheStore {
	if now == nil {
		now = time.Now
	}
	s := &DnsCacheStore{
		maxEntries: maxEntries,
		now:        now,
	}
	for i := range s.shards {
		s.shards[i].entries = make(map[DnsCacheKey]*DnsCache)
	}
	return s
}

func (s *DnsCacheStore) Insert(key DnsCacheKey, cache *DnsCache) {
	shard := s.shard(key)
	shard.mu.Lock()
	if _, exists := shard.entries[key]; !exists {
		shard.size++
	}
	shard.entries[key] = cache
	shard.mu.Unlock()
}

func (s *DnsCacheStore) Has(key DnsCacheKey) bool {
	shard := s.shard(key)
	shard.mu.RLock()
	_, ok := shard.entries[key]
	shard.mu.RUnlock()
	return ok
}

func (s *DnsCacheStore) Len() int {
	return s.TotalSize()
}

func (s *DnsCacheStore) TotalSize() int {
	total := 0
	for i := 0; i < dnsCacheStoreShardCount; i++ {
		shard := &s.shards[i]
		shard.mu.RLock()
		total += shard.size
		shard.mu.RUnlock()
	}
	return total
}

func (s *DnsCacheStore) CountLive(now time.Time) int {
	live := 0
	for i := range s.shards {
		shard := &s.shards[i]
		shard.mu.RLock()
		for _, cache := range shard.entries {
			if cache.ExpiresAt().After(now) {
				live++
			}
		}
		shard.mu.RUnlock()
	}
	return live
}

func (s *DnsCacheStore) SnapshotClone() map[string]*DnsCache {
	snapshot := make(map[string]*DnsCache, s.Len())
	for i := range s.shards {
		shard := &s.shards[i]
		shard.mu.RLock()
		for key, cache := range shard.entries {
			snapshot[key.String()] = cache.Clone()
		}
		shard.mu.RUnlock()
	}
	return snapshot
}

func (s *DnsCacheStore) Sweep(now time.Time) (removed []*DnsCache) {
	for i := range s.shards {
		shard := &s.shards[i]
		shard.mu.Lock()
		for key, cache := range shard.entries {
			if cache.ExpiresAt().After(now) {
				continue
			}
			delete(shard.entries, key)
			shard.size--
			removed = append(removed, cache)
		}
		shard.mu.Unlock()
	}
	return removed
}

func (s *DnsCacheStore) Remove(key DnsCacheKey) (cache *DnsCache, ok bool) {
	shard := s.shard(key)
	shard.mu.Lock()
	cache, ok = shard.entries[key]
	if ok {
		delete(shard.entries, key)
		shard.size--
	}
	shard.mu.Unlock()
	return cache, ok
}

func (s *DnsCacheStore) Lookup(key DnsCacheKey, ignoreFixedTtl bool) (cache *DnsCache, expiredRemoved *DnsCache) {
	now := s.now()
	shard := s.shard(key)
	shard.mu.RLock()
	cache = shard.entries[key]
	if cache == nil {
		shard.mu.RUnlock()
		return nil, nil
	}
	if cache.EffectiveDeadline(ignoreFixedTtl).After(now) || cache.ExpiresAt().After(now) {
		shard.mu.RUnlock()
		return cache, nil
	}
	shard.mu.RUnlock()

	shard.mu.Lock()
	cache = shard.entries[key]
	if cache == nil {
		shard.mu.Unlock()
		return nil, nil
	}
	now = s.now()
	if cache.EffectiveDeadline(ignoreFixedTtl).After(now) || cache.ExpiresAt().After(now) {
		shard.mu.Unlock()
		return cache, nil
	}
	delete(shard.entries, key)
	shard.size--
	shard.mu.Unlock()
	return nil, cache
}

func (s *DnsCacheStore) Upsert(
	key DnsCacheKey,
	create func() (*DnsCache, error),
	updateExisting func(*DnsCache),
) (cache *DnsCache, evicted []*DnsCache, created bool, err error) {
	shard := s.shard(key)
	shardCap := s.shardCapacity()

	shard.mu.Lock()
	if cache = shard.entries[key]; cache != nil {
		updateExisting(cache)
		shard.mu.Unlock()
		return cache, nil, false, nil
	}
	shard.mu.Unlock()

	cache, err = create()
	if err != nil {
		return nil, nil, false, err
	}

	shard.mu.Lock()
	if existing := shard.entries[key]; existing != nil {
		updateExisting(existing)
		shard.mu.Unlock()
		return existing, nil, false, nil
	}
	if shardCap > 0 && shard.size >= shardCap {
		if evictedOne, ok := evictOldestFromShardLocked(shard); ok {
			evicted = append(evicted, evictedOne)
		}
	}
	shard.entries[key] = cache
	shard.size++
	shard.mu.Unlock()
	return cache, evicted, true, nil
}

func (s *DnsCacheStore) shard(key DnsCacheKey) *dnsCacheStoreShard {
	return &s.shards[dnsCacheStoreShardIndex(key)]
}

func dnsCacheStoreShardIndex(key DnsCacheKey) uint32 {
	var hash uint32 = 2166136261
	for i := 0; i < len(key.Host); i++ {
		hash ^= uint32(key.Host[i])
		hash *= 16777619
	}
	hash ^= uint32(byte(key.QType))
	hash *= 16777619
	hash ^= uint32(byte(key.QType >> 8))
	hash *= 16777619
	return hash & (dnsCacheStoreShardCount - 1)
}

func evictOldestFromShardLocked(shard *dnsCacheStoreShard) (*DnsCache, bool) {
	var (
		oldestKey      DnsCacheKey
		oldestCache    *DnsCache
		oldestDeadline time.Time
		oldestSeen     bool
	)
	for key, cache := range shard.entries {
		deadline := cache.ExpiresAt()
		if !oldestSeen || deadline.Before(oldestDeadline) {
			oldestKey = key
			oldestCache = cache
			oldestDeadline = deadline
			oldestSeen = true
		}
	}
	if !oldestSeen {
		return nil, false
	}
	cache := shard.entries[oldestKey]
	if cache == nil {
		return nil, false
	}
	delete(shard.entries, oldestKey)
	shard.size--
	return oldestCache, true
}
