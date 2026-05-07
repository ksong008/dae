/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"sync"
	"time"
)

type Closeable interface {
	Close() error
}

type ForwarderCacheCloseError[K comparable] struct {
	Key K
	Err error
}

type ForwarderCache[K comparable, V Closeable] struct {
	mu          sync.Mutex
	entries     map[K]*forwarderCacheEntry[V]
	idleTimeout time.Duration
	maxEntries  int
	now         func() time.Time
}

type forwarderCacheEntry[V Closeable] struct {
	value    V
	lastUsed time.Time
	refs     int
	stale    bool
}

type ForwarderCacheLease[K comparable, V Closeable] struct {
	cache *ForwarderCache[K, V]
	key   K
	entry *forwarderCacheEntry[V]
	value V
}

func NewForwarderCache[K comparable, V Closeable](idleTimeout time.Duration, maxEntries int, now func() time.Time) *ForwarderCache[K, V] {
	if now == nil {
		now = time.Now
	}
	return &ForwarderCache[K, V]{
		entries:     make(map[K]*forwarderCacheEntry[V]),
		idleTimeout: idleTimeout,
		maxEntries:  maxEntries,
		now:         now,
	}
}

func (c *ForwarderCache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *ForwarderCache[K, V]) Has(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[key]
	return ok
}

func (c *ForwarderCache[K, V]) Insert(key K, value V, lastUsed time.Time, refs int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = &forwarderCacheEntry[V]{
		value:    value,
		lastUsed: lastUsed,
		refs:     refs,
	}
}

func (c *ForwarderCache[K, V]) TryAcquire(key K) (value V, lease ForwarderCacheLease[K, V], ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || entry.stale {
		var zero V
		return zero, ForwarderCacheLease[K, V]{}, false
	}
	entry.lastUsed = c.now()
	entry.refs++
	return entry.value, ForwarderCacheLease[K, V]{
		cache: c,
		key:   key,
		entry: entry,
		value: entry.value,
	}, true
}

func (c *ForwarderCache[K, V]) StoreNew(key K, value V) (V, ForwarderCacheLease[K, V]) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := &forwarderCacheEntry[V]{
		value:    value,
		lastUsed: c.now(),
		refs:     1,
	}
	c.entries[key] = entry
	return value, ForwarderCacheLease[K, V]{
		cache: c,
		key:   key,
		entry: entry,
		value: value,
	}
}

func (c *ForwarderCache[K, V]) Sweep(now time.Time, enforceLimit bool) []ForwarderCacheCloseError[K] {
	c.mu.Lock()
	toClose := make([]struct {
		key   K
		value V
	}, 0)
	for key, entry := range c.entries {
		if entry.refs > 0 {
			continue
		}
		if entry.lastUsed.Add(c.idleTimeout).After(now) {
			continue
		}
		delete(c.entries, key)
		entry.stale = true
		toClose = append(toClose, struct {
			key   K
			value V
		}{key: key, value: entry.value})
	}
	if enforceLimit && c.maxEntries > 0 {
		for len(c.entries) >= c.maxEntries {
			var (
				oldestKey  K
				oldestTime time.Time
				oldestSeen bool
			)
			for key, entry := range c.entries {
				if entry.refs > 0 {
					continue
				}
				if !oldestSeen || entry.lastUsed.Before(oldestTime) {
					oldestKey = key
					oldestTime = entry.lastUsed
					oldestSeen = true
				}
			}
			if !oldestSeen {
				break
			}
			entry := c.entries[oldestKey]
			entry.stale = true
			toClose = append(toClose, struct {
				key   K
				value V
			}{key: oldestKey, value: entry.value})
			delete(c.entries, oldestKey)
		}
	}
	c.mu.Unlock()

	errs := make([]ForwarderCacheCloseError[K], 0)
	for _, item := range toClose {
		if err := item.value.Close(); err != nil {
			errs = append(errs, ForwarderCacheCloseError[K]{Key: item.key, Err: err})
		}
	}
	return errs
}

func (c *ForwarderCache[K, V]) CloseAll() []ForwarderCacheCloseError[K] {
	c.mu.Lock()
	toClose := make([]struct {
		key   K
		value V
	}, 0, len(c.entries))
	for key, entry := range c.entries {
		toClose = append(toClose, struct {
			key   K
			value V
		}{key: key, value: entry.value})
	}
	c.entries = make(map[K]*forwarderCacheEntry[V])
	c.mu.Unlock()

	errs := make([]ForwarderCacheCloseError[K], 0)
	for _, item := range toClose {
		if err := item.value.Close(); err != nil {
			errs = append(errs, ForwarderCacheCloseError[K]{Key: item.key, Err: err})
		}
	}
	return errs
}

func (l ForwarderCacheLease[K, V]) Release(failed bool) error {
	if l.cache == nil || l.entry == nil {
		return nil
	}

	c := l.cache
	c.mu.Lock()
	if l.entry.refs > 0 {
		l.entry.refs--
	}
	if failed {
		l.entry.stale = true
		if cached, ok := c.entries[l.key]; ok && cached == l.entry {
			delete(c.entries, l.key)
		}
	}
	shouldClose := l.entry.stale && l.entry.refs == 0
	c.mu.Unlock()
	if !shouldClose {
		return nil
	}
	return l.value.Close()
}
