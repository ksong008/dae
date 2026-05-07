/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"sync"

	"github.com/daeuniverse/dae/common/consts"
)

type DomainMatcher interface {
	AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey)
	Build() error
	MatchDomainBitmap(domain string) (bitmap []uint32)
}

type DomainMatcherInto interface {
	MatchDomainBitmapInto(domain string, bitmap []uint32) error
}

type DomainMatcherCloser interface {
	Close()
}

type DomainBitmapBuffer struct {
	bitmap []uint32
}

func NewDomainBitmapPool(matcher DomainMatcher, bitLength int) *sync.Pool {
	if _, ok := matcher.(DomainMatcherInto); !ok {
		return nil
	}
	return &sync.Pool{
		New: func() any {
			return &DomainBitmapBuffer{
				bitmap: make([]uint32, (bitLength+31)/32),
			}
		},
	}
}

func MatchDomainBitmapWithPool(matcher DomainMatcher, pool *sync.Pool, domain string) (bitmap []uint32, buffer *DomainBitmapBuffer, err error) {
	if matcherInto, ok := matcher.(DomainMatcherInto); ok && pool != nil {
		buffer = pool.Get().(*DomainBitmapBuffer)
		bitmap = buffer.bitmap
		if err = matcherInto.MatchDomainBitmapInto(domain, bitmap); err != nil {
			pool.Put(buffer)
			return nil, nil, err
		}
		return bitmap, buffer, nil
	}
	return matcher.MatchDomainBitmap(domain), nil, nil
}

func PutDomainBitmap(pool *sync.Pool, buffer *DomainBitmapBuffer) {
	if pool == nil || buffer == nil {
		return
	}
	pool.Put(buffer)
}
