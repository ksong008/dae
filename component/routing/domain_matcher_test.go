/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"errors"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

type testDomainMatcher struct {
	bitmap []uint32
}

func (m *testDomainMatcher) AddSet(int, []string, consts.RoutingDomainKey) {}

func (m *testDomainMatcher) Build() error { return nil }

func (m *testDomainMatcher) MatchDomainBitmap(string) []uint32 {
	return append([]uint32(nil), m.bitmap...)
}

type testDomainMatcherInto struct {
	err   error
	calls int
}

func (m *testDomainMatcherInto) AddSet(int, []string, consts.RoutingDomainKey) {}

func (m *testDomainMatcherInto) Build() error { return nil }

func (m *testDomainMatcherInto) MatchDomainBitmap(string) []uint32 {
	panic("MatchDomainBitmap should not be called when pooled MatchDomainBitmapInto is available")
}

func (m *testDomainMatcherInto) MatchDomainBitmapInto(_ string, bitmap []uint32) error {
	m.calls++
	if m.err != nil {
		return m.err
	}
	for i := range bitmap {
		bitmap[i] = uint32(i + 1)
	}
	return nil
}

func TestNewDomainBitmapPool(t *testing.T) {
	if pool := NewDomainBitmapPool(&testDomainMatcher{}, 65); pool != nil {
		t.Fatal("expected nil pool for matcher without MatchDomainBitmapInto")
	}

	pool := NewDomainBitmapPool(&testDomainMatcherInto{}, 65)
	if pool == nil {
		t.Fatal("expected pool for matcher with MatchDomainBitmapInto")
	}
	if buffer := pool.Get().(*DomainBitmapBuffer); len(buffer.bitmap) != 3 {
		t.Fatalf("bitmap len = %d, want 3", len(buffer.bitmap))
	}
}

func TestMatchDomainBitmapWithPoolUsesIntoMatcher(t *testing.T) {
	matcher := &testDomainMatcherInto{}
	pool := NewDomainBitmapPool(matcher, 65)

	bitmap, buffer, err := MatchDomainBitmapWithPool(matcher, pool, "example.com")
	if err != nil {
		t.Fatalf("MatchDomainBitmapWithPool error: %v", err)
	}
	if buffer == nil {
		t.Fatal("expected pooled bitmap buffer")
	}
	if matcher.calls != 1 {
		t.Fatalf("MatchDomainBitmapInto calls = %d, want 1", matcher.calls)
	}
	if len(bitmap) != 3 || bitmap[0] != 1 || bitmap[1] != 2 || bitmap[2] != 3 {
		t.Fatalf("unexpected bitmap: %#v", bitmap)
	}

	PutDomainBitmap(pool, buffer)
}

func TestMatchDomainBitmapWithPoolReturnsBitmapOnIntoError(t *testing.T) {
	wantErr := errors.New("match failed")
	matcher := &testDomainMatcherInto{err: wantErr}
	pool := NewDomainBitmapPool(matcher, 33)

	bitmap, buffer, err := MatchDomainBitmapWithPool(matcher, pool, "example.com")
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if bitmap != nil {
		t.Fatalf("bitmap = %#v, want nil", bitmap)
	}
	if buffer != nil {
		t.Fatal("buffer must be nil after helper has already returned bitmap to pool")
	}

	reused := pool.Get().(*DomainBitmapBuffer)
	if len(reused.bitmap) != 2 {
		t.Fatalf("reused bitmap len = %d, want 2", len(reused.bitmap))
	}
}

func TestMatchDomainBitmapWithPoolFallsBackToMatcher(t *testing.T) {
	matcher := &testDomainMatcher{bitmap: []uint32{7, 9}}

	bitmap, buffer, err := MatchDomainBitmapWithPool(matcher, nil, "example.com")
	if err != nil {
		t.Fatalf("MatchDomainBitmapWithPool error: %v", err)
	}
	if buffer != nil {
		t.Fatal("buffer must be nil for fallback matcher")
	}
	if len(bitmap) != 2 || bitmap[0] != 7 || bitmap[1] != 9 {
		t.Fatalf("unexpected bitmap: %#v", bitmap)
	}
}

func BenchmarkMatchDomainBitmapWithPool(b *testing.B) {
	matcher := &testDomainMatcherInto{}
	pool := NewDomainBitmapPool(matcher, 1024)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, buffer, err := MatchDomainBitmapWithPool(matcher, pool, "example.com")
		if err != nil {
			b.Fatal(err)
		}
		if buffer == nil {
			b.Fatal("expected pooled bitmap buffer")
		}
		PutDomainBitmap(pool, buffer)
	}
}
