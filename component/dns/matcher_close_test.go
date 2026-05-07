/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

type blockingDnsDomainMatcher struct {
	entered    chan struct{}
	release    chan struct{}
	closeCount atomic.Int32
}

func newBlockingDnsDomainMatcher() *blockingDnsDomainMatcher {
	return &blockingDnsDomainMatcher{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (m *blockingDnsDomainMatcher) AddSet(int, []string, consts.RoutingDomainKey) {}

func (m *blockingDnsDomainMatcher) Build() error { return nil }

func (m *blockingDnsDomainMatcher) MatchDomainBitmap(string) []uint32 {
	panic("MatchDomainBitmap should not be called when pooled MatchDomainBitmapInto is available")
}

func (m *blockingDnsDomainMatcher) MatchDomainBitmapInto(_ string, bitmap []uint32) error {
	select {
	case <-m.entered:
	default:
		close(m.entered)
	}
	<-m.release
	for i := range bitmap {
		bitmap[i] = 0
	}
	return nil
}

func (m *blockingDnsDomainMatcher) Close() {
	m.closeCount.Add(1)
}

var (
	_ routing.DomainMatcher       = (*blockingDnsDomainMatcher)(nil)
	_ routing.DomainMatcherInto   = (*blockingDnsDomainMatcher)(nil)
	_ routing.DomainMatcherCloser = (*blockingDnsDomainMatcher)(nil)
)

func TestRequestMatcherCloseWaitsForActiveMatch(t *testing.T) {
	domainMatcher := newBlockingDnsDomainMatcher()
	matcher := &RequestMatcher{
		domainMatcher:    domainMatcher,
		domainBitmapPool: routing.NewDomainBitmapPool(domainMatcher, 32),
		matches: []requestMatchSet{
			{
				Type:     consts.MatchType_Fallback,
				Upstream: uint8(consts.DnsRequestOutboundIndex_AsIs),
			},
		},
	}

	matchDone := make(chan error, 1)
	go func() {
		_, err := matcher.Match("example.com", uint16(1))
		matchDone <- err
	}()

	select {
	case <-domainMatcher.entered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for matcher to enter MatchDomainBitmapInto")
	}

	closeDone := make(chan struct{})
	go func() {
		matcher.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
		t.Fatal("Close returned before active Match completed")
	case <-time.After(25 * time.Millisecond):
	}

	close(domainMatcher.release)

	select {
	case err := <-matchDone:
		if err != nil {
			t.Fatalf("Match() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Match to complete")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Close to complete")
	}

	if got := domainMatcher.closeCount.Load(); got != 1 {
		t.Fatalf("domain matcher close count = %d, want 1", got)
	}
	if _, err := matcher.Match("example.com", uint16(1)); err == nil {
		t.Fatal("Match after Close() error = nil, want error")
	}
}
