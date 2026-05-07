/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

func TestRequestFlowRuntimeRejectRemovesCacheAndReturnsReject(t *testing.T) {
	runtime := NewRequestFlowRuntime()
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)

	removed := 0
	outcome, err := runtime.HandlePlannedRequest(
		msg,
		DnsRequestLookupPlan{
			QType:         dnsmessage.TypeA,
			UpstreamIndex: consts.DnsRequestOutboundIndex_Reject,
		},
		"example.com.1",
		true,
		true,
		RequestFlowHooks{
			RemoveCache: func(string) {
				removed++
			},
		},
	)
	if err != nil {
		t.Fatalf("HandlePlannedRequest() error = %v", err)
	}
	if !outcome.Reject {
		t.Fatal("expected reject outcome")
	}
	if removed != 1 {
		t.Fatalf("expected one cache removal, got %d", removed)
	}
}

func TestRequestFlowRuntimeCacheHitShortCircuitsLookup(t *testing.T) {
	runtime := NewRequestFlowRuntime()
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)

	executed := 0
	resp := []byte{1, 2, 3}
	outcome, err := runtime.HandlePlannedRequest(
		msg,
		DnsRequestLookupPlan{
			QType:         dnsmessage.TypeA,
			UpstreamIndex: consts.DnsRequestOutboundIndex(0),
		},
		"example.com.1",
		true,
		true,
		RequestFlowHooks{
			LookupCache: func(*dnsmessage.Msg, string, bool) []byte {
				return resp
			},
			ExecuteLookup: func(*dnsmessage.Msg, DnsRequestLookupPlan, bool) error {
				executed++
				return nil
			},
		},
	)
	if err != nil {
		t.Fatalf("HandlePlannedRequest() error = %v", err)
	}
	if executed != 0 {
		t.Fatalf("expected lookup executor not to run, got %d", executed)
	}
	if string(outcome.CachedResponse) != string(resp) {
		t.Fatalf("unexpected cached response: %v", outcome.CachedResponse)
	}
}

func TestRequestFlowRuntimeSerializesSameKeyLookups(t *testing.T) {
	runtime := NewRequestFlowRuntime()
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)

	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var active atomic.Int32
	var maxActive atomic.Int32

	run := func(done chan error) {
		_, err := runtime.HandlePlannedRequest(
			msg.Copy(),
			DnsRequestLookupPlan{
				QType:         dnsmessage.TypeA,
				UpstreamIndex: consts.DnsRequestOutboundIndex(0),
			},
			"example.com.1",
			false,
			true,
			RequestFlowHooks{
				ExecuteLookup: func(*dnsmessage.Msg, DnsRequestLookupPlan, bool) error {
					current := active.Add(1)
					for {
						prev := maxActive.Load()
						if current <= prev || maxActive.CompareAndSwap(prev, current) {
							break
						}
					}
					started <- struct{}{}
					<-release
					active.Add(-1)
					return nil
				},
			},
		)
		done <- err
	}

	done1 := make(chan error, 1)
	done2 := make(chan error, 1)
	go run(done1)
	<-started
	go run(done2)
	select {
	case <-started:
		t.Fatal("expected second lookup to wait on first for same key")
	default:
	}
	close(release)
	if err := <-done1; err != nil {
		t.Fatalf("first lookup error = %v", err)
	}
	if err := <-done2; err != nil {
		t.Fatalf("second lookup error = %v", err)
	}
	if maxActive.Load() != 1 {
		t.Fatalf("expected max active lookups to be 1, got %d", maxActive.Load())
	}
}
