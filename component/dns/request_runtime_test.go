/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

func TestRequestRuntimePreferredCacheRejectsRequestedQuery(t *testing.T) {
	runtime := NewRequestRuntime()
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)

	preferredCacheKey := dnsmessage.CanonicalName("example.com.") + "28"
	outcome, err := runtime.HandleRequest(
		msg,
		DnsRequestPlan{
			Requested: DnsRequestLookupPlan{
				QType:         dnsmessage.TypeA,
				UpstreamIndex: consts.DnsRequestOutboundIndex(0),
			},
			Preferred: &DnsRequestLookupPlan{
				QType:         dnsmessage.TypeAAAA,
				UpstreamIndex: consts.DnsRequestOutboundIndex(0),
			},
		},
		true,
		true,
		RequestRuntimeHooks{
			LookupCacheEntry: func(cacheKey string, ignoreFixedTtl bool) *DnsCache {
				if cacheKey == preferredCacheKey {
					return &DnsCache{HasAnyIP: true}
				}
				return nil
			},
			LookupCacheResp: func(*dnsmessage.Msg, string, bool) []byte { return nil },
			RemoveCache:     func(string) {},
			ExecuteLookup:   func(*dnsmessage.Msg, DnsRequestLookupPlan, bool) error { return nil },
			NextMessageID:   func() uint16 { return 999 },
		},
	)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !outcome.Reject {
		t.Fatal("expected preferred cache hit to reject requested query")
	}
}

func TestRequestRuntimeReturnsCachedRequestedResponseAfterDualLookup(t *testing.T) {
	runtime := NewRequestRuntime()
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)

	requestedResp := []byte{1, 2, 3}
	requestedCacheKey := dnsmessage.CanonicalName("example.com.") + "1"
	outcome, err := runtime.HandleRequest(
		msg,
		DnsRequestPlan{
			Requested: DnsRequestLookupPlan{
				QType:         dnsmessage.TypeA,
				UpstreamIndex: consts.DnsRequestOutboundIndex(0),
			},
			Preferred: &DnsRequestLookupPlan{
				QType:         dnsmessage.TypeAAAA,
				UpstreamIndex: consts.DnsRequestOutboundIndex(0),
			},
		},
		true,
		true,
		RequestRuntimeHooks{
			LookupCacheEntry: func(string, bool) *DnsCache { return nil },
			LookupCacheResp: func(_ *dnsmessage.Msg, cacheKey string, ignoreFixedTtl bool) []byte {
				if cacheKey == requestedCacheKey && ignoreFixedTtl {
					return requestedResp
				}
				return nil
			},
			RemoveCache:   func(string) {},
			ExecuteLookup: func(*dnsmessage.Msg, DnsRequestLookupPlan, bool) error { return nil },
			NextMessageID: func() uint16 { return 999 },
		},
	)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if string(outcome.CachedResponse) != string(requestedResp) {
		t.Fatalf("unexpected cached response: %v", outcome.CachedResponse)
	}
}
