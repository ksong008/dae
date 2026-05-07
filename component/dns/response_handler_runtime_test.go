/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestResponseHandlerRuntimeRejectClearsAnswersAndPacks(t *testing.T) {
	now := time.Now()
	cache := NewDnsCacheRuntime(logrus.New(), 8, nil, DnsCacheHooks{}, func() time.Time { return now })
	runtime := NewResponseHandlerRuntime(cache)

	req := new(dnsmessage.Msg)
	req.Id = 1234
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	resp := new(dnsmessage.Msg)
	resp.SetReply(req)
	resp.Answer = []dnsmessage.RR{newTestResponseARecord("example.com.", "1.1.1.1")}

	outcome, err := runtime.FinalizeResponse(resp, DnsResponseDecision{
		Kind:          DnsResponseDecisionReject,
		UpstreamIndex: consts.DnsResponseOutboundIndex_Reject,
	}, req.Id, true)
	if err != nil {
		t.Fatalf("FinalizeResponse() error = %v", err)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected reject finalization to clear answers, got %v", resp.Answer)
	}
	if len(outcome.PackedResponse) == 0 {
		t.Fatal("expected packed response bytes")
	}
}

func TestResponseHandlerRuntimeAcceptCachesAndPacks(t *testing.T) {
	now := time.Now()
	cache := NewDnsCacheRuntime(logrus.New(), 8, nil, DnsCacheHooks{}, func() time.Time { return now })
	runtime := NewResponseHandlerRuntime(cache)

	req := new(dnsmessage.Msg)
	req.Id = 5678
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	resp := new(dnsmessage.Msg)
	resp.SetReply(req)
	resp.Answer = []dnsmessage.RR{newTestResponseARecord("example.com.", "2.2.2.2")}

	outcome, err := runtime.FinalizeResponse(resp, DnsResponseDecision{
		Kind:          DnsResponseDecisionAccept,
		UpstreamIndex: consts.DnsResponseOutboundIndex_Accept,
	}, req.Id, true)
	if err != nil {
		t.Fatalf("FinalizeResponse() error = %v", err)
	}
	if len(outcome.PackedResponse) == 0 {
		t.Fatal("expected packed response bytes")
	}
	cacheEntry := cache.Lookup(dnsmessage.CanonicalName("example.com.")+"1", false)
	if cacheEntry == nil || !cacheEntry.IncludeIp(netip.MustParseAddr("2.2.2.2")) {
		t.Fatalf("expected cached dns response, got %+v", cacheEntry)
	}
}
