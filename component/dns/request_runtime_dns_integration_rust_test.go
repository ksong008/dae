//go:build rust_dns_request_matcher && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"testing"

	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestRustDnsRequestRuntimeDnsNewIntegration(t *testing.T) {
	routing, err := New(&config.Dns{
		Upstream: []config.KeyableString{
			"test:udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "test",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}, &NewOption{
		Logger:             logrus.New(),
		RequestQTypePrefer: uint16(dnsmessage.TypeAAAA),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer routing.Close()

	if routing.rustRouting == nil {
		t.Fatal("expected Rust DNS routing runtime to be installed on Dns")
	}
	if routing.reqMatcher != nil {
		t.Fatalf("expected Go request matcher shell to be bypassed, got %T", routing.reqMatcher)
	}
	if routing.respMatcher != nil {
		t.Fatalf("expected Go response matcher shell to be bypassed, got %T", routing.respMatcher)
	}

	requestUpstream, _, err := routing.RequestSelect("example.com.", uint16(dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("RequestSelect() error = %v", err)
	}
	if requestUpstream != 0 {
		t.Fatalf("RequestSelect() upstream = %v, want 0", requestUpstream)
	}

	plan, err := routing.PlanRequest("example.com.", uint16(dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("PlanRequest() error = %v", err)
	}
	if plan.Preferred == nil || plan.Preferred.QType != uint16(dnsmessage.TypeAAAA) {
		t.Fatalf("PlanRequest() preferred = %+v, want AAAA lookup", plan.Preferred)
	}
}

func BenchmarkRustDnsRoutingRequestSelectSharedFixture(b *testing.B) {
	routing, err := New(&config.Dns{
		Upstream: []config.KeyableString{
			"test:udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "test",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}, &NewOption{
		Logger: logrus.New(),
	})
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer routing.Close()
	qname := "example.com."
	qtype := uint16(dnsmessage.TypeA)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		upstream, _, err := routing.RequestSelect(qname, qtype)
		if err != nil {
			b.Fatalf("RequestSelect() error = %v", err)
		}
		if upstream != 0 {
			b.Fatalf("RequestSelect() upstream = %v, want 0", upstream)
		}
	}
}

func BenchmarkRustDnsRoutingPlanRequestSharedFixture(b *testing.B) {
	routing, err := New(&config.Dns{
		Upstream: []config.KeyableString{
			"test:udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "test",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}, &NewOption{
		Logger:             logrus.New(),
		RequestQTypePrefer: uint16(dnsmessage.TypeAAAA),
	})
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	defer routing.Close()
	qname := "example.com."
	qtype := uint16(dnsmessage.TypeA)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plan, err := routing.PlanRequest(qname, qtype)
		if err != nil {
			b.Fatalf("PlanRequest() error = %v", err)
		}
		if plan.Requested.UpstreamIndex != 0 {
			b.Fatalf("PlanRequest() requested upstream = %v, want 0", plan.Requested.UpstreamIndex)
		}
		if plan.Preferred == nil || plan.Preferred.UpstreamIndex != 0 {
			b.Fatalf("PlanRequest() preferred plan = %+v, want upstream 0", plan.Preferred)
		}
	}
}
