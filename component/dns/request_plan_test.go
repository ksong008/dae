/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestDnsPlanRequestDualStackPreference(t *testing.T) {
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

	plan, err := routing.PlanRequest("example.com.", uint16(dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("PlanRequest() error = %v", err)
	}
	if plan.Requested.QType != uint16(dnsmessage.TypeA) {
		t.Fatalf("requested qtype = %d, want %d", plan.Requested.QType, dnsmessage.TypeA)
	}
	if plan.Requested.UpstreamIndex != consts.DnsRequestOutboundIndex(0) {
		t.Fatalf("requested upstream = %v, want 0", plan.Requested.UpstreamIndex)
	}
	if plan.Preferred == nil {
		t.Fatal("expected preferred lookup plan for non-preferred A query")
	}
	if plan.Preferred.QType != uint16(dnsmessage.TypeAAAA) {
		t.Fatalf("preferred qtype = %d, want %d", plan.Preferred.QType, dnsmessage.TypeAAAA)
	}
	if plan.Preferred.UpstreamIndex != consts.DnsRequestOutboundIndex(0) {
		t.Fatalf("preferred upstream = %v, want 0", plan.Preferred.UpstreamIndex)
	}

	nonIPPlan, err := routing.PlanRequest("example.com.", uint16(dnsmessage.TypeMX))
	if err != nil {
		t.Fatalf("PlanRequest(non-IP) error = %v", err)
	}
	if nonIPPlan.Preferred != nil {
		t.Fatalf("expected no preferred lookup for MX query, got %+v", *nonIPPlan.Preferred)
	}

	preferredPlan, err := routing.PlanRequest("example.com.", uint16(dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatalf("PlanRequest(preferred) error = %v", err)
	}
	if preferredPlan.Preferred != nil {
		t.Fatalf("expected no preferred lookup for already-preferred AAAA query, got %+v", *preferredPlan.Preferred)
	}
}
