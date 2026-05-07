//go:build rust_domain_matcher && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestRustDomainMatcherDnsNewIntegration(t *testing.T) {
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
		t.Fatalf("New() error = %v", err)
	}
	defer routing.Close()

	if _, ok := routing.reqMatcher.domainMatcher.(*domain_matcher.RustDomainMatcher); !ok {
		t.Fatalf("request matcher domain matcher type = %T, want *domain_matcher.RustDomainMatcher", routing.reqMatcher.domainMatcher)
	}
	if _, ok := routing.respMatcher.domainMatcher.(*domain_matcher.RustDomainMatcher); !ok {
		t.Fatalf("response matcher domain matcher type = %T, want *domain_matcher.RustDomainMatcher", routing.respMatcher.domainMatcher)
	}

	requestUpstream, err := routing.reqMatcher.Match("example.com.", uint16(dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("request matcher Match() error = %v", err)
	}
	if requestUpstream != 0 {
		t.Fatalf("request matcher upstream = %v, want 0", requestUpstream)
	}

	responseUpstream, err := routing.respMatcher.Match("example.com.", uint16(dnsmessage.TypeA), nil, consts.DnsRequestOutboundIndex(0))
	if err != nil {
		t.Fatalf("response matcher Match() error = %v", err)
	}
	if responseUpstream != consts.DnsResponseOutboundIndex_Accept {
		t.Fatalf("response matcher upstream = %v, want accept", responseUpstream)
	}
}
