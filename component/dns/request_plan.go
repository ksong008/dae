/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"fmt"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

type DnsRequestLookupPlan struct {
	QType         uint16
	UpstreamIndex consts.DnsRequestOutboundIndex
	Upstream      *Upstream
}

type DnsRequestPlan struct {
	Requested DnsRequestLookupPlan
	Preferred *DnsRequestLookupPlan
}

type rustDnsRequestActionPlan struct {
	QType         uint16
	UpstreamIndex consts.DnsRequestOutboundIndex
}

type rustDnsRequestPlan struct {
	Requested rustDnsRequestActionPlan
	Preferred *rustDnsRequestActionPlan
}

func (s *Dns) PlanRequest(qname string, qtype uint16) (DnsRequestPlan, error) {
	if s == nil {
		return DnsRequestPlan{}, fmt.Errorf("dns routing is nil")
	}
	if s.rustRouting != nil {
		return s.planRequestRust(qname, qtype)
	}
	return s.planRequestGo(qname, qtype)
}

func (s *Dns) planRequestGo(qname string, qtype uint16) (DnsRequestPlan, error) {
	requested, err := s.requestLookupPlan(qname, qtype)
	if err != nil {
		return DnsRequestPlan{}, err
	}
	plan := DnsRequestPlan{Requested: requested}
	if preferredQType, ok := preferredLookupQType(qtype, s.requestQTypePrefer); ok {
		preferred, err := s.requestLookupPlan(qname, preferredQType)
		if err != nil {
			return DnsRequestPlan{}, err
		}
		plan.Preferred = &preferred
	}
	return plan, nil
}

func (s *Dns) planRequestRust(qname string, qtype uint16) (DnsRequestPlan, error) {
	plan, err := s.rustRouting.PlanRequest(qname, qtype, s.requestQTypePrefer)
	if err != nil {
		return DnsRequestPlan{}, err
	}
	return s.resolveRustRequestPlan(plan)
}

func (s *Dns) resolveRustRequestPlan(plan rustDnsRequestPlan) (DnsRequestPlan, error) {
	requested, err := s.resolveRustRequestLookup(plan.Requested)
	if err != nil {
		return DnsRequestPlan{}, err
	}
	resolved := DnsRequestPlan{Requested: requested}
	if plan.Preferred != nil {
		preferred, err := s.resolveRustRequestLookup(*plan.Preferred)
		if err != nil {
			return DnsRequestPlan{}, err
		}
		resolved.Preferred = &preferred
	}
	return resolved, nil
}

func (s *Dns) resolveRustRequestLookup(plan rustDnsRequestActionPlan) (DnsRequestLookupPlan, error) {
	upstreamIndex, upstream, err := s.resolveRequestSelection(plan.UpstreamIndex)
	if err != nil {
		return DnsRequestLookupPlan{}, err
	}
	return DnsRequestLookupPlan{
		QType:         plan.QType,
		UpstreamIndex: upstreamIndex,
		Upstream:      upstream,
	}, nil
}

func (s *Dns) requestLookupPlan(qname string, qtype uint16) (DnsRequestLookupPlan, error) {
	upstreamIndex, upstream, err := s.RequestSelect(qname, qtype)
	if err != nil {
		return DnsRequestLookupPlan{}, err
	}
	return DnsRequestLookupPlan{
		QType:         qtype,
		UpstreamIndex: upstreamIndex,
		Upstream:      upstream,
	}, nil
}

func preferredLookupQType(qtype uint16, preferred uint16) (uint16, bool) {
	if preferred == 0 || preferred == qtype {
		return 0, false
	}
	switch qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if preferred != dnsmessage.TypeA && preferred != dnsmessage.TypeAAAA {
			return 0, false
		}
		return preferred, true
	default:
		return 0, false
	}
}
