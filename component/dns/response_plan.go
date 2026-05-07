/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

type DnsResponseDecisionKind uint8

const (
	DnsResponseDecisionAccept DnsResponseDecisionKind = iota
	DnsResponseDecisionReject
	DnsResponseDecisionRetry
)

type DnsResponseDecision struct {
	Kind          DnsResponseDecisionKind
	UpstreamIndex consts.DnsResponseOutboundIndex
	Upstream      *Upstream
}

type rustDnsResponseDecision struct {
	Kind          DnsResponseDecisionKind
	UpstreamIndex consts.DnsResponseOutboundIndex
}

func (s *Dns) PlanResponse(msg *dnsmessage.Msg, fromUpstream *Upstream) (DnsResponseDecision, error) {
	qname, qtype, ips, from, err := responseRoutingInputFromMsg(msg, fromUpstream)
	if err != nil {
		return DnsResponseDecision{}, err
	}
	if s.rustRouting != nil {
		return s.planResponseRust(qname, qtype, ips, from)
	}
	return s.planResponseGo(qname, qtype, ips, from)
}

func (s *Dns) planResponseGo(
	qname string,
	qtype uint16,
	ips []netip.Addr,
	from consts.DnsRequestOutboundIndex,
) (DnsResponseDecision, error) {
	upstreamIndex, err := s.matchResponse(qname, qtype, ips, from)
	if err != nil {
		return DnsResponseDecision{}, err
	}
	return s.resolveResponseDecision(upstreamIndex)
}

func (s *Dns) planResponseRust(
	qname string,
	qtype uint16,
	ips []netip.Addr,
	from consts.DnsRequestOutboundIndex,
) (DnsResponseDecision, error) {
	decision, err := s.rustRouting.PlanResponse(qname, qtype, ips, from)
	if err != nil {
		return DnsResponseDecision{}, err
	}
	return s.resolveRustResponseDecision(decision)
}

func (s *Dns) resolveRustResponseDecision(decision rustDnsResponseDecision) (DnsResponseDecision, error) {
	switch decision.Kind {
	case DnsResponseDecisionAccept:
		return DnsResponseDecision{
			Kind:          DnsResponseDecisionAccept,
			UpstreamIndex: consts.DnsResponseOutboundIndex_Accept,
		}, nil
	case DnsResponseDecisionReject:
		return DnsResponseDecision{
			Kind:          DnsResponseDecisionReject,
			UpstreamIndex: consts.DnsResponseOutboundIndex_Reject,
		}, nil
	case DnsResponseDecisionRetry:
		upstream, err := s.resolveResponseSelection(decision.UpstreamIndex)
		if err != nil {
			return DnsResponseDecision{}, err
		}
		return DnsResponseDecision{
			Kind:          DnsResponseDecisionRetry,
			UpstreamIndex: decision.UpstreamIndex,
			Upstream:      upstream,
		}, nil
	default:
		return DnsResponseDecision{}, fmt.Errorf("unknown rust dns response decision kind: %d", decision.Kind)
	}
}

func (s *Dns) resolveResponseDecision(upstreamIndex consts.DnsResponseOutboundIndex) (DnsResponseDecision, error) {
	switch upstreamIndex {
	case consts.DnsResponseOutboundIndex_Accept:
		return DnsResponseDecision{
			Kind:          DnsResponseDecisionAccept,
			UpstreamIndex: upstreamIndex,
		}, nil
	case consts.DnsResponseOutboundIndex_Reject:
		return DnsResponseDecision{
			Kind:          DnsResponseDecisionReject,
			UpstreamIndex: upstreamIndex,
		}, nil
	default:
		upstream, err := s.resolveResponseSelection(upstreamIndex)
		if err != nil {
			return DnsResponseDecision{}, err
		}
		return DnsResponseDecision{
			Kind:          DnsResponseDecisionRetry,
			UpstreamIndex: upstreamIndex,
			Upstream:      upstream,
		}, nil
	}
}

func responseRoutingInputFromMsg(msg *dnsmessage.Msg, fromUpstream *Upstream) (qname string, qtype uint16, ips []netip.Addr, from consts.DnsRequestOutboundIndex, err error) {
	if !msg.Response {
		return "", 0, nil, 0, fmt.Errorf("DNS response expected but DNS request received")
	}
	if len(msg.Question) == 0 {
		qname = ""
		qtype = 0
	} else {
		q := msg.Question[0]
		qname = q.Name
		qtype = q.Qtype
		for _, ans := range msg.Answer {
			var (
				ip netip.Addr
				ok bool
			)
			switch body := ans.(type) {
			case *dnsmessage.A:
				ip, ok = netip.AddrFromSlice(body.A)
			case *dnsmessage.AAAA:
				ip, ok = netip.AddrFromSlice(body.AAAA)
			}
			if ok {
				ips = append(ips, ip)
			}
		}
	}
	from = consts.DnsRequestOutboundIndex_AsIs
	if fromUpstream != nil {
		from = fromUpstream.Index
	}
	return qname, qtype, ips, from, nil
}
