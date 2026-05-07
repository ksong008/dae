/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	dnsmessage "github.com/miekg/dns"
)

type DnsExchangeMeta struct {
	L4Proto        consts.L4ProtoStr
	UpstreamName   string
	RetriedOverTCP bool
}

func AsIsUpstream(realDst netip.AddrPort) *Upstream {
	upstream := &Upstream{
		Scheme:   UpstreamScheme_UDP,
		Hostname: realDst.Addr().String(),
		Port:     realDst.Port(),
		Ip46:     &netutils.Ip46{},
	}
	if realDst.Addr().Is4() {
		upstream.Ip46.Ip4 = realDst.Addr()
	} else if realDst.Addr().Is6() {
		upstream.Ip46.Ip6 = realDst.Addr()
	}
	return upstream
}

func ValidateResponseForRequest(reqMsg *dnsmessage.Msg, respMsg *dnsmessage.Msg, requireMatchingID bool) error {
	if respMsg == nil {
		return fmt.Errorf("dns response is nil")
	}
	if !respMsg.Response {
		return fmt.Errorf("dns response expected but dns request received")
	}
	if requireMatchingID && respMsg.Id != reqMsg.Id {
		return fmt.Errorf("dns response id mismatch: got %d want %d", respMsg.Id, reqMsg.Id)
	}
	if len(reqMsg.Question) == 0 {
		return nil
	}
	if len(respMsg.Question) == 0 {
		return fmt.Errorf("dns response missing question")
	}
	if len(respMsg.Question) != len(reqMsg.Question) {
		return fmt.Errorf("dns response question count mismatch: got %d want %d", len(respMsg.Question), len(reqMsg.Question))
	}
	for i := range reqMsg.Question {
		if responseQuestionsEqual(reqMsg.Question[i], respMsg.Question[i]) {
			continue
		}
		return fmt.Errorf(
			"dns response question mismatch at index %d: got %s want %s",
			i,
			formatResponseQuestion(respMsg.Question[i]),
			formatResponseQuestion(reqMsg.Question[i]),
		)
	}
	return nil
}

func ShouldValidateResponseID(upstream *Upstream) bool {
	if upstream == nil {
		return false
	}
	switch upstream.Scheme {
	case UpstreamScheme_UDP, UpstreamScheme_TCP, UpstreamScheme_TCP_UDP, UpstreamScheme_TLS:
		return true
	default:
		return false
	}
}

func ShouldRetryTruncatedResponseOverTCP(respMsg *dnsmessage.Msg, upstream *Upstream, l4proto consts.L4ProtoStr) bool {
	if respMsg == nil || upstream == nil {
		return false
	}
	if !respMsg.Truncated || l4proto != consts.L4ProtoStr_UDP {
		return false
	}
	return upstream.Scheme == UpstreamScheme_TCP_UDP
}

func FormatResponseQuestion(msg *dnsmessage.Msg) string {
	if msg == nil || len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	return strings.ToLower(q.Name) + " " + qtypeToString(q.Qtype)
}

func canonicalResponseQuestionName(name string) string {
	if name == "" {
		return ""
	}
	return dnsmessage.CanonicalName(name)
}

func responseQuestionsEqual(a, b dnsmessage.Question) bool {
	return canonicalResponseQuestionName(a.Name) == canonicalResponseQuestionName(b.Name) &&
		a.Qtype == b.Qtype &&
		a.Qclass == b.Qclass
}

func formatResponseQuestion(q dnsmessage.Question) string {
	return fmt.Sprintf("%s %s class=%d", strings.ToLower(canonicalResponseQuestionName(q.Name)), qtypeToString(q.Qtype), q.Qclass)
}

func qtypeToString(qtype uint16) string {
	if str, ok := dnsmessage.TypeToString[qtype]; ok {
		return str
	}
	return strconv.Itoa(int(qtype))
}
