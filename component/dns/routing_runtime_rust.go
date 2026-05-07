//go:build rust_dns_request_matcher && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

/*
#cgo LDFLAGS: -L${SRCDIR}/../../rust/target/release -ldae_domain_matcher -lm -ldl -lpthread
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

typedef struct FfiDnsRequestMatcher DaeDnsRequestMatcher;
typedef struct FfiDnsResponseMatcher DaeDnsResponseMatcher;
typedef struct FfiDnsRouting DaeDnsRouting;

int32_t dae_dns_routing_new(DaeDnsRequestMatcher* request_matcher, DaeDnsResponseMatcher* response_matcher, DaeDnsRouting** out_routing);
void dae_dns_routing_free(DaeDnsRouting* routing);
int32_t dae_dns_routing_match_request_bytes(const DaeDnsRouting* routing, const uint8_t* qname, uintptr_t qname_len, uint16_t qtype, int16_t* out_action);
int32_t dae_dns_routing_plan_request_bytes(const DaeDnsRouting* routing, const uint8_t* qname, uintptr_t qname_len, uint16_t qtype, uint16_t preferred_qtype, _Bool* out_has_preferred, int16_t* out_requested_action, int16_t* out_preferred_action);
int32_t dae_dns_routing_match_response_bytes(const DaeDnsRouting* routing, const uint8_t* qname, uintptr_t qname_len, uint16_t qtype, int16_t request_upstream, const uint8_t* ips, uintptr_t ips_len, int16_t* out_action);
int32_t dae_dns_routing_plan_response_bytes(const DaeDnsRouting* routing, const uint8_t* qname, uintptr_t qname_len, uint16_t qtype, int16_t request_upstream, const uint8_t* ips, uintptr_t ips_len, uint8_t* out_decision_kind, int16_t* out_retry_action);
const char* dae_domain_matcher_last_error(void);
*/
import "C"

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/daeuniverse/dae/common/consts"
)

type rustDnsRoutingRuntime struct {
	routing *C.DaeDnsRouting
}

func newRustDnsRoutingRuntime(reqBuilder *RequestMatcherBuilder, respBuilder *ResponseMatcherBuilder) (*rustDnsRoutingRuntime, error) {
	reqRuntime, err := newRequestMatcherRuntime(consts.MaxMatchSetLen, reqBuilder.simulatedDomainSet, reqBuilder.rules)
	if err != nil {
		return nil, err
	}
	respRuntime, err := newResponseMatcherRuntime(consts.MaxMatchSetLen, respBuilder.simulatedDomainSet, respBuilder.simulatedIpPrefixes, respBuilder.rules)
	if err != nil {
		reqRuntime.Close()
		return nil, err
	}
	var routing *C.DaeDnsRouting
	if status := C.dae_dns_routing_new(reqRuntime.matcher, respRuntime.matcher, &routing); status != 0 {
		err := rustDnsRoutingLastError("build routing runtime")
		reqRuntime.Close()
		respRuntime.Close()
		return nil, err
	}
	reqRuntime.matcher = nil
	respRuntime.matcher = nil
	reqRuntime.Close()
	respRuntime.Close()
	return &rustDnsRoutingRuntime{routing: routing}, nil
}

func (m *rustDnsRoutingRuntime) RequestMatch(qName string, qType uint16) (consts.DnsRequestOutboundIndex, error) {
	if m.routing == nil {
		return 0, fmt.Errorf("rust dns routing runtime used before successful build")
	}
	var qnamePtr *C.uint8_t
	if len(qName) > 0 {
		qnamePtr = (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(qName)))
	}
	var action C.int16_t
	if status := C.dae_dns_routing_match_request_bytes(
		m.routing,
		qnamePtr,
		C.uintptr_t(len(qName)),
		C.uint16_t(qType),
		&action,
	); status != 0 {
		return 0, rustDnsRoutingLastError("match request")
	}
	return consts.DnsRequestOutboundIndex(action), nil
}

func (m *rustDnsRoutingRuntime) PlanRequest(qName string, qType uint16, preferredQType uint16) (rustDnsRequestPlan, error) {
	if m.routing == nil {
		return rustDnsRequestPlan{}, fmt.Errorf("rust dns routing runtime used before successful build")
	}
	var qnamePtr *C.uint8_t
	if len(qName) > 0 {
		qnamePtr = (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(qName)))
	}
	var (
		hasPreferred    C.bool
		requestedAction C.int16_t
		preferredAction C.int16_t
	)
	if status := C.dae_dns_routing_plan_request_bytes(
		m.routing,
		qnamePtr,
		C.uintptr_t(len(qName)),
		C.uint16_t(qType),
		C.uint16_t(preferredQType),
		&hasPreferred,
		&requestedAction,
		&preferredAction,
	); status != 0 {
		return rustDnsRequestPlan{}, rustDnsRoutingLastError("plan request")
	}
	plan := rustDnsRequestPlan{
		Requested: rustDnsRequestActionPlan{
			QType:         qType,
			UpstreamIndex: consts.DnsRequestOutboundIndex(requestedAction),
		},
	}
	if bool(hasPreferred) {
		plan.Preferred = &rustDnsRequestActionPlan{
			QType:         preferredQType,
			UpstreamIndex: consts.DnsRequestOutboundIndex(preferredAction),
		}
	}
	return plan, nil
}

func (m *rustDnsRoutingRuntime) ResponseMatch(qName string, qType uint16, ips []netip.Addr, upstream consts.DnsRequestOutboundIndex) (consts.DnsResponseOutboundIndex, error) {
	if m.routing == nil {
		return 0, fmt.Errorf("rust dns routing runtime used before successful build")
	}
	var qnamePtr *C.uint8_t
	if len(qName) > 0 {
		qnamePtr = (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(qName)))
	}
	ipBytes := make([]byte, 0, len(ips)*16)
	for _, ip := range ips {
		addr := ip.As16()
		ipBytes = append(ipBytes, addr[:]...)
	}
	var ipsPtr *C.uint8_t
	if len(ipBytes) > 0 {
		ipsPtr = (*C.uint8_t)(unsafe.Pointer(&ipBytes[0]))
	}
	var action C.int16_t
	if status := C.dae_dns_routing_match_response_bytes(
		m.routing,
		qnamePtr,
		C.uintptr_t(len(qName)),
		C.uint16_t(qType),
		C.int16_t(upstream),
		ipsPtr,
		C.uintptr_t(len(ipBytes)),
		&action,
	); status != 0 {
		return 0, rustDnsRoutingLastError("match response")
	}
	return consts.DnsResponseOutboundIndex(action), nil
}

func (m *rustDnsRoutingRuntime) PlanResponse(qName string, qType uint16, ips []netip.Addr, upstream consts.DnsRequestOutboundIndex) (rustDnsResponseDecision, error) {
	if m.routing == nil {
		return rustDnsResponseDecision{}, fmt.Errorf("rust dns routing runtime used before successful build")
	}
	var qnamePtr *C.uint8_t
	if len(qName) > 0 {
		qnamePtr = (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(qName)))
	}
	ipBytes := make([]byte, 0, len(ips)*16)
	for _, ip := range ips {
		addr := ip.As16()
		ipBytes = append(ipBytes, addr[:]...)
	}
	var ipsPtr *C.uint8_t
	if len(ipBytes) > 0 {
		ipsPtr = (*C.uint8_t)(unsafe.Pointer(&ipBytes[0]))
	}
	var (
		decisionKind C.uint8_t
		retryAction  C.int16_t
	)
	if status := C.dae_dns_routing_plan_response_bytes(
		m.routing,
		qnamePtr,
		C.uintptr_t(len(qName)),
		C.uint16_t(qType),
		C.int16_t(upstream),
		ipsPtr,
		C.uintptr_t(len(ipBytes)),
		&decisionKind,
		&retryAction,
	); status != 0 {
		return rustDnsResponseDecision{}, rustDnsRoutingLastError("plan response")
	}
	decision := rustDnsResponseDecision{
		Kind: DnsResponseDecisionKind(decisionKind),
	}
	if decision.Kind == DnsResponseDecisionRetry {
		decision.UpstreamIndex = consts.DnsResponseOutboundIndex(retryAction)
	}
	return decision, nil
}

func (m *rustDnsRoutingRuntime) Close() {
	if m.routing != nil {
		C.dae_dns_routing_free(m.routing)
		m.routing = nil
	}
}

func rustDnsRoutingLastError(operation string) error {
	msg := C.dae_domain_matcher_last_error()
	if msg == nil {
		return fmt.Errorf("rust dns routing runtime %s failed", operation)
	}
	return fmt.Errorf("rust dns routing runtime %s failed: %s", operation, C.GoString(msg))
}
