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

typedef struct FfiDnsResponseMatcherBuilder DaeDnsResponseMatcherBuilder;
typedef struct FfiDnsResponseMatcher DaeDnsResponseMatcher;

DaeDnsResponseMatcherBuilder* dae_dns_response_matcher_builder_new(uintptr_t bit_len);
void dae_dns_response_matcher_builder_free(DaeDnsResponseMatcherBuilder* builder);
int32_t dae_dns_response_matcher_builder_add_domain_pattern(DaeDnsResponseMatcherBuilder* builder, uintptr_t bit_index, uint32_t kind, const char* pattern);
int32_t dae_dns_response_matcher_builder_add_rule(DaeDnsResponseMatcherBuilder* builder, int16_t action, uintptr_t* out_rule_index);
int32_t dae_dns_response_matcher_builder_add_rule_domain_bit(DaeDnsResponseMatcherBuilder* builder, uintptr_t rule_index, uintptr_t bit_index, _Bool not);
int32_t dae_dns_response_matcher_builder_add_rule_qtypes(DaeDnsResponseMatcherBuilder* builder, uintptr_t rule_index, const uint16_t* values, uintptr_t values_len, _Bool not);
int32_t dae_dns_response_matcher_builder_add_rule_upstreams(DaeDnsResponseMatcherBuilder* builder, uintptr_t rule_index, const int16_t* values, uintptr_t values_len, _Bool not);
int32_t dae_dns_response_matcher_builder_add_rule_ip_set(DaeDnsResponseMatcherBuilder* builder, uintptr_t rule_index, uintptr_t set_index, _Bool not);
int32_t dae_dns_response_matcher_builder_add_ip_prefix(DaeDnsResponseMatcherBuilder* builder, uintptr_t set_index, const uint8_t* addr, uintptr_t addr_len, uint8_t prefix_bits);
int32_t dae_dns_response_matcher_builder_add_rule_fallback(DaeDnsResponseMatcherBuilder* builder, uintptr_t rule_index);
int32_t dae_dns_response_matcher_builder_build(const DaeDnsResponseMatcherBuilder* builder, DaeDnsResponseMatcher** out_matcher);
void dae_dns_response_matcher_free(DaeDnsResponseMatcher* matcher);
int32_t dae_dns_response_matcher_match_bytes(const DaeDnsResponseMatcher* matcher, const uint8_t* qname, uintptr_t qname_len, uint16_t qtype, int16_t request_upstream, const uint8_t* ips, uintptr_t ips_len, int16_t* out_action);
const char* dae_domain_matcher_last_error(void);
*/
import "C"

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

type rustDnsResponseMatcherRuntime struct {
	builder *C.DaeDnsResponseMatcherBuilder
	matcher *C.DaeDnsResponseMatcher
}

type rustResponseConditionSpec struct {
	domainBit *rustRequestDomainBitSpec
	qtypes    *rustRequestQTypeSpec
	upstreams *rustResponseUpstreamSpec
	ipSet     *rustResponseIpSetSpec
	fallback  bool
}

type rustResponseUpstreamSpec struct {
	values []int16
	not    bool
}

type rustResponseIpSetSpec struct {
	setIndex int
	not      bool
}

type rustResponseRuleSpec struct {
	conditions []rustResponseConditionSpec
	action     consts.DnsResponseOutboundIndex
}

func newResponseMatcherRuntime(bitLength int, domainSets []routing.DomainSet, ipSets [][]netip.Prefix, rules []responseMatchSet) (*rustDnsResponseMatcherRuntime, error) {
	runtime := &rustDnsResponseMatcherRuntime{
		builder: C.dae_dns_response_matcher_builder_new(C.uintptr_t(bitLength)),
	}
	if runtime.builder == nil {
		return nil, fmt.Errorf("rust dns response matcher builder is nil")
	}
	for _, set := range domainSets {
		kind, err := rustRequestDomainKind(set.Key)
		if err != nil {
			runtime.Close()
			return nil, err
		}
		for _, pattern := range set.Domains {
			cPattern := C.CString(pattern)
			status := C.dae_dns_response_matcher_builder_add_domain_pattern(
				runtime.builder,
				C.uintptr_t(set.RuleIndex),
				C.uint32_t(kind),
				cPattern,
			)
			C.free(unsafe.Pointer(cPattern))
			if status != 0 {
				err := rustDnsResponseLastError("add domain pattern")
				runtime.Close()
				return nil, err
			}
		}
	}
	for setIndex, prefixes := range ipSets {
		for _, prefix := range prefixes {
			bits := prefix.Bits()
			if prefix.Addr().Is4() {
				bits += 96
			}
			addr := prefix.Addr().As16()
			if status := C.dae_dns_response_matcher_builder_add_ip_prefix(
				runtime.builder,
				C.uintptr_t(setIndex),
				(*C.uint8_t)(unsafe.Pointer(&addr[0])),
				C.uintptr_t(len(addr)),
				C.uint8_t(bits),
			); status != 0 {
				err := rustDnsResponseLastError("add ip prefix")
				runtime.Close()
				return nil, err
			}
		}
	}
	ruleSpecs, err := translateRustResponseRuleSpecs(rules)
	if err != nil {
		runtime.Close()
		return nil, err
	}
	for _, rule := range ruleSpecs {
		var ruleIndex C.uintptr_t
		if status := C.dae_dns_response_matcher_builder_add_rule(
			runtime.builder,
			C.int16_t(rule.action),
			&ruleIndex,
		); status != 0 {
			err := rustDnsResponseLastError("add rule")
			runtime.Close()
			return nil, err
		}
		for _, condition := range rule.conditions {
			switch {
			case condition.domainBit != nil:
				if status := C.dae_dns_response_matcher_builder_add_rule_domain_bit(
					runtime.builder,
					ruleIndex,
					C.uintptr_t(condition.domainBit.bitIndex),
					C.bool(condition.domainBit.not),
				); status != 0 {
					err := rustDnsResponseLastError("add domain bit condition")
					runtime.Close()
					return nil, err
				}
			case condition.qtypes != nil:
				values := condition.qtypes.values
				if status := C.dae_dns_response_matcher_builder_add_rule_qtypes(
					runtime.builder,
					ruleIndex,
					(*C.uint16_t)(unsafe.Pointer(&values[0])),
					C.uintptr_t(len(values)),
					C.bool(condition.qtypes.not),
				); status != 0 {
					err := rustDnsResponseLastError("add qtype condition")
					runtime.Close()
					return nil, err
				}
			case condition.upstreams != nil:
				values := condition.upstreams.values
				if status := C.dae_dns_response_matcher_builder_add_rule_upstreams(
					runtime.builder,
					ruleIndex,
					(*C.int16_t)(unsafe.Pointer(&values[0])),
					C.uintptr_t(len(values)),
					C.bool(condition.upstreams.not),
				); status != 0 {
					err := rustDnsResponseLastError("add upstream condition")
					runtime.Close()
					return nil, err
				}
			case condition.ipSet != nil:
				if status := C.dae_dns_response_matcher_builder_add_rule_ip_set(
					runtime.builder,
					ruleIndex,
					C.uintptr_t(condition.ipSet.setIndex),
					C.bool(condition.ipSet.not),
				); status != 0 {
					err := rustDnsResponseLastError("add ip set condition")
					runtime.Close()
					return nil, err
				}
			case condition.fallback:
				if status := C.dae_dns_response_matcher_builder_add_rule_fallback(runtime.builder, ruleIndex); status != 0 {
					err := rustDnsResponseLastError("add fallback condition")
					runtime.Close()
					return nil, err
				}
			default:
				runtime.Close()
				return nil, fmt.Errorf("empty rust dns response condition")
			}
		}
	}
	var matcher *C.DaeDnsResponseMatcher
	if status := C.dae_dns_response_matcher_builder_build(runtime.builder, &matcher); status != 0 {
		err := rustDnsResponseLastError("build matcher")
		runtime.Close()
		return nil, err
	}
	C.dae_dns_response_matcher_builder_free(runtime.builder)
	runtime.builder = nil
	runtime.matcher = matcher
	return runtime, nil
}

func (m *rustDnsResponseMatcherRuntime) Match(qName string, qType uint16, ips []netip.Addr, upstream consts.DnsRequestOutboundIndex) (consts.DnsResponseOutboundIndex, error) {
	if m.matcher == nil {
		return 0, fmt.Errorf("rust dns response matcher used before successful build")
	}
	if qName == "" {
		return 0, fmt.Errorf("qName cannot be empty")
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
	if status := C.dae_dns_response_matcher_match_bytes(
		m.matcher,
		qnamePtr,
		C.uintptr_t(len(qName)),
		C.uint16_t(qType),
		C.int16_t(upstream),
		ipsPtr,
		C.uintptr_t(len(ipBytes)),
		&action,
	); status != 0 {
		return 0, rustDnsResponseLastError("match response")
	}
	return consts.DnsResponseOutboundIndex(action), nil
}

func (m *rustDnsResponseMatcherRuntime) Close() {
	if m.builder != nil {
		C.dae_dns_response_matcher_builder_free(m.builder)
		m.builder = nil
	}
	if m.matcher != nil {
		C.dae_dns_response_matcher_free(m.matcher)
		m.matcher = nil
	}
}

func translateRustResponseRuleSpecs(matches []responseMatchSet) ([]rustResponseRuleSpec, error) {
	var rules []rustResponseRuleSpec
	for i := 0; i < len(matches); {
		var (
			conditions []rustResponseConditionSpec
			action     consts.DnsResponseOutboundIndex
		)
		for {
			if i >= len(matches) {
				return nil, fmt.Errorf("unterminated dns response rule")
			}
			match := matches[i]
			switch match.Type {
			case consts.MatchType_DomainSet:
				conditions = append(conditions, rustResponseConditionSpec{
					domainBit: &rustRequestDomainBitSpec{
						bitIndex: i,
						not:      match.Not,
					},
				})
				action = consts.DnsResponseOutboundIndex(match.Upstream)
				i++
			case consts.MatchType_QType:
				qtypeNot := match.Not
				values := make([]uint16, 0, 1)
				for {
					values = append(values, match.Value)
					action = consts.DnsResponseOutboundIndex(match.Upstream)
					i++
					if action != consts.DnsResponseOutboundIndex_LogicalOr {
						break
					}
					if i >= len(matches) {
						return nil, fmt.Errorf("unterminated dns response qtype group")
					}
					match = matches[i]
					if match.Type != consts.MatchType_QType || match.Not != qtypeNot {
						return nil, fmt.Errorf("mixed dns response qtype group")
					}
				}
				conditions = append(conditions, rustResponseConditionSpec{
					qtypes: &rustRequestQTypeSpec{values: values, not: qtypeNot},
				})
			case consts.MatchType_Upstream:
				upstreamNot := match.Not
				values := make([]int16, 0, 1)
				for {
					values = append(values, int16(match.Value))
					action = consts.DnsResponseOutboundIndex(match.Upstream)
					i++
					if action != consts.DnsResponseOutboundIndex_LogicalOr {
						break
					}
					if i >= len(matches) {
						return nil, fmt.Errorf("unterminated dns response upstream group")
					}
					match = matches[i]
					if match.Type != consts.MatchType_Upstream || match.Not != upstreamNot {
						return nil, fmt.Errorf("mixed dns response upstream group")
					}
				}
				conditions = append(conditions, rustResponseConditionSpec{
					upstreams: &rustResponseUpstreamSpec{values: values, not: upstreamNot},
				})
			case consts.MatchType_IpSet:
				conditions = append(conditions, rustResponseConditionSpec{
					ipSet: &rustResponseIpSetSpec{
						setIndex: int(match.Value),
						not:      match.Not,
					},
				})
				action = consts.DnsResponseOutboundIndex(match.Upstream)
				i++
			case consts.MatchType_Fallback:
				conditions = append(conditions, rustResponseConditionSpec{fallback: true})
				action = consts.DnsResponseOutboundIndex(match.Upstream)
				i++
			default:
				return nil, fmt.Errorf("unsupported dns response match type for rust runtime: %v", match.Type)
			}

			if action == consts.DnsResponseOutboundIndex_LogicalAnd {
				continue
			}
			if action == consts.DnsResponseOutboundIndex_LogicalOr {
				return nil, fmt.Errorf("dns response rule ended on logical or")
			}
			rules = append(rules, rustResponseRuleSpec{
				conditions: conditions,
				action:     action,
			})
			break
		}
	}
	return rules, nil
}

func rustDnsResponseLastError(operation string) error {
	msg := C.dae_domain_matcher_last_error()
	if msg == nil {
		return fmt.Errorf("rust dns response matcher %s failed", operation)
	}
	return fmt.Errorf("rust dns response matcher %s failed: %s", operation, C.GoString(msg))
}
