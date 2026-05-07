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

typedef struct FfiDnsRequestMatcherBuilder DaeDnsRequestMatcherBuilder;
typedef struct FfiDnsRequestMatcher DaeDnsRequestMatcher;

DaeDnsRequestMatcherBuilder* dae_dns_request_matcher_builder_new(uintptr_t bit_len);
void dae_dns_request_matcher_builder_free(DaeDnsRequestMatcherBuilder* builder);
int32_t dae_dns_request_matcher_builder_add_domain_pattern(DaeDnsRequestMatcherBuilder* builder, uintptr_t bit_index, uint32_t kind, const char* pattern);
int32_t dae_dns_request_matcher_builder_add_rule(DaeDnsRequestMatcherBuilder* builder, int16_t action, uintptr_t* out_rule_index);
int32_t dae_dns_request_matcher_builder_add_rule_domain_bit(DaeDnsRequestMatcherBuilder* builder, uintptr_t rule_index, uintptr_t bit_index, _Bool not);
int32_t dae_dns_request_matcher_builder_add_rule_qtypes(DaeDnsRequestMatcherBuilder* builder, uintptr_t rule_index, const uint16_t* values, uintptr_t values_len, _Bool not);
int32_t dae_dns_request_matcher_builder_add_rule_fallback(DaeDnsRequestMatcherBuilder* builder, uintptr_t rule_index);
int32_t dae_dns_request_matcher_builder_build(const DaeDnsRequestMatcherBuilder* builder, DaeDnsRequestMatcher** out_matcher);
void dae_dns_request_matcher_free(DaeDnsRequestMatcher* matcher);
int32_t dae_dns_request_matcher_match_bytes(const DaeDnsRequestMatcher* matcher, const uint8_t* qname, uintptr_t qname_len, uint16_t qtype, int16_t* out_action);
const char* dae_domain_matcher_last_error(void);
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

const (
	rustRequestDomainKindFull uint32 = iota
	rustRequestDomainKindSuffix
	rustRequestDomainKindKeyword
	rustRequestDomainKindRegex
)

type rustDnsRequestMatcherRuntime struct {
	builder *C.DaeDnsRequestMatcherBuilder
	matcher *C.DaeDnsRequestMatcher
}

type rustRequestConditionSpec struct {
	domainBit *rustRequestDomainBitSpec
	qtypes    *rustRequestQTypeSpec
	fallback  bool
}

type rustRequestDomainBitSpec struct {
	bitIndex int
	not      bool
}

type rustRequestQTypeSpec struct {
	values []uint16
	not    bool
}

type rustRequestRuleSpec struct {
	conditions []rustRequestConditionSpec
	action     consts.DnsRequestOutboundIndex
}

func newRequestMatcherRuntime(bitLength int, domainSets []routing.DomainSet, rules []requestMatchSet) (*rustDnsRequestMatcherRuntime, error) {
	runtime := &rustDnsRequestMatcherRuntime{
		builder: C.dae_dns_request_matcher_builder_new(C.uintptr_t(bitLength)),
	}
	if runtime.builder == nil {
		return nil, fmt.Errorf("rust dns request matcher builder is nil")
	}

	for _, set := range domainSets {
		kind, err := rustRequestDomainKind(set.Key)
		if err != nil {
			runtime.Close()
			return nil, err
		}
		for _, pattern := range set.Domains {
			cPattern := C.CString(pattern)
			status := C.dae_dns_request_matcher_builder_add_domain_pattern(
				runtime.builder,
				C.uintptr_t(set.RuleIndex),
				C.uint32_t(kind),
				cPattern,
			)
			C.free(unsafe.Pointer(cPattern))
			if status != 0 {
				err := rustDnsRequestLastError("add domain pattern")
				runtime.Close()
				return nil, err
			}
		}
	}

	ruleSpecs, err := translateRustRequestRuleSpecs(rules)
	if err != nil {
		runtime.Close()
		return nil, err
	}
	for _, rule := range ruleSpecs {
		var ruleIndex C.uintptr_t
		if status := C.dae_dns_request_matcher_builder_add_rule(
			runtime.builder,
			C.int16_t(rule.action),
			&ruleIndex,
		); status != 0 {
			err := rustDnsRequestLastError("add rule")
			runtime.Close()
			return nil, err
		}
		for _, condition := range rule.conditions {
			switch {
			case condition.domainBit != nil:
				if status := C.dae_dns_request_matcher_builder_add_rule_domain_bit(
					runtime.builder,
					ruleIndex,
					C.uintptr_t(condition.domainBit.bitIndex),
					C.bool(condition.domainBit.not),
				); status != 0 {
					err := rustDnsRequestLastError("add domain bit condition")
					runtime.Close()
					return nil, err
				}
			case condition.qtypes != nil:
				values := condition.qtypes.values
				if status := C.dae_dns_request_matcher_builder_add_rule_qtypes(
					runtime.builder,
					ruleIndex,
					(*C.uint16_t)(unsafe.Pointer(&values[0])),
					C.uintptr_t(len(values)),
					C.bool(condition.qtypes.not),
				); status != 0 {
					err := rustDnsRequestLastError("add qtype condition")
					runtime.Close()
					return nil, err
				}
			case condition.fallback:
				if status := C.dae_dns_request_matcher_builder_add_rule_fallback(
					runtime.builder,
					ruleIndex,
				); status != 0 {
					err := rustDnsRequestLastError("add fallback condition")
					runtime.Close()
					return nil, err
				}
			default:
				runtime.Close()
				return nil, fmt.Errorf("empty rust dns request condition")
			}
		}
	}

	var matcher *C.DaeDnsRequestMatcher
	if status := C.dae_dns_request_matcher_builder_build(runtime.builder, &matcher); status != 0 {
		err := rustDnsRequestLastError("build matcher")
		runtime.Close()
		return nil, err
	}
	C.dae_dns_request_matcher_builder_free(runtime.builder)
	runtime.builder = nil
	runtime.matcher = matcher
	return runtime, nil
}

func (m *rustDnsRequestMatcherRuntime) Match(qName string, qType uint16) (consts.DnsRequestOutboundIndex, error) {
	if m.matcher == nil {
		return 0, fmt.Errorf("rust dns request matcher used before successful build")
	}
	var qnamePtr *C.uint8_t
	if len(qName) > 0 {
		qnamePtr = (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(qName)))
	}
	var action C.int16_t
	if status := C.dae_dns_request_matcher_match_bytes(
		m.matcher,
		qnamePtr,
		C.uintptr_t(len(qName)),
		C.uint16_t(qType),
		&action,
	); status != 0 {
		return 0, rustDnsRequestLastError("match request")
	}
	return consts.DnsRequestOutboundIndex(action), nil
}

func (m *rustDnsRequestMatcherRuntime) Close() {
	if m.builder != nil {
		C.dae_dns_request_matcher_builder_free(m.builder)
		m.builder = nil
	}
	if m.matcher != nil {
		C.dae_dns_request_matcher_free(m.matcher)
		m.matcher = nil
	}
}

func translateRustRequestRuleSpecs(matches []requestMatchSet) ([]rustRequestRuleSpec, error) {
	var rules []rustRequestRuleSpec
	for i := 0; i < len(matches); {
		var (
			conditions []rustRequestConditionSpec
			action     consts.DnsRequestOutboundIndex
		)
		for {
			if i >= len(matches) {
				return nil, fmt.Errorf("unterminated dns request rule")
			}
			match := matches[i]
			switch match.Type {
			case consts.MatchType_DomainSet:
				conditions = append(conditions, rustRequestConditionSpec{
					domainBit: &rustRequestDomainBitSpec{
						bitIndex: i,
						not:      match.Not,
					},
				})
				action = consts.DnsRequestOutboundIndex(match.Upstream)
				i++
			case consts.MatchType_QType:
				qtypeNot := match.Not
				values := make([]uint16, 0, 1)
				for {
					values = append(values, match.Value)
					action = consts.DnsRequestOutboundIndex(match.Upstream)
					i++
					if action != consts.DnsRequestOutboundIndex_LogicalOr {
						break
					}
					if i >= len(matches) {
						return nil, fmt.Errorf("unterminated dns request qtype group")
					}
					match = matches[i]
					if match.Type != consts.MatchType_QType || match.Not != qtypeNot {
						return nil, fmt.Errorf("mixed dns request qtype group")
					}
				}
				conditions = append(conditions, rustRequestConditionSpec{
					qtypes: &rustRequestQTypeSpec{
						values: values,
						not:    qtypeNot,
					},
				})
			case consts.MatchType_Fallback:
				conditions = append(conditions, rustRequestConditionSpec{fallback: true})
				action = consts.DnsRequestOutboundIndex(match.Upstream)
				i++
			default:
				return nil, fmt.Errorf("unsupported dns request match type for rust runtime: %v", match.Type)
			}

			if action == consts.DnsRequestOutboundIndex_LogicalAnd {
				continue
			}
			if action == consts.DnsRequestOutboundIndex_LogicalOr {
				return nil, fmt.Errorf("dns request rule ended on logical or")
			}
			rules = append(rules, rustRequestRuleSpec{
				conditions: conditions,
				action:     action,
			})
			break
		}
	}
	return rules, nil
}

func rustRequestDomainKind(typ consts.RoutingDomainKey) (uint32, error) {
	switch typ {
	case consts.RoutingDomainKey_Full:
		return rustRequestDomainKindFull, nil
	case consts.RoutingDomainKey_Suffix:
		return rustRequestDomainKindSuffix, nil
	case consts.RoutingDomainKey_Keyword:
		return rustRequestDomainKindKeyword, nil
	case consts.RoutingDomainKey_Regex:
		return rustRequestDomainKindRegex, nil
	default:
		return 0, fmt.Errorf("unsupported rust dns request matcher domain key: %s", typ)
	}
}

func rustDnsRequestLastError(operation string) error {
	msg := C.dae_domain_matcher_last_error()
	if msg == nil {
		return fmt.Errorf("rust dns request matcher %s failed", operation)
	}
	return fmt.Errorf("rust dns request matcher %s failed: %s", operation, C.GoString(msg))
}
