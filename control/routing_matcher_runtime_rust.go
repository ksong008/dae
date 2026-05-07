//go:build rust_userspace_routing && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package control

/*
#cgo LDFLAGS: -L${SRCDIR}/../rust/target/release -ldae_domain_matcher -lm -ldl -lpthread
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

typedef struct FfiUserspaceRoutingMatcherBuilder DaeUserspaceRoutingMatcherBuilder;
typedef struct FfiUserspaceRoutingMatcher DaeUserspaceRoutingMatcher;
typedef struct {
	int32_t status;
	uint8_t outbound;
	uint32_t mark;
	uint8_t must;
} DaeUserspaceRoutingMatchResult;

DaeUserspaceRoutingMatcherBuilder* dae_userspace_routing_matcher_builder_new(uintptr_t bit_len);
void dae_userspace_routing_matcher_builder_free(DaeUserspaceRoutingMatcherBuilder* builder);
int32_t dae_userspace_routing_matcher_builder_add_domain_pattern(DaeUserspaceRoutingMatcherBuilder* builder, uintptr_t bit_index, uint32_t kind, const char* pattern);
int32_t dae_userspace_routing_matcher_builder_add_ip_prefix(DaeUserspaceRoutingMatcherBuilder* builder, uint32_t set_kind, uintptr_t set_index, const uint8_t* addr, uintptr_t addr_len, uint8_t prefix_bits);
int32_t dae_userspace_routing_matcher_builder_add_rule(DaeUserspaceRoutingMatcherBuilder* builder, uint32_t action_kind, uint8_t outbound, uint32_t mark, _Bool must, uintptr_t* out_rule_index);
int32_t dae_userspace_routing_matcher_builder_add_rule_domain_bit(DaeUserspaceRoutingMatcherBuilder* builder, uintptr_t rule_index, uintptr_t bit_index, _Bool not);
int32_t dae_userspace_routing_matcher_builder_add_rule_set(DaeUserspaceRoutingMatcherBuilder* builder, uintptr_t rule_index, uint32_t set_kind, uintptr_t set_index, _Bool not);
int32_t dae_userspace_routing_matcher_builder_add_rule_ports(DaeUserspaceRoutingMatcherBuilder* builder, uintptr_t rule_index, _Bool is_source, const uint16_t* ranges, uintptr_t ranges_len, _Bool not);
int32_t dae_userspace_routing_matcher_builder_add_rule_l4proto_mask(DaeUserspaceRoutingMatcherBuilder* builder, uintptr_t rule_index, uint8_t mask, _Bool not);
int32_t dae_userspace_routing_matcher_builder_add_rule_ip_version_mask(DaeUserspaceRoutingMatcherBuilder* builder, uintptr_t rule_index, uint8_t mask, _Bool not);
int32_t dae_userspace_routing_matcher_builder_add_rule_process_names(DaeUserspaceRoutingMatcherBuilder* builder, uintptr_t rule_index, const uint8_t* names, uintptr_t names_len, _Bool not);
int32_t dae_userspace_routing_matcher_builder_add_rule_dscp_values(DaeUserspaceRoutingMatcherBuilder* builder, uintptr_t rule_index, const uint8_t* values, uintptr_t values_len, _Bool not);
int32_t dae_userspace_routing_matcher_builder_add_rule_fallback(DaeUserspaceRoutingMatcherBuilder* builder, uintptr_t rule_index);
int32_t dae_userspace_routing_matcher_builder_build(const DaeUserspaceRoutingMatcherBuilder* builder, DaeUserspaceRoutingMatcher** out_matcher);
void dae_userspace_routing_matcher_free(DaeUserspaceRoutingMatcher* matcher);
int32_t dae_userspace_routing_matcher_match_domain_bitmap_bytes_into(const DaeUserspaceRoutingMatcher* matcher, const uint8_t* domain, uintptr_t domain_len, uint32_t* bitmap, uintptr_t bitmap_len);
int32_t dae_userspace_routing_matcher_match_bytes(const DaeUserspaceRoutingMatcher* matcher, const uint8_t* source_addr, uintptr_t source_addr_len, const uint8_t* dest_addr, uintptr_t dest_addr_len, uint16_t source_port, uint16_t dest_port, uint8_t ip_version, uint8_t l4proto, const uint8_t* domain, uintptr_t domain_len, const uint8_t* process_name, uintptr_t process_name_len, uint8_t dscp, const uint8_t* mac, uintptr_t mac_len, uint8_t* out_outbound, uint32_t* out_mark, _Bool* out_must);
DaeUserspaceRoutingMatchResult dae_userspace_routing_matcher_match_words(const DaeUserspaceRoutingMatcher* matcher, uint64_t source_addr_hi, uint64_t source_addr_lo, uint64_t dest_addr_hi, uint64_t dest_addr_lo, uint16_t source_port, uint16_t dest_port, uint8_t ip_version, uint8_t l4proto, const uint8_t* domain, uintptr_t domain_len, uint64_t process_name_hi, uint64_t process_name_lo, uint8_t dscp, uint64_t mac_hi, uint64_t mac_lo);
const char* dae_domain_matcher_last_error(void);
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

const (
	rustRoutingDomainKindFull uint32 = iota
	rustRoutingDomainKindSuffix
	rustRoutingDomainKindKeyword
	rustRoutingDomainKindRegex
)

const (
	rustRoutingSetDestIP uint32 = iota
	rustRoutingSetSourceIP
	rustRoutingSetMac
)

const (
	rustRoutingActionContinueMust uint32 = iota
	rustRoutingActionRoute
)

type rustUserspaceRoutingMatcherRuntime struct {
	bitLength int
	builder   *C.DaeUserspaceRoutingMatcherBuilder
	matcher   *C.DaeUserspaceRoutingMatcher
}

func newRustUserspaceRoutingMatcherRuntime(bitLength int, domainSets []routing.DomainSet, lpmTries [][]netip.Prefix, rules []bpfMatchSet) (*rustUserspaceRoutingMatcherRuntime, error) {
	runtime := &rustUserspaceRoutingMatcherRuntime{
		bitLength: bitLength,
		builder:   C.dae_userspace_routing_matcher_builder_new(C.uintptr_t(bitLength)),
	}
	if runtime.builder == nil {
		return nil, fmt.Errorf("rust userspace routing matcher builder is nil")
	}
	for _, set := range domainSets {
		kind, err := rustRoutingDomainKind(set.Key)
		if err != nil {
			runtime.Close()
			return nil, err
		}
		for _, pattern := range set.Domains {
			cPattern := C.CString(pattern)
			status := C.dae_userspace_routing_matcher_builder_add_domain_pattern(
				runtime.builder,
				C.uintptr_t(set.RuleIndex),
				C.uint32_t(kind),
				cPattern,
			)
			C.free(unsafe.Pointer(cPattern))
			if status != 0 {
				err := rustUserspaceRoutingLastError("add domain pattern")
				runtime.Close()
				return nil, err
			}
		}
	}
	if err := addRoutingPrefixes(runtime.builder, lpmTries, rules); err != nil {
		runtime.Close()
		return nil, err
	}
	if err := addRoutingRules(runtime.builder, rules); err != nil {
		runtime.Close()
		return nil, err
	}
	var matcher *C.DaeUserspaceRoutingMatcher
	if status := C.dae_userspace_routing_matcher_builder_build(runtime.builder, &matcher); status != 0 {
		err := rustUserspaceRoutingLastError("build matcher")
		runtime.Close()
		return nil, err
	}
	C.dae_userspace_routing_matcher_builder_free(runtime.builder)
	runtime.builder = nil
	runtime.matcher = matcher
	return runtime, nil
}

func (m *rustUserspaceRoutingMatcherRuntime) MatchDomainBitmap(domain string) ([]uint32, error) {
	if m.matcher == nil {
		return nil, fmt.Errorf("rust userspace routing matcher used before successful build")
	}
	bitmap := make([]uint32, (m.bitLength+31)/32)
	var domainPtr *C.uint8_t
	if len(domain) > 0 {
		domainPtr = (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(domain)))
	}
	if status := C.dae_userspace_routing_matcher_match_domain_bitmap_bytes_into(
		m.matcher,
		domainPtr,
		C.uintptr_t(len(domain)),
		(*C.uint32_t)(unsafe.Pointer(&bitmap[0])),
		C.uintptr_t(len(bitmap)),
	); status != 0 {
		return nil, rustUserspaceRoutingLastError("match domain bitmap")
	}
	return bitmap, nil
}

func (m *rustUserspaceRoutingMatcherRuntime) Match(
	sourceAddr []byte,
	destAddr []byte,
	sourcePort uint16,
	destPort uint16,
	ipVersion consts.IpVersionType,
	l4proto consts.L4ProtoType,
	domain string,
	processName [16]uint8,
	dscp uint8,
	mac []byte,
) (consts.OutboundIndex, uint32, bool, error) {
	if m.matcher == nil {
		return 0, 0, false, fmt.Errorf("rust userspace routing matcher used before successful build")
	}
	if len(sourceAddr) != 16 || len(destAddr) != 16 || len(mac) != 16 {
		return 0, 0, false, fmt.Errorf("bad address length")
	}
	return m.MatchAddr16(
		(*[16]byte)(unsafe.Pointer(&sourceAddr[0])),
		(*[16]byte)(unsafe.Pointer(&destAddr[0])),
		sourcePort,
		destPort,
		ipVersion,
		l4proto,
		domain,
		processName,
		dscp,
		(*[16]byte)(unsafe.Pointer(&mac[0])),
	)
}

func (m *rustUserspaceRoutingMatcherRuntime) MatchAddr16(
	sourceAddr *[16]byte,
	destAddr *[16]byte,
	sourcePort uint16,
	destPort uint16,
	ipVersion consts.IpVersionType,
	l4proto consts.L4ProtoType,
	domain string,
	processName [16]uint8,
	dscp uint8,
	mac *[16]byte,
) (consts.OutboundIndex, uint32, bool, error) {
	if m.matcher == nil {
		return 0, 0, false, fmt.Errorf("rust userspace routing matcher used before successful build")
	}
	var domainPtr *C.uint8_t
	if len(domain) > 0 {
		domainPtr = (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(domain)))
	}
	processNameWords := wordsFrom16((*[16]byte)(unsafe.Pointer(&processName)))
	result := C.dae_userspace_routing_matcher_match_words(
		m.matcher,
		C.uint64_t(binary.BigEndian.Uint64(sourceAddr[:8])),
		C.uint64_t(binary.BigEndian.Uint64(sourceAddr[8:])),
		C.uint64_t(binary.BigEndian.Uint64(destAddr[:8])),
		C.uint64_t(binary.BigEndian.Uint64(destAddr[8:])),
		C.uint16_t(sourcePort),
		C.uint16_t(destPort),
		C.uint8_t(ipVersion),
		C.uint8_t(l4proto),
		domainPtr,
		C.uintptr_t(len(domain)),
		C.uint64_t(processNameWords.hi),
		C.uint64_t(processNameWords.lo),
		C.uint8_t(dscp),
		C.uint64_t(binary.BigEndian.Uint64(mac[:8])),
		C.uint64_t(binary.BigEndian.Uint64(mac[8:])),
	)
	if result.status != 0 {
		return 0, 0, false, rustUserspaceRoutingLastError("match routing")
	}
	return consts.OutboundIndex(result.outbound), uint32(result.mark), result.must != 0, nil
}

type words16 struct {
	hi uint64
	lo uint64
}

func wordsFrom16(value *[16]byte) words16 {
	return words16{
		hi: binary.BigEndian.Uint64(value[:8]),
		lo: binary.BigEndian.Uint64(value[8:]),
	}
}

func (m *rustUserspaceRoutingMatcherRuntime) Close() {
	if m.builder != nil {
		C.dae_userspace_routing_matcher_builder_free(m.builder)
		m.builder = nil
	}
	if m.matcher != nil {
		C.dae_userspace_routing_matcher_free(m.matcher)
		m.matcher = nil
	}
}

func addRoutingPrefixes(builder *C.DaeUserspaceRoutingMatcherBuilder, lpmTries [][]netip.Prefix, rules []bpfMatchSet) error {
	seen := make(map[[2]uint32]struct{})
	for _, rule := range rules {
		var setKind uint32
		switch consts.MatchType(rule.Type) {
		case consts.MatchType_IpSet:
			setKind = rustRoutingSetDestIP
		case consts.MatchType_SourceIpSet:
			setKind = rustRoutingSetSourceIP
		case consts.MatchType_Mac:
			setKind = rustRoutingSetMac
		default:
			continue
		}
		lpmIndex := binary.LittleEndian.Uint32(rule.Value[:])
		key := [2]uint32{setKind, lpmIndex}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		for _, prefix := range lpmTries[lpmIndex] {
			bits := prefix.Bits()
			if prefix.Addr().Is4() {
				bits += 96
			}
			addr := prefix.Addr().As16()
			if status := C.dae_userspace_routing_matcher_builder_add_ip_prefix(
				builder,
				C.uint32_t(setKind),
				C.uintptr_t(lpmIndex),
				(*C.uint8_t)(unsafe.Pointer(&addr[0])),
				C.uintptr_t(len(addr)),
				C.uint8_t(bits),
			); status != 0 {
				return rustUserspaceRoutingLastError("add ip prefix")
			}
		}
	}
	return nil
}

func rustRoutingDomainKind(typ consts.RoutingDomainKey) (uint32, error) {
	switch typ {
	case consts.RoutingDomainKey_Full:
		return rustRoutingDomainKindFull, nil
	case consts.RoutingDomainKey_Suffix:
		return rustRoutingDomainKindSuffix, nil
	case consts.RoutingDomainKey_Keyword:
		return rustRoutingDomainKindKeyword, nil
	case consts.RoutingDomainKey_Regex:
		return rustRoutingDomainKindRegex, nil
	default:
		return 0, fmt.Errorf("unsupported rust userspace routing domain key: %s", typ)
	}
}

func addRoutingRules(builder *C.DaeUserspaceRoutingMatcherBuilder, rules []bpfMatchSet) error {
	for i := 0; i < len(rules); {
		var (
			actionKind uint32
			outbound   uint8
			mark       uint32
			must       bool
			conditions []func(C.uintptr_t) error
		)
		for {
			if i >= len(rules) {
				return fmt.Errorf("unterminated userspace routing rule")
			}
			match := rules[i]
			switch consts.MatchType(match.Type) {
			case consts.MatchType_DomainSet:
				bitIndex := i
				not := match.Not
				conditions = append(conditions, func(ruleIndex C.uintptr_t) error {
					if status := C.dae_userspace_routing_matcher_builder_add_rule_domain_bit(
						builder,
						ruleIndex,
						C.uintptr_t(bitIndex),
						C.bool(not),
					); status != 0 {
						return rustUserspaceRoutingLastError("add domain condition")
					}
					return nil
				})
				i++
				if consts.OutboundIndex(match.Outbound) == consts.OutboundLogicalAnd {
					continue
				}
				outbound = match.Outbound
				mark = match.Mark
				must = match.Must
			case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
				setKind, err := routingSetKindFromMatchType(consts.MatchType(match.Type))
				if err != nil {
					return err
				}
				setIndex := binary.LittleEndian.Uint32(match.Value[:])
				not := match.Not
				conditions = append(conditions, func(ruleIndex C.uintptr_t) error {
					if status := C.dae_userspace_routing_matcher_builder_add_rule_set(
						builder,
						ruleIndex,
						C.uint32_t(setKind),
						C.uintptr_t(setIndex),
						C.bool(not),
					); status != 0 {
						return rustUserspaceRoutingLastError("add set condition")
					}
					return nil
				})
				i++
				if consts.OutboundIndex(match.Outbound) == consts.OutboundLogicalAnd {
					continue
				}
				outbound = match.Outbound
				mark = match.Mark
				must = match.Must
			case consts.MatchType_Port, consts.MatchType_SourcePort:
				matchType := consts.MatchType(match.Type)
				not := match.Not
				values := make([]uint16, 0, 2)
				for {
					start, end := ParsePortRange(match.Value[:])
					values = append(values, start, end)
					i++
					if i >= len(rules) || consts.OutboundIndex(match.Outbound) != consts.OutboundLogicalOr {
						break
					}
					match = rules[i]
					if consts.MatchType(match.Type) != matchType || match.Not != not {
						return fmt.Errorf("mixed port group in userspace routing rule")
					}
				}
				terminal := rules[i-1]
				conditions = append(conditions, func(ruleIndex C.uintptr_t) error {
					if status := C.dae_userspace_routing_matcher_builder_add_rule_ports(
						builder,
						ruleIndex,
						C.bool(matchType == consts.MatchType_SourcePort),
						(*C.uint16_t)(unsafe.Pointer(&values[0])),
						C.uintptr_t(len(values)),
						C.bool(not),
					); status != 0 {
						return rustUserspaceRoutingLastError("add port condition")
					}
					return nil
				})
				if consts.OutboundIndex(terminal.Outbound) == consts.OutboundLogicalAnd {
					continue
				}
				outbound = terminal.Outbound
				mark = terminal.Mark
				must = terminal.Must
			case consts.MatchType_L4Proto:
				mask := match.Value[0]
				not := match.Not
				conditions = append(conditions, func(ruleIndex C.uintptr_t) error {
					if status := C.dae_userspace_routing_matcher_builder_add_rule_l4proto_mask(
						builder, ruleIndex, C.uint8_t(mask), C.bool(not),
					); status != 0 {
						return rustUserspaceRoutingLastError("add l4proto condition")
					}
					return nil
				})
				i++
				if consts.OutboundIndex(match.Outbound) == consts.OutboundLogicalAnd {
					continue
				}
				outbound = match.Outbound
				mark = match.Mark
				must = match.Must
			case consts.MatchType_IpVersion:
				mask := match.Value[0]
				not := match.Not
				conditions = append(conditions, func(ruleIndex C.uintptr_t) error {
					if status := C.dae_userspace_routing_matcher_builder_add_rule_ip_version_mask(
						builder, ruleIndex, C.uint8_t(mask), C.bool(not),
					); status != 0 {
						return rustUserspaceRoutingLastError("add ipversion condition")
					}
					return nil
				})
				i++
				if consts.OutboundIndex(match.Outbound) == consts.OutboundLogicalAnd {
					continue
				}
				outbound = match.Outbound
				mark = match.Mark
				must = match.Must
			case consts.MatchType_ProcessName:
				not := match.Not
				names := make([]byte, 0, 16)
				for {
					names = append(names, match.Value[:]...)
					i++
					if i >= len(rules) || consts.OutboundIndex(match.Outbound) != consts.OutboundLogicalOr {
						break
					}
					match = rules[i]
					if consts.MatchType(match.Type) != consts.MatchType_ProcessName || match.Not != not {
						return fmt.Errorf("mixed process name group in userspace routing rule")
					}
				}
				terminal := rules[i-1]
				conditions = append(conditions, func(ruleIndex C.uintptr_t) error {
					if status := C.dae_userspace_routing_matcher_builder_add_rule_process_names(
						builder,
						ruleIndex,
						(*C.uint8_t)(unsafe.Pointer(&names[0])),
						C.uintptr_t(len(names)),
						C.bool(not),
					); status != 0 {
						return rustUserspaceRoutingLastError("add process name condition")
					}
					return nil
				})
				if consts.OutboundIndex(terminal.Outbound) == consts.OutboundLogicalAnd {
					continue
				}
				outbound = terminal.Outbound
				mark = terminal.Mark
				must = terminal.Must
			case consts.MatchType_Dscp:
				not := match.Not
				values := make([]byte, 0, 1)
				for {
					values = append(values, match.Value[0])
					i++
					if i >= len(rules) || consts.OutboundIndex(match.Outbound) != consts.OutboundLogicalOr {
						break
					}
					match = rules[i]
					if consts.MatchType(match.Type) != consts.MatchType_Dscp || match.Not != not {
						return fmt.Errorf("mixed dscp group in userspace routing rule")
					}
				}
				terminal := rules[i-1]
				conditions = append(conditions, func(ruleIndex C.uintptr_t) error {
					if status := C.dae_userspace_routing_matcher_builder_add_rule_dscp_values(
						builder,
						ruleIndex,
						(*C.uint8_t)(unsafe.Pointer(&values[0])),
						C.uintptr_t(len(values)),
						C.bool(not),
					); status != 0 {
						return rustUserspaceRoutingLastError("add dscp condition")
					}
					return nil
				})
				if consts.OutboundIndex(terminal.Outbound) == consts.OutboundLogicalAnd {
					continue
				}
				outbound = terminal.Outbound
				mark = terminal.Mark
				must = terminal.Must
			case consts.MatchType_Fallback:
				conditions = append(conditions, func(ruleIndex C.uintptr_t) error {
					if status := C.dae_userspace_routing_matcher_builder_add_rule_fallback(builder, ruleIndex); status != 0 {
						return rustUserspaceRoutingLastError("add fallback condition")
					}
					return nil
				})
				i++
				outbound = match.Outbound
				mark = match.Mark
				must = match.Must
			default:
				return fmt.Errorf("unsupported userspace routing match type for rust runtime: %v", match.Type)
			}

			actionKind = rustRoutingActionRoute
			if consts.OutboundIndex(outbound) == consts.OutboundMustRules {
				actionKind = rustRoutingActionContinueMust
			}
			var ruleIndex C.uintptr_t
			if status := C.dae_userspace_routing_matcher_builder_add_rule(
				builder,
				C.uint32_t(actionKind),
				C.uint8_t(outbound),
				C.uint32_t(mark),
				C.bool(must),
				&ruleIndex,
			); status != 0 {
				return rustUserspaceRoutingLastError("add rule")
			}
			for _, addCondition := range conditions {
				if err := addCondition(ruleIndex); err != nil {
					return err
				}
			}
			break
		}
	}
	return nil
}

func routingSetKindFromMatchType(typ consts.MatchType) (uint32, error) {
	switch typ {
	case consts.MatchType_IpSet:
		return rustRoutingSetDestIP, nil
	case consts.MatchType_SourceIpSet:
		return rustRoutingSetSourceIP, nil
	case consts.MatchType_Mac:
		return rustRoutingSetMac, nil
	default:
		return 0, fmt.Errorf("unsupported userspace routing set match type: %v", typ)
	}
}

func rustUserspaceRoutingLastError(operation string) error {
	msg := C.dae_domain_matcher_last_error()
	if msg == nil {
		return fmt.Errorf("rust userspace routing matcher %s failed", operation)
	}
	return fmt.Errorf("rust userspace routing matcher %s failed: %s", operation, C.GoString(msg))
}
