//go:build rust_domain_matcher && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../rust/target/release -ldae_domain_matcher -lm -ldl -lpthread
#include <stdint.h>
#include <stdlib.h>

typedef struct FfiMatcherBuilder DaeDomainMatcherBuilder;
typedef struct FfiMatcher DaeDomainMatcher;

DaeDomainMatcherBuilder* dae_domain_matcher_builder_new(uintptr_t bit_len);
void dae_domain_matcher_builder_free(DaeDomainMatcherBuilder* builder);
int32_t dae_domain_matcher_builder_add_pattern(DaeDomainMatcherBuilder* builder, uintptr_t bit_index, uint32_t kind, const char* pattern);
int32_t dae_domain_matcher_builder_build(const DaeDomainMatcherBuilder* builder, DaeDomainMatcher** out_matcher);
void dae_domain_matcher_free(DaeDomainMatcher* matcher);
int32_t dae_domain_matcher_match_into(const DaeDomainMatcher* matcher, const char* domain, uint32_t* bitmap, uintptr_t bitmap_len);
int32_t dae_domain_matcher_match_bytes_into(const DaeDomainMatcher* matcher, const uint8_t* domain, uintptr_t domain_len, uint32_t* bitmap, uintptr_t bitmap_len);
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
	rustDomainKindFull uint32 = iota
	rustDomainKindSuffix
	rustDomainKindKeyword
	rustDomainKindRegex
)

var (
	_ routing.DomainMatcher       = (*RustDomainMatcher)(nil)
	_ routing.DomainMatcherInto   = (*RustDomainMatcher)(nil)
	_ routing.DomainMatcherCloser = (*RustDomainMatcher)(nil)
)

type RustDomainMatcher struct {
	bitLength int
	builder   *C.DaeDomainMatcherBuilder
	matcher   *C.DaeDomainMatcher
	buildErr  error
}

func NewRustDomainMatcher(bitLength int) *RustDomainMatcher {
	return &RustDomainMatcher{
		bitLength: bitLength,
		builder:   C.dae_domain_matcher_builder_new(C.uintptr_t(bitLength)),
	}
}

func (m *RustDomainMatcher) AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey) {
	if m.buildErr != nil {
		return
	}
	if m.builder == nil {
		m.buildErr = fmt.Errorf("rust domain matcher builder is nil")
		return
	}
	kind, err := rustDomainKind(typ)
	if err != nil {
		m.buildErr = err
		return
	}

	for _, pattern := range patterns {
		cPattern := C.CString(pattern)
		status := C.dae_domain_matcher_builder_add_pattern(
			m.builder,
			C.uintptr_t(bitIndex),
			C.uint32_t(kind),
			cPattern,
		)
		C.free(unsafe.Pointer(cPattern))
		if status != 0 {
			m.buildErr = rustDomainLastError("add pattern")
			return
		}
	}
}

func (m *RustDomainMatcher) Build() error {
	if m.buildErr != nil {
		return m.buildErr
	}
	if m.builder == nil {
		return fmt.Errorf("rust domain matcher builder is nil")
	}

	var matcher *C.DaeDomainMatcher
	if status := C.dae_domain_matcher_builder_build(m.builder, &matcher); status != 0 {
		return rustDomainLastError("build matcher")
	}
	C.dae_domain_matcher_builder_free(m.builder)
	m.builder = nil
	m.matcher = matcher
	return nil
}

func (m *RustDomainMatcher) MatchDomainBitmap(domain string) []uint32 {
	bitmap := make([]uint32, rustDomainBitmapWords(m.bitLength))
	if err := m.MatchDomainBitmapInto(domain, bitmap); err != nil {
		panic(err)
	}
	return bitmap
}

func (m *RustDomainMatcher) MatchDomainBitmapInto(domain string, bitmap []uint32) error {
	if m.matcher == nil {
		return fmt.Errorf("rust domain matcher used before successful Build")
	}
	if len(bitmap) != rustDomainBitmapWords(m.bitLength) {
		return fmt.Errorf("rust domain matcher bitmap len=%d, want %d", len(bitmap), rustDomainBitmapWords(m.bitLength))
	}

	var domainPtr *C.uint8_t
	if len(domain) > 0 {
		domainPtr = (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(domain)))
	}

	if status := C.dae_domain_matcher_match_bytes_into(
		m.matcher,
		domainPtr,
		C.uintptr_t(len(domain)),
		(*C.uint32_t)(unsafe.Pointer(&bitmap[0])),
		C.uintptr_t(len(bitmap)),
	); status != 0 {
		return rustDomainLastError("match domain")
	}
	return nil
}

func (m *RustDomainMatcher) Close() {
	if m.builder != nil {
		C.dae_domain_matcher_builder_free(m.builder)
		m.builder = nil
	}
	if m.matcher != nil {
		C.dae_domain_matcher_free(m.matcher)
		m.matcher = nil
	}
}

func rustDomainKind(typ consts.RoutingDomainKey) (uint32, error) {
	switch typ {
	case consts.RoutingDomainKey_Full:
		return rustDomainKindFull, nil
	case consts.RoutingDomainKey_Suffix:
		return rustDomainKindSuffix, nil
	case consts.RoutingDomainKey_Keyword:
		return rustDomainKindKeyword, nil
	case consts.RoutingDomainKey_Regex:
		return rustDomainKindRegex, nil
	default:
		return 0, fmt.Errorf("unsupported rust domain matcher key: %s", typ)
	}
}

func rustDomainLastError(operation string) error {
	msg := C.dae_domain_matcher_last_error()
	if msg == nil {
		return fmt.Errorf("rust domain matcher %s failed", operation)
	}
	return fmt.Errorf("rust domain matcher %s failed: %s", operation, C.GoString(msg))
}

func rustDomainBitmapWords(bitLength int) int {
	return (bitLength + 31) / 32
}
