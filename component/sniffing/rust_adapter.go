//go:build rust_sniffing && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

/*
#cgo LDFLAGS: -L${SRCDIR}/../../rust/target/release -ldae_sniffing -lm -ldl -lpthread
#include <stdint.h>
#include <stdlib.h>

typedef struct FfiQuicSniffScratch DaeSniffingQuicScratch;

DaeSniffingQuicScratch* dae_sniffing_quic_scratch_new(void);
void dae_sniffing_quic_scratch_free(DaeSniffingQuicScratch* scratch);
int32_t dae_sniffing_quic_initial_sni_two_into(
	DaeSniffingQuicScratch* scratch,
	const uint8_t* packet1,
	uintptr_t packet1_len,
	const uint8_t* packet2,
	uintptr_t packet2_len,
	uint8_t* out,
	uintptr_t out_len,
	uintptr_t* written
);
int32_t dae_sniffing_http_host_into(const uint8_t* data, uintptr_t data_len, uint8_t* out, uintptr_t out_len, uintptr_t* written);
int32_t dae_sniffing_tls_sni_into(const uint8_t* data, uintptr_t data_len, uint8_t* out, uintptr_t out_len, uintptr_t* written);
const char* dae_sniffing_last_error(void);
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

type RustQuicSniffScratch struct {
	ptr     *C.DaeSniffingQuicScratch
	written C.uintptr_t
}

func NewRustQuicSniffScratch() (*RustQuicSniffScratch, error) {
	scratch := &RustQuicSniffScratch{}
	if err := scratch.init(); err != nil {
		return nil, err
	}
	return scratch, nil
}

func (s *RustQuicSniffScratch) init() error {
	if s.ptr != nil {
		return nil
	}
	s.ptr = C.dae_sniffing_quic_scratch_new()
	if s.ptr == nil {
		return fmt.Errorf("rust quic sniff scratch allocation returned nil")
	}
	return nil
}

func (s *RustQuicSniffScratch) Close() {
	if s.ptr != nil {
		C.dae_sniffing_quic_scratch_free(s.ptr)
		s.ptr = nil
	}
}

func (s *RustQuicSniffScratch) SniffTwoInto(packet1, packet2, out []byte) (int, error) {
	if err := s.init(); err != nil {
		return 0, err
	}
	var packet1Ptr *C.uint8_t
	if len(packet1) > 0 {
		packet1Ptr = (*C.uint8_t)(unsafe.Pointer(&packet1[0]))
	}
	var packet2Ptr *C.uint8_t
	if len(packet2) > 0 {
		packet2Ptr = (*C.uint8_t)(unsafe.Pointer(&packet2[0]))
	}
	var outPtr *C.uint8_t
	if len(out) > 0 {
		outPtr = (*C.uint8_t)(unsafe.Pointer(&out[0]))
	}

	s.written = 0
	status := C.dae_sniffing_quic_initial_sni_two_into(
		s.ptr,
		packet1Ptr,
		C.uintptr_t(len(packet1)),
		packet2Ptr,
		C.uintptr_t(len(packet2)),
		outPtr,
		C.uintptr_t(len(out)),
		&s.written,
	)
	if status != 0 {
		return 0, rustSniffingLastError()
	}
	return int(s.written), nil
}

func (s *RustQuicSniffScratch) SniffHTTPHostInto(data, out []byte) (int, error) {
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	var outPtr *C.uint8_t
	if len(out) > 0 {
		outPtr = (*C.uint8_t)(unsafe.Pointer(&out[0]))
	}

	s.written = 0
	status := C.dae_sniffing_http_host_into(
		dataPtr,
		C.uintptr_t(len(data)),
		outPtr,
		C.uintptr_t(len(out)),
		&s.written,
	)
	if status != 0 {
		return 0, rustSniffingLastError()
	}
	return int(s.written), nil
}

func (s *RustQuicSniffScratch) SniffTLSSNIInto(data, out []byte) (int, error) {
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	var outPtr *C.uint8_t
	if len(out) > 0 {
		outPtr = (*C.uint8_t)(unsafe.Pointer(&out[0]))
	}

	s.written = 0
	status := C.dae_sniffing_tls_sni_into(
		dataPtr,
		C.uintptr_t(len(data)),
		outPtr,
		C.uintptr_t(len(out)),
		&s.written,
	)
	if status != 0 {
		return 0, rustSniffingLastError()
	}
	return int(s.written), nil
}

func rustSniffingLastError() error {
	msg := C.dae_sniffing_last_error()
	if msg == nil {
		return fmt.Errorf("rust sniffing failed")
	}
	errmsg := C.GoString(msg)
	switch {
	case strings.Contains(errmsg, "NeedMore"):
		return ErrNeedMore
	case strings.Contains(errmsg, "NotApplicable"):
		return ErrNotApplicable
	case strings.Contains(errmsg, "NotFound"):
		return ErrNotFound
	case strings.Contains(errmsg, "InvalidUtf8"):
		return ErrNotApplicable
	default:
		return fmt.Errorf("rust sniffing failed: %s", errmsg)
	}
}
