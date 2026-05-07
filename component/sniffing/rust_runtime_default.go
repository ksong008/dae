//go:build !rust_sniffing || !cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

type rustSniffingState struct{}

func (s *Sniffer) trySniffHTTPRust() (string, error, bool) {
	return "", nil, false
}

func (s *Sniffer) trySniffTLSRust() (string, error, bool) {
	return "", nil, false
}

func (s *Sniffer) trySniffQUICRust() (string, error, bool) {
	return "", nil, false
}

func (s *Sniffer) closeRustSniffing() {}
