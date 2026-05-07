//go:build rust_sniffing && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

const rustSniffingScratchPoolCap = 1024

var rustSniffingScratchPool = make(chan *RustQuicSniffScratch, rustSniffingScratchPoolCap)

type rustSniffingState struct {
	scratch *RustQuicSniffScratch
	out     [256]byte
}

func getRustSniffingScratch() (*RustQuicSniffScratch, error) {
	select {
	case scratch := <-rustSniffingScratchPool:
		return scratch, nil
	default:
		return NewRustQuicSniffScratch()
	}
}

func putRustSniffingScratch(scratch *RustQuicSniffScratch) {
	if scratch == nil {
		return
	}
	select {
	case rustSniffingScratchPool <- scratch:
	default:
		scratch.Close()
	}
}

func (s *Sniffer) rustScratch() (*RustQuicSniffScratch, error) {
	if s.rustSniffing.scratch != nil {
		return s.rustSniffing.scratch, nil
	}
	scratch, err := getRustSniffingScratch()
	if err != nil {
		return nil, err
	}
	s.rustSniffing.scratch = scratch
	return scratch, nil
}

func (s *Sniffer) trySniffHTTPRust() (string, error, bool) {
	scratch, err := s.rustScratch()
	if err != nil {
		return "", err, true
	}
	n, err := scratch.SniffHTTPHostInto(s.buf.Bytes(), s.rustSniffing.out[:])
	if err != nil {
		return "", err, true
	}
	return string(s.rustSniffing.out[:n]), nil, true
}

func (s *Sniffer) trySniffTLSRust() (string, error, bool) {
	scratch, err := s.rustScratch()
	if err != nil {
		return "", err, true
	}
	n, err := scratch.SniffTLSSNIInto(s.buf.Bytes(), s.rustSniffing.out[:])
	if err != nil {
		return "", err, true
	}
	return string(s.rustSniffing.out[:n]), nil, true
}

func (s *Sniffer) trySniffQUICRust() (string, error, bool) {
	if s.stream || len(s.data) == 0 {
		return "", nil, false
	}
	var packets [2][]byte
	var nPackets int
	for _, packet := range s.data {
		if len(packet) == 0 {
			continue
		}
		if nPackets == len(packets) {
			return "", nil, false
		}
		packets[nPackets] = packet
		nPackets++
	}
	if nPackets == 0 {
		return "", nil, false
	}
	scratch, err := s.rustScratch()
	if err != nil {
		return "", err, true
	}
	n, err := scratch.SniffTwoInto(packets[0], packets[1], s.rustSniffing.out[:])
	if err != nil {
		if err == ErrNeedMore {
			s.needMore = true
			return "", ErrNotFound, true
		}
		return "", err, true
	}
	return string(s.rustSniffing.out[:n]), nil, true
}

func (s *Sniffer) closeRustSniffing() {
	putRustSniffingScratch(s.rustSniffing.scratch)
	s.rustSniffing.scratch = nil
}
