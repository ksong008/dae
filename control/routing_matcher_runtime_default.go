//go:build !rust_userspace_routing || !cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

type rustUserspaceRoutingMatcherRuntime struct{}

func newRustUserspaceRoutingMatcherRuntime(_ int, _ []routing.DomainSet, _ [][]netip.Prefix, _ []bpfMatchSet) (*rustUserspaceRoutingMatcherRuntime, error) {
	return nil, nil
}

func (m *rustUserspaceRoutingMatcherRuntime) MatchDomainBitmap(string) ([]uint32, error) {
	return nil, fmt.Errorf("rust userspace routing matcher runtime is unavailable in this build")
}

func (m *rustUserspaceRoutingMatcherRuntime) Match(
	_ []byte,
	_ []byte,
	_ uint16,
	_ uint16,
	_ consts.IpVersionType,
	_ consts.L4ProtoType,
	_ string,
	_ [16]uint8,
	_ uint8,
	_ []byte,
) (consts.OutboundIndex, uint32, bool, error) {
	return 0, 0, false, fmt.Errorf("rust userspace routing matcher runtime is unavailable in this build")
}

func (m *rustUserspaceRoutingMatcherRuntime) MatchAddr16(
	_ *[16]byte,
	_ *[16]byte,
	_ uint16,
	_ uint16,
	_ consts.IpVersionType,
	_ consts.L4ProtoType,
	_ string,
	_ [16]uint8,
	_ uint8,
	_ *[16]byte,
) (consts.OutboundIndex, uint32, bool, error) {
	return 0, 0, false, fmt.Errorf("rust userspace routing matcher runtime is unavailable in this build")
}

func (m *rustUserspaceRoutingMatcherRuntime) Close() {}
