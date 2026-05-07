/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import "fmt"

type Version int

const (
	Version_Draft = iota
	Version_V1
	Version_V2
)

var (
	versionDraftInitialSalt = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	versionV1InitialSalt    = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	versionV2InitialSalt    = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}

	versionV1HpLabel  = []byte("quic hp")
	versionV2HpLabel  = []byte("quicv2 hp")
	versionV1KeyLabel = []byte("quic key")
	versionV2KeyLabel = []byte("quicv2 key")
	versionV1IvLabel  = []byte("quic iv")
	versionV2IvLabel  = []byte("quicv2 iv")
)

func ParseVersion(version uint32) (Version, error) {
	switch version {
	case 0x6b3343cf:
		return Version_V2, nil
	case 1:
		return Version_V1, nil
	default:
		if (version & 0xff000000) == 0xff000000 {
			return Version_Draft, nil
		}
		return 0, fmt.Errorf("unknown version")
	}
}

func (v Version) InitialSalt() []byte {
	switch v {
	case Version_Draft:
		return versionDraftInitialSalt
	case Version_V1:
		return versionV1InitialSalt
	case Version_V2:
		return versionV2InitialSalt
	default:
		panic("unsupported quic version")
	}
}

func (v Version) HpLabel() []byte {
	switch v {
	case Version_Draft:
		fallthrough
	case Version_V1:
		return versionV1HpLabel
	case Version_V2:
		return versionV2HpLabel
	default:
		panic("unsupported quic version")
	}
}
func (v Version) KeyLabel() []byte {
	switch v {
	case Version_Draft:
		fallthrough
	case Version_V1:
		return versionV1KeyLabel
	case Version_V2:
		return versionV2KeyLabel
	default:
		panic("unsupported quic version")
	}
}
func (v Version) IvLabel() []byte {
	switch v {
	case Version_Draft:
		fallthrough
	case Version_V1:
		return versionV1IvLabel
	case Version_V2:
		return versionV2IvLabel
	default:
		panic("unsupported quic version")
	}
}
