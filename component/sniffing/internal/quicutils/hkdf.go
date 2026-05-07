/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Modified from https://github.com/quic-go/quic-go/blob/58cedf7a4f/internal/handshake/hkdf.go

package quicutils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/hkdf"
)

// HkdfExpandLabelFromPool HKDF expands a label.
// Since this implementation avoids using a cryptobyte.Builder, it is about 15% faster than the
// hkdfExpandLabel in the standard library.
func HkdfExpandLabelFromPool(h func() hash.Hash, secret, label []byte, context []byte, length int) ([]byte, error) {
	b := pool.Get(3 + 6 + len(label) + 1 + len(context))
	defer pool.Put(b)
	binary.BigEndian.PutUint16(b, uint16(length))
	b[2] = uint8(6 + len(label))
	copy(b[3:], "tls13 ")
	copy(b[9:], label)
	b[9+len(label)] = uint8(len(context))
	copy(b[10+len(label):], context)

	out := pool.Get(length)
	if _, err := io.ReadFull(hkdf.Expand(h, secret, b), out); err != nil {
		return nil, err
	}
	return out, nil
}

func HkdfExtractSHA256Into(salt, secret, out []byte) error {
	if len(out) < sha256.Size {
		return fmt.Errorf("hkdf extract output too short: %d", len(out))
	}
	mac := hmac.New(sha256.New, salt)
	if _, err := mac.Write(secret); err != nil {
		return err
	}
	var sum [sha256.Size]byte
	copy(out, mac.Sum(sum[:0]))
	return nil
}

func HkdfExpandLabelSHA256Into(secret, label []byte, context []byte, out []byte) error {
	var info [64]byte
	infoLen := 3 + 6 + len(label) + 1 + len(context)
	if infoLen > len(info) {
		return fmt.Errorf("hkdf label too long: %d", infoLen)
	}
	binary.BigEndian.PutUint16(info[:2], uint16(len(out)))
	info[2] = uint8(6 + len(label))
	copy(info[3:], "tls13 ")
	copy(info[9:], label)
	info[9+len(label)] = uint8(len(context))
	copy(info[10+len(label):], context)

	return HkdfExpandSHA256Into(secret, info[:infoLen], out)
}

func HkdfExpandSHA256Into(secret, info []byte, out []byte) error {
	if len(out) > sha256.Size {
		return fmt.Errorf("hkdf expand output too long: %d", len(out))
	}
	mac := hmac.New(sha256.New, secret)
	if _, err := mac.Write(info); err != nil {
		return err
	}
	var counter = [1]byte{1}
	if _, err := mac.Write(counter[:]); err != nil {
		return err
	}
	var sum [sha256.Size]byte
	copy(out, mac.Sum(sum[:0]))
	return nil
}
