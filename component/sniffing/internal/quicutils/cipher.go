/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/pool"
)

const (
	MaxVarintLen64 = 8

	MaxPacketNumberLength = 4
	SampleSize            = 16
)

var (
	InitialClientLabel = []byte("client in")
)

type Keys struct {
	version                Version
	clientInitialSecret    []byte
	key                    []byte
	iv                     []byte
	headerProtectionKey    []byte
	clientInitialSecretBuf [32]byte
	keyBuf                 [16]byte
	ivBuf                  [12]byte
	headerProtectionKeyBuf [16]byte
	newAead                func(key []byte) (cipher.AEAD, error)
	headerProtection       cipher.Block
	aead                   cipher.AEAD
	headerProtectionMask   [aes.BlockSize]byte
}

func (k *Keys) Close() error {
	k.clientInitialSecret = nil
	k.headerProtectionKey = nil
	k.iv = nil
	k.key = nil
	return nil
}

func NewKeys(clientDstConnectionId []byte, version Version, newAead func(key []byte) (cipher.AEAD, error)) (keys *Keys, err error) {
	// https://datatracker.ietf.org/doc/html/rfc9001#name-keys
	var initialSecret [32]byte
	if err = HkdfExtractSHA256Into(version.InitialSalt(), clientDstConnectionId, initialSecret[:]); err != nil {
		return nil, err
	}
	keys = &Keys{
		version: version,
		newAead: newAead,
	}
	keys.clientInitialSecret = keys.clientInitialSecretBuf[:]
	if err = HkdfExpandLabelSHA256Into(initialSecret[:], InitialClientLabel, nil, keys.clientInitialSecret); err != nil {
		return nil, err
	}
	// We differentiated a deriveKeys func is just for example test.
	if err = keys.deriveKeys(); err != nil {
		keys.Close()
		return nil, err
	}

	return keys, nil
}

func (k *Keys) deriveKeys() (err error) {
	k.key = k.keyBuf[:]
	err = HkdfExpandLabelSHA256Into(k.clientInitialSecret, k.version.KeyLabel(), nil, k.key)
	if err != nil {
		return err
	}
	k.iv = k.ivBuf[:]
	err = HkdfExpandLabelSHA256Into(k.clientInitialSecret, k.version.IvLabel(), nil, k.iv)
	if err != nil {
		return err
	}
	k.headerProtectionKey = k.headerProtectionKeyBuf[:]
	err = HkdfExpandLabelSHA256Into(k.clientInitialSecret, k.version.HpLabel(), nil, k.headerProtectionKey)
	if err != nil {
		return err
	}
	k.headerProtection, err = aes.NewCipher(k.headerProtectionKey)
	if err != nil {
		return err
	}
	k.aead, err = k.newAead(k.key)
	if err != nil {
		return err
	}
	return nil
}

// HeaderProtection_ encrypt/decrypt firstByte and packetNumber in place.
func (k *Keys) HeaderProtection_(sample []byte, longHeader bool, firstByte *byte, potentialPacketNumber []byte) (packetNumber []byte, err error) {
	// Get mask.
	mask := k.headerProtectionMask[:]
	k.headerProtection.Encrypt(mask, sample)
	// Encrypt/decrypt first byte.
	if longHeader {
		// Long header: 4 bits masked
		// High 4 bits are not protected.
		*firstByte ^= mask[0] & 0x0f
	} else {
		// Short header: 5 bits masked
		// High 3 bits are not protected.
		*firstByte ^= mask[0] & 0x1f
	}
	// The length of the Packet Number field is the value of this field plus one.
	packetNumberLength := int((*firstByte & 0b11) + 1)
	packetNumber = potentialPacketNumber[:packetNumberLength]

	// Encrypt/decrypt packet number.
	for i := range packetNumber {
		packetNumber[i] ^= mask[1+i]
	}
	return packetNumber, nil
}

func (k *Keys) PayloadDecrypt(ciphertext []byte, packetNumber []byte, header []byte) (plaintext []byte, err error) {
	// https://datatracker.ietf.org/doc/html/rfc9001#name-initial-secrets

	// We only decrypt once, so we do not need to XOR it back.
	// https://github.com/quic-go/qtls-go1-20/blob/e132a0e6cb45e20ac0b705454849a11d09ba5a54/cipher_suites.go#L496
	var nonce [12]byte
	copy(nonce[:], k.iv)
	for i := range packetNumber {
		nonce[len(k.iv)-len(packetNumber)+i] ^= packetNumber[i]
	}
	plaintext = make([]byte, len(ciphertext)-k.aead.Overhead())
	plaintext, err = k.aead.Open(plaintext[:0], nonce[:len(k.iv)], ciphertext, header)
	if err != nil {
		// Do nothing.
	}
	return plaintext, nil
}

func (k *Keys) PayloadDecryptFromPool(ciphertext []byte, packetNumber []byte, header []byte) (plaintext []byte, err error) {
	var nonce [12]byte
	copy(nonce[:], k.iv)
	for i := range packetNumber {
		nonce[len(k.iv)-len(packetNumber)+i] ^= packetNumber[i]
	}
	plaintext = pool.Get(len(ciphertext) - k.aead.Overhead())
	plaintext, err = k.aead.Open(plaintext[:0], nonce[:len(k.iv)], ciphertext, header)
	if err != nil {
		pool.Put(plaintext)
		return nil, err
	}
	return plaintext, nil
}

func DecryptQuic_(header []byte, blockEnd int, destConnId []byte) (plaintext []byte, err error) {
	_version := binary.BigEndian.Uint32(header[1:])
	version, err := ParseVersion(_version)
	if err != nil {
		return nil, err
	}
	keys, err := NewKeys(destConnId, version, common.NewGcm)
	if err != nil {
		return nil, err
	}
	defer keys.Close()
	return DecryptQuicWithKeys_(header, blockEnd, keys)
}

func DecryptQuicWithKeys_(header []byte, blockEnd int, keys *Keys) (plaintext []byte, err error) {
	return decryptQuicWithKeys(header, blockEnd, keys, false)
}

func DecryptQuicWithKeysFromPool_(header []byte, blockEnd int, keys *Keys) (plaintext []byte, err error) {
	return decryptQuicWithKeys(header, blockEnd, keys, true)
}

func decryptQuicWithKeys(header []byte, blockEnd int, keys *Keys, fromPool bool) (plaintext []byte, err error) {
	if blockEnd-len(header) < SampleSize {
		return nil, io.ErrUnexpectedEOF
	}
	// Sample 16B
	sample := header[len(header) : len(header)+SampleSize]

	// Decrypt header flag and packet number.
	var packetNumber []byte
	if packetNumber, err = keys.HeaderProtection_(sample, true, &header[0], header[len(header)-MaxPacketNumberLength:]); err != nil {
		return nil, err
	}
	header = header[:len(header)-MaxPacketNumberLength+len(packetNumber)] // Correct header
	payload := header[len(header):blockEnd]                               // Correct payload

	if fromPool {
		plaintext, err = keys.PayloadDecryptFromPool(payload, packetNumber, header)
	} else {
		plaintext, err = keys.PayloadDecrypt(payload, packetNumber, header)
	}
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
