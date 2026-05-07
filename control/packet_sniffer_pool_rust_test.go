//go:build rust_sniffing && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package control

import (
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
)

func decodePacketSnifferHexForRustTest(tb testing.TB, index int) []byte {
	tb.Helper()

	data, err := hex.DecodeString(testPacketSnifferData[index])
	if err != nil {
		tb.Fatalf("decode fixture %d: %v", index, err)
	}
	return data
}

func TestPacketSnifferPoolRemoveClosesInitializedRustSniffer(t *testing.T) {
	pool := NewPacketSnifferPool()
	defer pool.Close()

	key := PacketSnifferKey{
		LAddr: netip.MustParseAddrPort("1.1.1.1:41001"),
		RAddr: netip.MustParseAddrPort("2.2.2.2:41001"),
	}
	snifferSession, _ := pool.GetOrCreate(key, &PacketSnifferOptions{Ttl: time.Second})

	snifferSession.AppendData(decodePacketSnifferHexForRustTest(t, 0))
	_, err := snifferSession.SniffUdp()
	if err != nil && !sniffing.IsSniffingError(err) {
		t.Fatal(err)
	}
	if !snifferSession.NeedMore() {
		t.Fatal("expected NeedMore() after first QUIC packet")
	}

	snifferSession.AppendData(decodePacketSnifferHexForRustTest(t, 1))
	domain, err := snifferSession.SniffUdp()
	if err != nil {
		t.Fatal(err)
	}
	if domain != "i.ytimg.com" {
		t.Fatalf("domain = %q, want %q", domain, "i.ytimg.com")
	}

	if err := pool.Remove(key, snifferSession); err != nil {
		t.Fatal(err)
	}
	if pool.Get(key) != nil {
		t.Fatal("expected packet sniffer session to be removed from the pool")
	}
	if err := snifferSession.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPacketSnifferPoolFlushClosesInitializedRustSniffers(t *testing.T) {
	pool := NewPacketSnifferPool()
	defer pool.Close()

	keys := []PacketSnifferKey{
		{
			LAddr: netip.MustParseAddrPort("1.1.1.1:42001"),
			RAddr: netip.MustParseAddrPort("2.2.2.2:42001"),
		},
		{
			LAddr: netip.MustParseAddrPort("1.1.1.1:42002"),
			RAddr: netip.MustParseAddrPort("2.2.2.2:42002"),
		},
	}

	for _, key := range keys {
		snifferSession, _ := pool.GetOrCreate(key, &PacketSnifferOptions{Ttl: time.Second})
		snifferSession.AppendData(decodePacketSnifferHexForRustTest(t, 0))
		_, err := snifferSession.SniffUdp()
		if err != nil && !sniffing.IsSniffingError(err) {
			t.Fatal(err)
		}
	}

	if err := pool.Flush(); err != nil {
		t.Fatal(err)
	}
	if pool.Count() != 0 {
		t.Fatalf("expected flushed packet sniffer pool to be empty, got %d", pool.Count())
	}
}
