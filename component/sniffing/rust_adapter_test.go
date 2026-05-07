//go:build rust_sniffing && cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func newRustQuicSniffScratchForTest(tb testing.TB) *RustQuicSniffScratch {
	tb.Helper()

	scratch, err := NewRustQuicSniffScratch()
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(scratch.Close)
	return scratch
}

func TestRustQuicInitialSNIParity(t *testing.T) {
	scratch := newRustQuicSniffScratchForTest(t)
	out := make([]byte, 256)

	n, err := scratch.SniffTwoInto(QuicStream2_1, QuicStream2_2, out)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out[:n]), "i.ytimg.com"; got != want {
		t.Fatalf("split QUIC SNI = %q, want %q", got, want)
	}

	n, err = scratch.SniffTwoInto(QuicStream3, nil, out)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out[:n]), "i.ytimg.com"; got != want {
		t.Fatalf("single QUIC SNI = %q, want %q", got, want)
	}
}

func TestRustHTTPHostParity(t *testing.T) {
	scratch := newRustQuicSniffScratchForTest(t)
	out := make([]byte, 256)
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")

	n, err := scratch.SniffHTTPHostInto(request, out)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out[:n]), " example.com"; got != want {
		t.Fatalf("HTTP Host = %q, want %q", got, want)
	}
}

func TestRustTLSSNIParity(t *testing.T) {
	scratch := newRustQuicSniffScratchForTest(t)
	out := make([]byte, 256)

	n, err := scratch.SniffTLSSNIInto(tlsStreamGoogle, out)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out[:n]), "www.google.com"; got != want {
		t.Fatalf("TLS SNI = %q, want %q", got, want)
	}
}

func TestRustSnifferRuntimeHTTPAndCloseLifecycle(t *testing.T) {
	drainRustSniffingScratchPoolForTest(t)

	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
	sniffer := NewPacketSniffer(request, time.Second)
	host, err := sniffer.SniffHttp()
	if err != nil {
		t.Fatal(err)
	}
	if host != " example.com" {
		t.Fatalf("HTTP Host = %q, want %q", host, " example.com")
	}

	scratch := sniffer.rustSniffing.scratch
	if scratch == nil {
		t.Fatal("expected runtime Rust sniffing scratch to be initialized")
	}
	if err := sniffer.Close(); err != nil {
		t.Fatal(err)
	}
	if sniffer.rustSniffing.scratch != nil {
		t.Fatal("expected Close() to detach runtime Rust sniffing scratch")
	}

	select {
	case got := <-rustSniffingScratchPool:
		if got != scratch {
			got.Close()
			t.Fatal("Close() returned a different Rust sniffing scratch to the pool")
		}
		got.Close()
	default:
		t.Fatal("expected Close() to return runtime Rust sniffing scratch to the pool")
	}
}

func TestRustSnifferRuntimeTLSThroughSniffTcp(t *testing.T) {
	sniffer := NewPacketSniffer(tlsStreamGoogle, time.Second)
	t.Cleanup(func() {
		_ = sniffer.Close()
	})

	sni, err := sniffer.SniffTcp()
	if err != nil {
		t.Fatal(err)
	}
	if sni != "www.google.com" {
		t.Fatalf("TLS SNI = %q, want %q", sni, "www.google.com")
	}
	if sniffer.rustSniffing.scratch == nil {
		t.Fatal("expected SniffTcp() to use runtime Rust sniffing scratch")
	}
}

func TestRustSnifferRuntimeQUICNeedMoreAndAppend(t *testing.T) {
	sniffer := NewPacketSniffer(QuicStream2_1, time.Second)
	t.Cleanup(func() {
		_ = sniffer.Close()
	})

	_, err := sniffer.SniffQuic()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("first SniffQuic() error = %v, want ErrNotFound", err)
	}
	if !sniffer.NeedMore() {
		t.Fatal("expected NeedMore() after first split QUIC Initial packet")
	}

	sniffer.AppendData(QuicStream2_2)
	sni, err := sniffer.SniffQuic()
	if err != nil {
		t.Fatal(err)
	}
	if sni != "i.ytimg.com" {
		t.Fatalf("QUIC SNI = %q, want %q", sni, "i.ytimg.com")
	}
	if sniffer.NeedMore() {
		t.Fatal("expected NeedMore() to be cleared after AppendData")
	}
	if sniffer.rustSniffing.scratch == nil {
		t.Fatal("expected SniffQuic() to use runtime Rust sniffing scratch")
	}
}

func drainRustSniffingScratchPoolForTest(tb testing.TB) {
	tb.Helper()
	for {
		select {
		case scratch := <-rustSniffingScratchPool:
			scratch.Close()
		default:
			return
		}
	}
}

func BenchmarkGoHTTPHost(b *testing.B) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sniffer := NewPacketSniffer(nil, 0)
		sniffer.AppendData(request)
		host, err := sniffer.SniffHttp()
		_ = sniffer.Close()
		if err != nil {
			b.Fatal(err)
		}
		if host != " example.com" {
			b.Fatal(host)
		}
	}
}

func BenchmarkRustHTTPHostInto(b *testing.B) {
	scratch := newRustQuicSniffScratchForTest(b)
	out := make([]byte, 256)
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
	want := []byte(" example.com")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := scratch.SniffHTTPHostInto(request, out)
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(out[:n], want) {
			b.Fatalf("HTTP Host = %q, want %q", out[:n], want)
		}
	}
}

func BenchmarkGoTLSSNI(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sniffer := NewPacketSniffer(nil, 0)
		sniffer.AppendData(tlsStreamGoogle)
		sni, err := sniffer.SniffTls()
		_ = sniffer.Close()
		if err != nil {
			b.Fatal(err)
		}
		if sni != "www.google.com" {
			b.Fatal(sni)
		}
	}
}

func BenchmarkRustTLSSNIInto(b *testing.B) {
	scratch := newRustQuicSniffScratchForTest(b)
	out := make([]byte, 256)
	want := []byte("www.google.com")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := scratch.SniffTLSSNIInto(tlsStreamGoogle, out)
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(out[:n], want) {
			b.Fatalf("TLS SNI = %q, want %q", out[:n], want)
		}
	}
}

func BenchmarkRustQuicInitialSNIReuseScratch(b *testing.B) {
	scratch := newRustQuicSniffScratchForTest(b)
	out := make([]byte, 256)
	want := []byte("i.ytimg.com")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := scratch.SniffTwoInto(QuicStream2_1, QuicStream2_2, out)
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(out[:n], want) {
			b.Fatalf("SNI = %q, want %q", out[:n], want)
		}
	}
}
