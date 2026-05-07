/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	tc "github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	dnsmessage "github.com/miekg/dns"
)

type DnsForwarder interface {
	ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error)
	Close() error
}

type ForwarderPath struct {
	Dialer     netproxy.Dialer
	BestTarget netip.AddrPort
	Mark       uint32
	MPTCP      bool
	L4Proto    consts.L4ProtoStr
}

type ForwarderHooks struct {
	OnUDPRetry            func()
	OnDoHStatusFailure    func()
	OnDoHContentTypeError func()
}

func ForwarderReusable(upstream *Upstream, path ForwarderPath) bool {
	switch path.L4Proto {
	case consts.L4ProtoStr_TCP:
		return upstream.Scheme == UpstreamScheme_HTTPS
	case consts.L4ProtoStr_UDP:
		return upstream.Scheme == UpstreamScheme_H3 ||
			upstream.Scheme == UpstreamScheme_QUIC
	default:
		return false
	}
}

func NewForwarder(upstream *Upstream, path ForwarderPath, hooks ForwarderHooks) (DnsForwarder, error) {
	switch path.L4Proto {
	case consts.L4ProtoStr_TCP:
		switch upstream.Scheme {
		case UpstreamScheme_TCP, UpstreamScheme_TCP_UDP:
			return &DoTCP{Upstream: *upstream, path: path}, nil
		case UpstreamScheme_TLS:
			return &DoTLS{Upstream: *upstream, path: path}, nil
		case UpstreamScheme_HTTPS:
			return &DoH{Upstream: *upstream, path: path, hooks: hooks, http3: false}, nil
		default:
			return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
		}
	case consts.L4ProtoStr_UDP:
		switch upstream.Scheme {
		case UpstreamScheme_UDP, UpstreamScheme_TCP_UDP:
			return &DoUDP{Upstream: *upstream, path: path, hooks: hooks}, nil
		case UpstreamScheme_QUIC:
			return &DoQ{Upstream: *upstream, path: path}, nil
		case UpstreamScheme_H3:
			return &DoH{Upstream: *upstream, path: path, hooks: hooks, http3: true}, nil
		default:
			return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
		}
	default:
		return nil, fmt.Errorf("unexpected l4proto: %v", path.L4Proto)
	}
}

type DoH struct {
	Upstream
	path      ForwarderPath
	hooks     ForwarderHooks
	http3     bool
	mu        sync.Mutex
	client    *http.Client
	transport http.RoundTripper
}

func (d *DoH) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	return sendHttpDNS(ctx, d.getClient(), d.path.BestTarget.String(), &d.Upstream, data, d.hooks)
}

func (d *DoH) getClient() *http.Client {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.client == nil {
		if d.http3 {
			d.transport = d.getHttp3RoundTripper()
		} else {
			d.transport = d.getHttpRoundTripper()
		}
		d.client = &http.Client{
			Transport: d.transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("do not use a server that will redirect, upstream: %v", d.Upstream.String())
			},
		}
	}
	return d.client
}

func (d *DoH) getHttpRoundTripper() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			InsecureSkipVerify: false,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := d.path.Dialer.DialContext(
				ctx,
				common.MagicNetwork("tcp", d.path.Mark, d.path.MPTCP),
				d.path.BestTarget.String(),
			)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{Conn: conn}, nil
		},
	}
}

func (d *DoH) getHttp3RoundTripper() *http3.RoundTripper {
	return &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: false,
		},
		QUICConfig: &quic.Config{},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			udpAddr := net.UDPAddrFromAddrPort(d.path.BestTarget)
			conn, err := d.path.Dialer.DialContext(
				ctx,
				common.MagicNetwork("udp", d.path.Mark, d.path.MPTCP),
				d.path.BestTarget.String(),
			)
			if err != nil {
				return nil, err
			}
			fakePkt := netproxy.NewFakeNetPacketConn(conn.(netproxy.PacketConn), net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
			return quic.DialEarly(ctx, fakePkt, udpAddr, tlsCfg, cfg)
		},
	}
}

func (d *DoH) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var err error
	switch transport := d.transport.(type) {
	case interface{ Close() error }:
		err = transport.Close()
	case interface{ CloseIdleConnections() }:
		transport.CloseIdleConnections()
	}
	d.client = nil
	d.transport = nil
	return err
}

type DoQ struct {
	Upstream
	path       ForwarderPath
	mu         sync.Mutex
	connection quic.EarlyConnection
}

func (d *DoQ) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.getConnection(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn, err = d.replaceConnection(ctx, conn)
		if err != nil {
			return nil, err
		}
		stream, err = conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = stream.Close() }()
	return sendStreamDNS(stream, dnsDataWithZeroID(data))
}

func (d *DoQ) getConnection(ctx context.Context) (quic.EarlyConnection, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.connection == nil {
		qc, err := d.createConnection(ctx)
		if err != nil {
			return nil, err
		}
		d.connection = qc
	}
	return d.connection, nil
}

func (d *DoQ) replaceConnection(ctx context.Context, stale quic.EarlyConnection) (quic.EarlyConnection, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if stale != nil && d.connection == stale {
		_ = stale.CloseWithError(0, "")
		d.connection = nil
	}
	if d.connection == nil {
		qc, err := d.createConnection(ctx)
		if err != nil {
			return nil, err
		}
		d.connection = qc
	}
	return d.connection, nil
}

func (d *DoQ) createConnection(ctx context.Context) (quic.EarlyConnection, error) {
	udpAddr := net.UDPAddrFromAddrPort(d.path.BestTarget)
	conn, err := d.path.Dialer.DialContext(
		ctx,
		common.MagicNetwork("udp", d.path.Mark, d.path.MPTCP),
		d.path.BestTarget.String(),
	)
	if err != nil {
		return nil, err
	}
	fakePkt := netproxy.NewFakeNetPacketConn(conn.(netproxy.PacketConn), net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
	tlsCfg := &tls.Config{
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	}
	addr := net.UDPAddrFromAddrPort(d.path.BestTarget)
	qc, err := quic.DialEarly(ctx, fakePkt, addr, tlsCfg, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return qc, nil
}

func (d *DoQ) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.connection != nil {
		err := d.connection.CloseWithError(0, "")
		d.connection = nil
		return err
	}
	return nil
}

type DoTLS struct {
	Upstream
	path ForwarderPath
	conn netproxy.Conn
}

func (d *DoTLS) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.path.Dialer.DialContext(
		ctx,
		common.MagicNetwork("tcp", d.path.Mark, d.path.MPTCP),
		d.path.BestTarget.String(),
	)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(&netproxy.FakeNetConn{Conn: conn}, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	})
	if err = tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	d.conn = tlsConn
	return sendStreamDNS(tlsConn, data)
}

func (d *DoTLS) Close() error {
	if d.conn != nil {
		conn := d.conn
		d.conn = nil
		return conn.Close()
	}
	return nil
}

type DoTCP struct {
	Upstream
	path ForwarderPath
	conn netproxy.Conn
}

func (d *DoTCP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.path.Dialer.DialContext(
		ctx,
		common.MagicNetwork("tcp", d.path.Mark, d.path.MPTCP),
		d.path.BestTarget.String(),
	)
	if err != nil {
		return nil, err
	}
	d.conn = conn
	return sendStreamDNS(conn, data)
}

func (d *DoTCP) Close() error {
	if d.conn != nil {
		conn := d.conn
		d.conn = nil
		return conn.Close()
	}
	return nil
}

type DoUDP struct {
	Upstream
	path  ForwarderPath
	hooks ForwarderHooks
	conn  netproxy.Conn
}

func (d *DoUDP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.path.Dialer.DialContext(
		ctx,
		common.MagicNetwork("udp", d.path.Mark, d.path.MPTCP),
		d.path.BestTarget.String(),
	)
	if err != nil {
		return nil, err
	}
	d.conn = conn

	timeout := dnsForwardTimeout(ctx)
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	deadline := time.Now().Add(timeout)

	respBuf := pool.GetFullCap(consts.EthernetMtu)
	defer pool.Put(respBuf)

	for attempt := 0; attempt < dnsUDPAttempts; attempt++ {
		perAttemptDeadline := deadline
		if attempt < dnsUDPAttempts-1 {
			if retryDeadline := time.Now().Add(dnsUDPRetryInterval); retryDeadline.Before(perAttemptDeadline) {
				perAttemptDeadline = retryDeadline
			}
		}
		if err := conn.SetDeadline(perAttemptDeadline); err != nil {
			return nil, err
		}
		if _, err = netutils.WriteUDPConn(conn, d.path.BestTarget.String(), data); err != nil {
			return nil, err
		}
		n, err := netutils.ReadUDPConn(conn, respBuf)
		if err == nil {
			var msg dnsmessage.Msg
			if err = msg.Unpack(respBuf[:n]); err != nil {
				return nil, err
			}
			return &msg, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !shouldRetryUDPQuery(err) || attempt == dnsUDPAttempts-1 || time.Now().After(deadline) {
			return nil, err
		}
		if d.hooks.OnUDPRetry != nil {
			d.hooks.OnUDPRetry()
		}
	}
	return nil, context.DeadlineExceeded
}

func (d *DoUDP) Close() error {
	if d.conn != nil {
		conn := d.conn
		d.conn = nil
		return conn.Close()
	}
	return nil
}

const (
	dnsUDPAttempts      = 3
	dnsUDPRetryInterval = time.Second
	dnsUDPTimeout       = 5 * time.Second
)

func dnsForwardTimeout(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		timeout := time.Until(deadline)
		if timeout < dnsUDPTimeout {
			return timeout
		}
	}
	return dnsUDPTimeout
}

func shouldRetryUDPQuery(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func dnsDataWithZeroID(data []byte) []byte {
	cloned := append([]byte(nil), data...)
	if len(cloned) >= 2 {
		binary.BigEndian.PutUint16(cloned[0:2], 0)
	}
	return cloned
}

const doHMaxResponseBytes = 64 * 1024
const doHMediaType = "application/dns-message"
const doHGetMaxEncodedQueryBytes = 1024

const DoHMediaType = doHMediaType
const DoHGetMaxEncodedQueryBytes = doHGetMaxEncodedQueryBytes

func DnsDataWithZeroID(data []byte) []byte {
	return dnsDataWithZeroID(data)
}

func BuildDoHRequest(ctx context.Context, target string, upstream *Upstream, data []byte) (*http.Request, error) {
	return buildDoHRequest(ctx, target, upstream, data)
}

func ValidateDoHResponse(resp *http.Response) error {
	return validateDoHResponse(resp, ForwarderHooks{})
}

func SendHttpDNS(ctx context.Context, client *http.Client, target string, upstream *Upstream, data []byte) (*dnsmessage.Msg, error) {
	return sendHttpDNS(ctx, client, target, upstream, data, ForwarderHooks{})
}

func SendHttpDNSWithHooks(ctx context.Context, client *http.Client, target string, upstream *Upstream, data []byte, hooks ForwarderHooks) (*dnsmessage.Msg, error) {
	return sendHttpDNS(ctx, client, target, upstream, data, hooks)
}

func buildDoHRequest(ctx context.Context, target string, upstream *Upstream, data []byte) (*http.Request, error) {
	requestBody := dnsDataWithZeroID(data)
	serverURL := url.URL{
		Scheme: "https",
		Host:   target,
		Path:   upstream.Path,
	}
	encoded := base64.RawURLEncoding.EncodeToString(requestBody)

	var (
		req *http.Request
		err error
	)
	if len(encoded) <= doHGetMaxEncodedQueryBytes {
		q := serverURL.Query()
		q.Set("dns", encoded)
		serverURL.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, serverURL.String(), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, serverURL.String(), bytes.NewReader(requestBody))
		if err == nil {
			req.Header.Set("Content-Type", doHMediaType)
		}
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", doHMediaType)
	req.Host = upstream.Hostname
	return req, nil
}

func validateDoHResponse(resp *http.Response, hooks ForwarderHooks) error {
	if resp.StatusCode != http.StatusOK {
		if hooks.OnDoHStatusFailure != nil {
			hooks.OnDoHStatusFailure()
		}
		return fmt.Errorf("doh server returned status %s", resp.Status)
	}
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		if hooks.OnDoHContentTypeError != nil {
			hooks.OnDoHContentTypeError()
		}
		return fmt.Errorf("invalid doh content-type %q: %w", contentType, err)
	}
	if mediaType != doHMediaType {
		if hooks.OnDoHContentTypeError != nil {
			hooks.OnDoHContentTypeError()
		}
		return fmt.Errorf("unexpected doh content-type %q", contentType)
	}
	return nil
}

func sendHttpDNS(ctx context.Context, client *http.Client, target string, upstream *Upstream, data []byte, hooks ForwarderHooks) (*dnsmessage.Msg, error) {
	req, err := buildDoHRequest(ctx, target, upstream, data)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := validateDoHResponse(resp, hooks); err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, doHMaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > doHMaxResponseBytes {
		return nil, fmt.Errorf("dns response too large: %d bytes", len(buf))
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack(buf); err != nil {
		return nil, err
	}
	return &msg, nil
}

func sendStreamDNS(stream io.ReadWriter, data []byte) (*dnsmessage.Msg, error) {
	bReq := pool.Get(2 + len(data))
	defer pool.Put(bReq)
	binary.BigEndian.PutUint16(bReq, uint16(len(data)))
	copy(bReq[2:], data)
	if _, err := stream.Write(bReq); err != nil {
		return nil, fmt.Errorf("failed to write DNS req: %w", err)
	}
	if _, err := io.ReadFull(stream, bReq[:2]); err != nil {
		return nil, fmt.Errorf("failed to read DNS resp payload length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(bReq))
	var buf []byte
	if len(bReq) < respLen {
		buf = pool.Get(respLen)
		defer pool.Put(buf)
	} else {
		buf = bReq
	}
	n, err := io.ReadFull(stream, buf[:respLen])
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS resp payload: %w", err)
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	return &msg, nil
}
