/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"testing"

	dnsmessage "github.com/miekg/dns"
)

func TestWriteRuntimeRejectResponseUsesMessageWriter(t *testing.T) {
	req := new(dnsmessage.Msg)
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	req.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
			A:   []byte{1, 1, 1, 1},
		},
	}

	var got *dnsmessage.Msg
	err := writeRuntimeRejectResponse(req, func(msg *dnsmessage.Msg) error {
		copied := msg.Copy()
		got = copied
		return nil
	}, nil)
	if err != nil {
		t.Fatalf("writeRuntimeRejectResponse() error = %v", err)
	}
	if got == nil {
		t.Fatal("expected message writer to be called")
	}
	if len(got.Answer) != 0 {
		t.Fatalf("expected reject response to clear answers, got %d", len(got.Answer))
	}
	if !got.Response || got.Rcode != dnsmessage.RcodeSuccess || !got.RecursionAvailable || got.Truncated {
		t.Fatalf("unexpected reject response flags: %+v", got)
	}
}

func TestWriteRuntimeResponseUnpacksForMessageWriter(t *testing.T) {
	msg := new(dnsmessage.Msg)
	msg.SetReply(&dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{Id: 1234},
		Question: []dnsmessage.Question{
			{Name: "example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
	})
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
			A:   []byte{1, 1, 1, 1},
		},
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	var got *dnsmessage.Msg
	err = writeRuntimeResponse(packed, func(resp *dnsmessage.Msg) error {
		got = resp.Copy()
		return nil
	}, nil)
	if err != nil {
		t.Fatalf("writeRuntimeResponse() error = %v", err)
	}
	if got == nil {
		t.Fatal("expected message writer to be called")
	}
	if got.Id != msg.Id || len(got.Answer) != 1 {
		t.Fatalf("unexpected unpacked response: %+v", got)
	}
}
