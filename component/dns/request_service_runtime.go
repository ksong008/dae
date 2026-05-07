/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import dnsmessage "github.com/miekg/dns"

type RequestServiceRuntime struct {
	routing *Dns
	handler *RequestHandlerRuntime
}

func NewRequestServiceRuntime(routing *Dns) *RequestServiceRuntime {
	return &RequestServiceRuntime{
		routing: routing,
		handler: NewRequestHandlerRuntime(),
	}
}

func (r *RequestServiceRuntime) Handle(
	msg *dnsmessage.Msg,
	needResp bool,
	allowAsIs bool,
	hooks RequestHandlerHooks,
) error {
	qname, qtype := requestQuestion(msg)
	plan, err := r.routing.PlanRequest(qname, qtype)
	if err != nil {
		return err
	}
	return r.handler.ServeRequest(msg, plan, needResp, allowAsIs, hooks)
}
