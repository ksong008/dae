//go:build !rust_domain_matcher || !cgo

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
)

func NewDefaultDomainMatcher(log *logrus.Logger, bitLength int) routing.DomainMatcher {
	return NewAhocorasickSlimtrie(log, bitLength)
}
