/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"fmt"
	"strconv"
	"strings"
)

type DnsCacheKey struct {
	Host  string
	QType uint16
}

func NewDnsCacheKey(host string, qtype uint16) DnsCacheKey {
	return DnsCacheKey{
		Host:  canonicalCacheHost(host),
		QType: qtype,
	}
}

func ParseDnsCacheKey(raw string) (DnsCacheKey, error) {
	lastDot := strings.LastIndex(raw, ".")
	if lastDot == -1 || lastDot == len(raw)-1 {
		return DnsCacheKey{}, fmt.Errorf("invalid dns cache key: %q", raw)
	}
	qtype, err := strconv.ParseUint(raw[lastDot+1:], 10, 16)
	if err != nil {
		return DnsCacheKey{}, fmt.Errorf("invalid dns cache key qtype %q: %w", raw, err)
	}
	return DnsCacheKey{
		Host:  raw[:lastDot],
		QType: uint16(qtype),
	}, nil
}

func (k DnsCacheKey) String() string {
	buf := make([]byte, 0, len(k.Host)+7)
	buf = append(buf, k.Host...)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(k.QType), 10)
	return string(buf)
}

func canonicalCacheHost(host string) string {
	if host == "" {
		return ""
	}
	if host[len(host)-1] == '.' {
		host = host[:len(host)-1]
	}
	needsAlloc := false
	for i := 0; i < len(host); i++ {
		ch := host[i]
		if 'A' <= ch && ch <= 'Z' {
			needsAlloc = true
			break
		}
	}
	if !needsAlloc {
		return host
	}
	buf := make([]byte, 0, len(host))
	for i := 0; i < len(host); i++ {
		ch := host[i]
		if 'A' <= ch && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		buf = append(buf, ch)
	}
	return string(buf)
}
