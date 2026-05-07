package control

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
)

func TestRuntimeDepsWithDefaultsCreatesFreshInstances(t *testing.T) {
	deps := (RuntimeDeps{}).withDefaults(logrus.New())
	defer deps.UdpEndpointPool.Close()
	defer deps.UdpTaskPool.Close()
	defer deps.AnyfromPool.Close()

	if deps.Netns == nil {
		t.Fatal("expected netns to be created")
	}
	if deps.UdpEndpointPool == nil {
		t.Fatal("expected udp endpoint pool to be created")
	}
	if deps.UdpTaskPool == nil {
		t.Fatal("expected udp task pool to be created")
	}
	if deps.AnyfromPool == nil {
		t.Fatal("expected anyfrom pool to be created")
	}
	if deps.UdpEndpointPool == DefaultUdpEndpointPool {
		t.Fatal("expected fresh udp endpoint pool instead of package global default")
	}
	if deps.UdpTaskPool == DefaultUdpTaskPool {
		t.Fatal("expected fresh udp task pool instead of package global default")
	}
	if deps.AnyfromPool == DefaultAnyfromPool {
		t.Fatal("expected fresh anyfrom pool instead of package global default")
	}
	if deps.AnyfromPool.netns != deps.Netns {
		t.Fatal("expected anyfrom pool to inherit the created netns")
	}
	if global := GetDaeNetns(); global != nil && deps.Netns == global {
		t.Fatal("expected fresh netns instead of package global default")
	}
}

func TestChooseDialTargetUsesDomainForUnspecifiedDest(t *testing.T) {
	c := &ControlPlane{
		log:      logrus.New(),
		dialMode: consts.DialMode_Ip,
	}
	target, _, dialIP := c.ChooseDialTarget(
		context.Background(),
		netip.MustParseAddrPort("0.0.0.0:0"),
		&bpfRoutingResult{},
		consts.OutboundDirect,
		netip.MustParseAddrPort("0.0.0.0:443"),
		"example.com",
	)
	if target != "example.com:443" {
		t.Fatalf("target = %q, want example.com:443", target)
	}
	if dialIP {
		t.Fatal("dialIP = true, want false for domain-only target")
	}
}

func TestRuntimeDepsWithDefaultsPreservesProvidedInstances(t *testing.T) {
	netns := NewDaeNetns(logrus.New())
	udpPool := NewUdpEndpointPool()
	udpTaskPool := NewUdpTaskPool()
	anyfromPool := NewAnyfromPoolWithNetns(netns)
	defer udpPool.Close()
	defer udpTaskPool.Close()
	defer anyfromPool.Close()

	deps := (RuntimeDeps{
		Netns:           netns,
		UdpEndpointPool: udpPool,
		UdpTaskPool:     udpTaskPool,
		AnyfromPool:     anyfromPool,
	}).withDefaults(logrus.New())

	if deps.Netns != netns {
		t.Fatal("expected provided netns to be preserved")
	}
	if deps.UdpEndpointPool != udpPool {
		t.Fatal("expected provided udp endpoint pool to be preserved")
	}
	if deps.UdpTaskPool != udpTaskPool {
		t.Fatal("expected provided udp task pool to be preserved")
	}
	if deps.AnyfromPool != anyfromPool {
		t.Fatal("expected provided anyfrom pool to be preserved")
	}
}

func TestControlPlaneCloseReturnsCleanupErrors(t *testing.T) {
	expected := errors.New("cleanup failed")
	plane := &ControlPlane{
		cancel: func() {},
		deferFuncs: []func() error{
			func() error { return expected },
		},
	}

	if err := plane.Close(); !errors.Is(err, expected) {
		t.Fatalf("Close() error = %v, want cleanup error", err)
	}
}

type controlPlaneTestDomainMatcher struct {
	closeCount int
}

func (m *controlPlaneTestDomainMatcher) AddSet(int, []string, consts.RoutingDomainKey) {}

func (m *controlPlaneTestDomainMatcher) Build() error { return nil }

func (m *controlPlaneTestDomainMatcher) MatchDomainBitmap(string) []uint32 {
	return []uint32{0}
}

func (m *controlPlaneTestDomainMatcher) Close() {
	m.closeCount++
}

type controlPlaneFixedBitmapMatcher struct {
	bitmap []uint32
}

func (m *controlPlaneFixedBitmapMatcher) AddSet(int, []string, consts.RoutingDomainKey) {}
func (m *controlPlaneFixedBitmapMatcher) Build() error                                  { return nil }
func (m *controlPlaneFixedBitmapMatcher) MatchDomainBitmap(string) []uint32 {
	return append([]uint32(nil), m.bitmap...)
}

var (
	_ routing.DomainMatcher       = (*controlPlaneTestDomainMatcher)(nil)
	_ routing.DomainMatcherCloser = (*controlPlaneTestDomainMatcher)(nil)
	_ routing.DomainMatcher       = (*controlPlaneFixedBitmapMatcher)(nil)
)

func TestRoutingMatcherClosePreventsDomainMatcherUse(t *testing.T) {
	domainMatcher := &controlPlaneTestDomainMatcher{}
	matcher := &RoutingMatcher{domainMatcher: domainMatcher}

	matcher.Close()
	matcher.Close()

	if domainMatcher.closeCount != 1 {
		t.Fatalf("domain matcher close count = %d, want 1", domainMatcher.closeCount)
	}
	if _, err := matcher.MatchDomainBitmap("example.com"); err == nil {
		t.Fatal("MatchDomainBitmap after Close() error = nil, want error")
	}
}

func TestNewDnsCacheEntryUsesRoutingMatcherBitmap(t *testing.T) {
	plane := &ControlPlane{
		routingMatcher: &RoutingMatcher{
			domainMatcher: &controlPlaneFixedBitmapMatcher{bitmap: []uint32{3}},
		},
	}
	cache, err := plane.newDnsCacheEntry(
		"example.com.",
		nil,
		time.Now(),
		time.Now(),
	)
	if err != nil {
		t.Fatalf("newDnsCacheEntry() error = %v", err)
	}
	if len(cache.DomainBitmap) != 1 || cache.DomainBitmap[0] != 3 {
		t.Fatalf("unexpected domain bitmap: %#v", cache.DomainBitmap)
	}
	if cache.HasAnyIP {
		t.Fatal("expected empty answers to report HasAnyIP=false")
	}
}
