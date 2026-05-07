/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package engine

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

// Service is the downstream-facing engine boundary intended for dae-wing style
// ownership. It keeps config helpers and runtime lifecycle on one explicit
// interface so a future Rust-native implementation can satisfy the same shape.
type Service interface {
	EmptyGlobalSection() string
	EmptyDnsSection() string
	EmptyRoutingSection() string
	EmptyConfig() *config.Config
	ExportFlatDesc() []*FlatDesc
	ParseConfig(globalSection *string, dnsSection *string, routingSection *string) (*config.Config, error)
	NecessaryOutbounds(routing *config.Routing) []string
	Run(log *logrus.Logger, conf *config.Config, externGeoDataDirs []string, disableTimestamp bool, dry bool) error
	Reload(conf *config.Config) error
	ReloadWithContext(ctx context.Context, conf *config.Config) error
	Stop(timeout time.Duration) error
	ControlPlane() (*control.ControlPlane, error)
	GetRuntimeOverview(windowSec int, maxPoints int) (*RuntimeOverview, error)
	HTTPTransport() http.RoundTripper
	IsControlPlaneNotInit(err error) bool
}

const timedOutStartStopTimeout = 5 * time.Second

type NativeService struct {
	mu      sync.RWMutex
	startMu sync.Mutex

	engine  *Engine
	running bool

	opts Options

	log               *logrus.Logger
	externGeoDataDirs []string
	disableTimestamp  bool
	dry               bool
}

func NewNativeService(opts Options) *NativeService {
	return &NativeService{opts: opts}
}

func WrapEngine(engine *Engine) *NativeService {
	return &NativeService{engine: engine, running: engine != nil}
}

func (n *NativeService) Engine() *Engine {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.engine
}

func (n *NativeService) CurrentRuntime() (*Engine, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.engine, n.running
}

func (*NativeService) EmptyGlobalSection() string {
	return EmptyGlobalSection
}

func (*NativeService) EmptyDnsSection() string {
	return EmptyDnsSection
}

func (*NativeService) EmptyRoutingSection() string {
	return EmptyRoutingSection
}

func (*NativeService) EmptyConfig() *config.Config {
	return EmptyConfig()
}

func (*NativeService) ExportFlatDesc() []*FlatDesc {
	return ExportFlatDesc()
}

func (*NativeService) ParseConfig(globalSection *string, dnsSection *string, routingSection *string) (*config.Config, error) {
	return ParseConfig(globalSection, dnsSection, routingSection)
}

func (*NativeService) NecessaryOutbounds(routing *config.Routing) []string {
	return NecessaryOutbounds(routing)
}

func (n *NativeService) Run(log *logrus.Logger, conf *config.Config, externGeoDataDirs []string, disableTimestamp bool, dry bool) error {
	runtime := New(n.opts)
	n.markRunning(runtime, log, externGeoDataDirs, disableTimestamp, dry)
	err := runtime.Run(log, conf, externGeoDataDirs, disableTimestamp, dry)
	n.markStopped(runtime)
	return err
}

func (n *NativeService) Reload(conf *config.Config) error {
	return n.ReloadWithContext(context.Background(), conf)
}

func (n *NativeService) ReloadWithContext(ctx context.Context, conf *config.Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime, running := n.CurrentRuntime()
	if running && runtime != nil {
		return runtime.ReloadWithContext(ctx, conf)
	}

	n.startMu.Lock()
	defer n.startMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	runtime, running = n.CurrentRuntime()
	if running && runtime != nil {
		return runtime.ReloadWithContext(ctx, conf)
	}
	return n.startRuntime(ctx, conf)
}

func (n *NativeService) Stop(timeout time.Duration) error {
	runtime, running := n.CurrentRuntime()
	if !running || runtime == nil {
		return nil
	}
	return runtime.Stop(timeout)
}

func (n *NativeService) ControlPlane() (*control.ControlPlane, error) {
	runtime, running := n.CurrentRuntime()
	if !running || runtime == nil {
		return nil, ErrControlPlaneNotInit
	}
	return runtime.ControlPlane()
}

func (n *NativeService) GetRuntimeOverview(windowSec int, maxPoints int) (*RuntimeOverview, error) {
	runtime, running := n.CurrentRuntime()
	if !running || runtime == nil {
		return (&Engine{}).GetRuntimeOverview(windowSec, maxPoints)
	}
	return runtime.GetRuntimeOverview(windowSec, maxPoints)
}

func (n *NativeService) HTTPTransport() http.RoundTripper {
	runtime, running := n.CurrentRuntime()
	if !running || runtime == nil {
		return notInitializedTransport{}
	}
	return runtime.HTTPTransport()
}

func (*NativeService) IsControlPlaneNotInit(err error) bool {
	return errors.Is(err, ErrControlPlaneNotInit)
}

func (n *NativeService) markRunning(runtime *Engine, log *logrus.Logger, externGeoDataDirs []string, disableTimestamp bool, dry bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.engine = runtime
	n.running = true
	n.log = log
	n.externGeoDataDirs = append([]string(nil), externGeoDataDirs...)
	n.disableTimestamp = disableTimestamp
	n.dry = dry
}

func (n *NativeService) markStopped(runtime *Engine) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.engine != runtime {
		return
	}
	n.engine = nil
	n.running = false
}

func (n *NativeService) startRuntime(ctx context.Context, conf *config.Config) error {
	n.mu.RLock()
	log := n.log
	externGeoDataDirs := append([]string(nil), n.externGeoDataDirs...)
	disableTimestamp := n.disableTimestamp
	dry := n.dry
	opts := n.opts
	n.mu.RUnlock()
	if log == nil {
		log = logrus.New()
	}

	ready := make(chan struct{}, 1)
	opts.OnReady = func() {
		select {
		case ready <- struct{}{}:
		default:
		}
		if n.opts.OnReady != nil {
			n.opts.OnReady()
		}
	}
	runtime := New(opts)
	runErr := make(chan error, 1)
	n.markRunning(runtime, log, externGeoDataDirs, disableTimestamp, dry)

	go func() {
		err := runtime.Run(log, conf, externGeoDataDirs, disableTimestamp, dry)
		n.markStopped(runtime)
		runErr <- err
		close(runErr)
	}()

	if dry {
		return nil
	}

	select {
	case <-ready:
		return nil
	case err := <-runErr:
		if err == nil {
			return ErrControlPlaneNotInit
		}
		return err
	case <-ctx.Done():
		go func() {
			if err := runtime.Stop(timedOutStartStopTimeout); err != nil {
				log.WithError(err).Warnln("failed to stop runtime after start timeout")
			}
		}()
		return ctx.Err()
	}
}

type notInitializedTransport struct{}

func (notInitializedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, ErrControlPlaneNotInit
}

var _ Service = (*NativeService)(nil)
