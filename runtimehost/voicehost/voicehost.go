// Package voicehost connects host voice requests to a registered IMS agent.
package voicehost

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
)

const (
	DefaultSimulateCallHoldSeconds = 10
	MaxSimulateCallHoldSeconds     = 60
)

type SimulateCallRequest struct {
	Callee      string
	HoldSeconds int
	OnConnected func()
}
type SimulateCallResult struct {
	Success    bool
	Reason     string
	DurationMs int64
}
type Agent interface {
	SimulateCall(context.Context, SimulateCallRequest) (SimulateCallResult, error)
}
type incomingNotifier interface {
	NotifyIncomingCall(deviceID, caller, callee string)
}
type Gateway struct {
	mu       sync.RWMutex
	agents   map[string]interface{}
	notifier interface{}
	started  bool
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewGateway() *Gateway { return &Gateway{agents: make(map[string]interface{})} }
func (g *Gateway) Start(ctx context.Context) error {
	if g == nil {
		return errors.New("voice gateway is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.started {
		return nil
	}
	g.ctx, g.cancel = context.WithCancel(ctx)
	g.started = true
	return nil
}
func (g *Gateway) Stop() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	g.started = false
	if g.cancel != nil {
		g.cancel()
	}
	g.mu.Unlock()
	return nil
}
func (g *Gateway) SetNotifier(n interface{}) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.notifier = n
	g.mu.Unlock()
}
func (g *Gateway) NotifyIncomingCall(deviceID, caller, callee string) {
	if g == nil {
		return
	}
	g.mu.RLock()
	n, _ := g.notifier.(incomingNotifier)
	g.mu.RUnlock()
	if n != nil {
		n.NotifyIncomingCall(deviceID, caller, callee)
	}
}
func (g *Gateway) RegisterAgent(deviceID string, agent interface{}) {
	if g == nil || deviceID == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.agents == nil {
		g.agents = make(map[string]interface{})
	}
	if agent == nil {
		delete(g.agents, deviceID)
	} else {
		g.agents[deviceID] = agent
	}
}

// UnregisterAgent cannot remove a replacement owned by a newer startup.
func (g *Gateway) UnregisterAgent(deviceID string, agent interface{}) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	current := g.agents[deviceID]
	if current == nil || agent == nil {
		return
	}
	a, b := reflect.ValueOf(current), reflect.ValueOf(agent)
	if a.Type() == b.Type() && a.Comparable() && a.Interface() == b.Interface() {
		delete(g.agents, deviceID)
	}
}
func (g *Gateway) GetAgent(deviceID string) interface{} {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.agents[deviceID]
}
func (g *Gateway) DeviceStatus(deviceID string) string {
	if g == nil {
		return "stopped"
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.started || g.ctx == nil || g.ctx.Err() != nil {
		return "stopped"
	}
	a := g.agents[deviceID]
	if a == nil {
		return "not_ready"
	}
	if r, ok := a.(interface{ Ready() bool }); ok && !r.Ready() {
		return "not_ready"
	}
	if _, ok := a.(Agent); !ok {
		return "not_ready"
	}
	return "ready"
}
func (g *Gateway) SimulateCall(ctx context.Context, deviceID string, req SimulateCallRequest) (*SimulateCallResult, error) {
	if g == nil {
		return nil, errors.New("voice gateway is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	g.mu.RLock()
	a, ok := g.agents[deviceID].(Agent)
	running := g.started
	gatewayCtx := g.ctx
	g.mu.RUnlock()
	if !running || gatewayCtx == nil {
		return nil, errors.New("voice gateway stopped")
	}
	if !ok {
		return nil, fmt.Errorf("device %s VoWiFi voice agent not found", deviceID)
	}
	callCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(gatewayCtx, cancel)
	defer func() { stop(); cancel() }()
	res, err := a.SimulateCall(callCtx, req)
	return &res, err
}
