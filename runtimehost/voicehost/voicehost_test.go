package voicehost

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testAgent struct{ started chan struct{} }

func (a *testAgent) Ready() bool { return true }
func (a *testAgent) SimulateCall(ctx context.Context, r SimulateCallRequest) (SimulateCallResult, error) {
	close(a.started)
	<-ctx.Done()
	return SimulateCallResult{}, ctx.Err()
}

type incomparableAgent []int

func (incomparableAgent) SimulateCall(context.Context, SimulateCallRequest) (SimulateCallResult, error) {
	return SimulateCallResult{}, errors.New("unused")
}
func TestGatewayRequiresRealAgentAndPreservesReplacement(t *testing.T) {
	g := NewGateway()
	if g.DeviceStatus("sim") != "stopped" {
		t.Fatal("new gateway ready")
	}
	if e := g.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	defer g.Stop()
	if _, e := g.SimulateCall(context.Background(), "sim", SimulateCallRequest{}); e == nil {
		t.Fatal("fabricated call without registered agent")
	}
	old, newer := &testAgent{}, &testAgent{}
	g.RegisterAgent("sim", old)
	g.RegisterAgent("sim", newer)
	g.UnregisterAgent("sim", old)
	if g.GetAgent("sim") != newer || g.DeviceStatus("sim") != "ready" {
		t.Fatal("old cleanup removed replacement")
	}
	g.UnregisterAgent("sim", newer)
	if g.GetAgent("sim") != nil {
		t.Fatal("did not unregister owner")
	}
	g.RegisterAgent("slice", incomparableAgent{1})
	g.UnregisterAgent("slice", incomparableAgent{1})
}
func TestGatewayStopCancelsActiveCall(t *testing.T) {
	g := NewGateway()
	g.Start(context.Background())
	a := &testAgent{started: make(chan struct{})}
	g.RegisterAgent("sim", a)
	done := make(chan error, 1)
	go func() { _, e := g.SimulateCall(context.Background(), "sim", SimulateCallRequest{}); done <- e }()
	<-a.started
	g.Stop()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway stop leaked call")
	}
	if g.DeviceStatus("sim") != "stopped" {
		t.Fatal("stopped gateway ready")
	}
}
