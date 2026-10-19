package runtimehost

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pexcn/vowifi-go/engine/sim"
	"github.com/pexcn/vowifi-go/runtimehost/identity"
)

type testSIM struct{}

func (testSIM) GetIMSI() (string, error) { return "001010123456789", nil }
func (testSIM) CalculateAKA([]byte, []byte) (sim.AKAResult, error) {
	return sim.AKAResult{}, errors.New("test does not authenticate")
}
func (testSIM) Close() error { return errors.New("borrowed provider must not be closed") }
func testRequest() StartRequest {
	return StartRequest{DeviceID: "device", SIM: testSIM{}, Prepared: &identity.PreparedSession{Profile: identity.Profile{IMSI: "001010123456789", MCC: "001", MNC: "01"}, EPDGAddr: "epdg.invalid"}}
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

func TestStartupFailureCleansOwnedResourcesInReverse(t *testing.T) {
	var order []string
	want := errors.New("IMS authentication rejected")
	inst, err := start(context.Background(), testRequest(), startup{connect: func(_ context.Context, _ StartRequest, i *Instance) error {
		_ = i.own(closeFunc(func() error { order = append(order, "tunnel"); return nil }))
		_ = i.own(closeFunc(func() error { order = append(order, "IMS"); return nil }))
		i.update(func(s *State) { s.TunnelReady = true })
		return want
	}})
	if !errors.Is(err, want) {
		t.Fatalf("error %v", err)
	}
	if !reflect.DeepEqual(order, []string{"IMS", "tunnel"}) {
		t.Fatal(order)
	}
	if s := inst.State(); s.Phase != PhaseFailed || s.TunnelReady || s.IMSReady || s.SMSReady {
		t.Fatalf("false readiness: %+v", s)
	}
}

func TestEpochInvalidationCancelsBlockedStartup(t *testing.T) {
	var mu sync.Mutex
	current := true
	req := testRequest()
	req.ShouldRun = func() bool { mu.Lock(); defer mu.Unlock(); return current }
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := start(context.Background(), req, startup{connect: func(ctx context.Context, _ StartRequest, _ *Instance) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		}})
		result <- err
	}()
	<-entered
	mu.Lock()
	current = false
	mu.Unlock()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale startup not cancelled")
	}
}

func TestFailedCleanupRetainsOwnershipForRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	i := &Instance{ctx: ctx, cancel: cancel}
	attempts := 0
	_ = i.own(closeFunc(func() error {
		attempts++
		if attempts == 1 {
			return errors.New("temporary close failure")
		}
		return nil
	}))
	if err := i.Stop(context.Background()); err == nil {
		t.Fatal("lost cleanup error")
	}
	if err := i.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("close attempts %d", attempts)
	}
	if err := i.Stop(context.Background()); err != nil || attempts != 2 {
		t.Fatalf("non-idempotent stop: %v %d", err, attempts)
	}
}

func TestObserverCanReadStateAndZeroValueCanStop(t *testing.T) {
	i := &Instance{}
	called := false
	i.AddObserver(ObserverFunc(func(_ context.Context, ev Event) { called = true; _ = i.State(); _ = ev.State }))
	if !called {
		t.Fatal("observer not given current state")
	}
	if err := i.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if i.Service() != nil || i.State().Phase != PhaseStopped {
		t.Fatal("zero-value stop")
	}
}
