package runtimehost

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestStartupObserverReceivesProgressBeforeStartReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan State, 16)
	req := testRequest()
	req.Observer = ObserverFunc(func(_ context.Context, ev Event) { events <- ev.State })
	connecting, finish := make(chan struct{}), make(chan struct{})
	done := make(chan *Instance, 1)
	go func() {
		inst, err := start(ctx, req, startup{connect: func(ctx context.Context, _ StartRequest, _ *Instance) error {
			close(connecting)
			select {
			case <-finish:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}})
		if err != nil {
			t.Errorf("start: %v", err)
		}
		done <- inst
	}()
	<-connecting
	for _, want := range []string{PhaseSIMReady, PhaseAccessReady, PhaseTunnelConnecting} {
		select {
		case state := <-events:
			if state.Phase != want || !state.SIMReady || state.TunnelReady || state.IMSReady || state.SMSReady {
				t.Fatalf("startup progress %s: %+v", want, state)
			}
			if state.AccessReady != (want != PhaseSIMReady) {
				t.Fatalf("incorrect access readiness: %+v", state)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s was not reported while Start was still connecting", want)
		}
	}
	select {
	case <-done:
		t.Fatal("Start returned before connect completed")
	default:
	}
	close(finish)
	inst := <-done
	if err := inst.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case state := <-events:
		if state.Phase != PhaseStopped {
			t.Fatalf("startup observer lost subsequent lifecycle events: %+v", state)
		}
	case <-time.After(time.Second):
		t.Fatal("startup observer did not receive stop")
	}
}

func TestStartupObserverReceivesFailureWithoutFalseReadiness(t *testing.T) {
	req := testRequest()
	events := make(chan State, 16)
	req.Observer = ObserverFunc(func(_ context.Context, ev Event) { events <- ev.State })
	want := errors.New("IMS rejected")
	inst, err := start(context.Background(), req, startup{connect: func(_ context.Context, _ StartRequest, inst *Instance) error {
		inst.update(func(s *State) { s.Phase = PhaseTunnelReady; s.TunnelReady = true })
		return want
	}})
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
	for _, phase := range []string{PhaseSIMReady, PhaseAccessReady, PhaseTunnelConnecting, PhaseTunnelReady, PhaseFailed} {
		select {
		case state := <-events:
			if state.Phase != phase {
				t.Fatalf("out of order: got %s, want %s", state.Phase, phase)
			}
			if phase == PhaseFailed && (state.TunnelReady || state.IMSReady || state.SMSReady || state.LastError != want.Error()) {
				t.Fatalf("failure retained false readiness: %+v", state)
			}
		case <-time.After(time.Second):
			t.Fatalf("missing %s event", phase)
		}
	}
	_ = inst.Stop(context.Background())
}

func TestObserverCanStopWithoutDeadlockAndTransitionsRemainOrdered(t *testing.T) {
	i := &Instance{}
	var seen []string
	done := make(chan struct{})
	i.AddObserver(ObserverFunc(func(_ context.Context, e Event) {
		seen = append(seen, e.State.Phase)
		if e.State.Phase == PhaseReady {
			if err := i.Stop(context.Background()); err != nil {
				t.Error(err)
			}
		}
		if e.State.Phase == PhaseStopped {
			close(done)
		}
	}))
	i.update(func(s *State) { s.Phase = PhaseReady; s.IMSReady = true })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("observer Stop deadlocked")
	}
	if !reflect.DeepEqual(seen, []string{"", PhaseReady, PhaseStopped}) {
		t.Fatalf("out of order: %v", seen)
	}
	if i.State().IMSReady {
		t.Fatal("stopped instance remains ready")
	}
}
