package runtimehost

import (
	"context"
	"reflect"
	"testing"
	"time"
)

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
