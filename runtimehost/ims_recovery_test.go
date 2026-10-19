package runtimehost

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/internal/ims"
	"github.com/iniwex5/vowifi-go/runtimehost/carrier"
)

func TestIMSRecoveryPreservesTunnelAndRestoresSMSReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	i := &Instance{ctx: ctx, cancel: cancel}
	i.update(func(s *State) {
		s.Phase, s.LastReason = PhaseReady, PhaseSMSReady
		s.TunnelReady, s.IMSReady, s.SMSReady = true, true, true
	})
	req := testRequest()
	reportIMSState(ctx, req, i, false, errors.Join(ims.ErrRecovering, errors.New("REGISTER 503")))
	s := i.State()
	if ctx.Err() != nil || !s.TunnelReady || s.IMSReady || s.SMSReady || s.Phase != PhaseIMSRegistering || s.LastErrorClass != "ims_recovering" {
		t.Fatalf("recovery lost tunnel or retained readiness: %+v, %v", s, ctx.Err())
	}
	reportIMSState(ctx, req, i, true, nil)
	s = i.State()
	if !s.TunnelReady || !s.IMSReady || !s.SMSReady || s.Phase != PhaseReady || s.LastReason != PhaseSMSReady || s.LastError != "" || s.LastErrorClass != "" {
		t.Fatalf("registration did not restore sms_ready: %+v", s)
	}
	reportIMSState(ctx, req, i, false, errors.New("invalid AKA challenge"))
	if ctx.Err() == nil || i.State().Phase != PhaseFailed {
		t.Fatal("authentication failure did not terminate session")
	}
	before := i.State()
	reportIMSState(ctx, req, i, true, nil)
	if after := i.State(); after != before {
		t.Fatalf("late registration revived cancelled session: %+v", after)
	}
}

func TestIMSRecoveryRejectsStaleEpochAndLostTunnel(t *testing.T) {
	for _, stale := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		i := &Instance{ctx: ctx, cancel: cancel}
		i.update(func(s *State) { s.Phase = PhaseFailed; s.TunnelReady = stale })
		req := testRequest()
		req.ShouldRun = func() bool { return !stale }
		reportIMSState(ctx, req, i, true, nil)
		if s := i.State(); s.IMSReady || s.SMSReady || s.Phase != PhaseFailed {
			t.Fatalf("late callback revived unusable session: %+v", s)
		}
		if stale && ctx.Err() == nil {
			t.Error("stale epoch was not cancelled")
		}
		cancel()
	}
}

func TestIMSProfileCarriesRegistrarRetryPolicy(t *testing.T) {
	c := carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{MCC: "001", MNC: "01"})
	c.Parameters.IMSRegisterTemplate.RegisterPolicy.TemporaryStatusCodes = []int{480, 503}
	c.Parameters.IMSRegisterTemplate.RegisterPolicy.ForbiddenStatusCodes = []int{403, 488}
	c.Parameters.IMSRegisterTemplate.RegisterPolicy.TemporaryRetrySeconds = 17
	cfg := ims.Config{}
	security := ims.SecurityParameters{SPIClient: 1001, SPIServer: 1002, PortClient: 40000, PortServer: 40001}
	if err := applyIMSProfile(&cfg, c.Parameters, &security); err != nil {
		t.Fatal(err)
	}
	if cfg.RecoveryInitial != 17*time.Second || len(cfg.TemporaryStatusCodes) != 2 || cfg.TemporaryStatusCodes[0] != 480 || len(cfg.ForbiddenStatusCodes) != 2 || cfg.ForbiddenStatusCodes[1] != 488 {
		t.Fatalf("carrier recovery policy lost: %+v", cfg)
	}
	c.Parameters.IMSRegisterTemplate.RegisterPolicy.TemporaryStatusCodes[0] = 500
	if cfg.TemporaryStatusCodes[0] != 480 {
		t.Fatal("carrier policy aliases active configuration")
	}
}
