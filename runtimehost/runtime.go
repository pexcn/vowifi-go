package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/runtimehost/carrier"
	"github.com/iniwex5/vowifi-go/runtimehost/eventhost"
	"github.com/iniwex5/vowifi-go/runtimehost/identity"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
)

const PhaseStopped = "stopped"

// Instance owns only resources acquired for this session. The modem and shared
// SIM adapter remain owned by the host; stopping a session must not close them.
type Instance struct {
	mu            sync.RWMutex
	cleanupMu     sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	state         State
	service       Service
	resources     []io.Closer
	observers     []Observer
	notifications []notification
	dispatching   bool
	stopped       bool
	deliveryStore messaging.DeliveryStore
	dispatch      eventhost.Dispatcher
	notifier      func(string)
	smsNotifier   func(string, string, string, time.Time)
}

type notification struct {
	state     State
	observers []Observer
	deliver   func()
}

// Queue transitions under the state lock, then drain without that lock. This
// preserves event order while allowing an observer to call State or Stop.
func (i *Instance) enqueueLocked(state State, observers []Observer) bool {
	i.notifications = append(i.notifications, notification{state: state, observers: observers})
	if i.dispatching {
		return false
	}
	i.dispatching = true
	return true
}
func (i *Instance) drainNotifications() {
	for {
		i.mu.Lock()
		if len(i.notifications) == 0 {
			i.dispatching = false
			i.mu.Unlock()
			return
		}
		event := i.notifications[0]
		i.notifications[0] = notification{}
		i.notifications = i.notifications[1:]
		i.mu.Unlock()
		if event.deliver != nil {
			event.deliver()
			continue
		}
		for _, observer := range event.observers {
			observer.OnRuntimeEvent(context.Background(), Event{State: event.state})
		}
	}
}

// startup is private so lifecycle tests can exercise the production ownership
// rules without contacting a carrier or weakening the public network defaults.
type startup struct {
	connect func(context.Context, StartRequest, *Instance) error
}

func Start(ctx context.Context, req StartRequest) (*Instance, error) {
	return start(ctx, req, startup{connect: connectSession})
}

func start(ctx context.Context, req StartRequest, stages startup) (*Instance, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(req.DeviceID) == "" {
		return nil, errors.New("runtimehost: missing device ID")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.ShouldRun != nil && !req.ShouldRun() {
		return nil, context.Canceled
	}
	if req.SIM == nil {
		return nil, errors.New("runtimehost: missing SIM AKA provider")
	}
	if req.Dataplane.Mode == "" {
		req.Dataplane.Mode = "userspace"
	}
	if req.Dataplane.Mode != "userspace" {
		return nil, fmt.Errorf("runtimehost: unsupported dataplane %q", req.Dataplane.Mode)
	}
	if req.TraceID == "" {
		req.TraceID = TraceIDFromContext(ctx)
	}
	if req.TraceID == "" {
		req.TraceID = NewTraceID()
	}
	if req.Prepared == nil {
		prepared, err := identity.PrepareStart(identity.PrepareStartInput{DeviceID: req.DeviceID, Profile: req.Profile, Access: req.Access})
		if err != nil {
			return nil, err
		}
		req.Prepared = &prepared
	}
	// Copy the caller-selected plan; do not re-read SIM or replace its identities.
	prepared := *req.Prepared
	req.Prepared = &prepared
	req.Profile = prepared.Profile
	if carrier.IsVoWiFiBlockedMCC(req.Profile.MCC) {
		return nil, carrier.NewVoWiFiBlockedMCCError(req.Profile.MCC)
	}
	if req.BeforeStart != nil {
		if err := req.BeforeStart(ctx, SessionConfig{DeviceID: req.DeviceID, TraceID: req.TraceID, DataplaneMode: req.Dataplane.Mode, Proxy: req.Proxy}); err != nil {
			return nil, err
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	now := time.Now()
	i := &Instance{ctx: runCtx, cancel: cancel, deliveryStore: req.DeliveryStore, dispatch: req.Dispatch, state: State{DeviceID: req.DeviceID, TraceID: req.TraceID, DataplaneMode: req.Dataplane.Mode, NetworkMode: req.NetworkMode, StartedAt: now, UpdatedAt: now}}
	if req.Access != nil && req.Access.modem != nil {
		i.state.RegStatus, i.state.RegStatusText = req.Access.modem.GetRegStatus()
	}
	i.update(func(s *State) { s.Phase = PhaseSIMReady; s.SIMReady = true; s.LastReason = "sim_provider_available" })
	// Epoch changes can happen during DNS, EAP, or REGISTER. Cancel those waits,
	// rather than waiting for a late success and publishing an obsolete runtime.
	if req.ShouldRun != nil {
		go func() {
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-ticker.C:
					if !req.ShouldRun() {
						cancel()
						return
					}
				}
			}
		}()
	}
	i.update(func(s *State) { s.Phase = PhaseAccessReady; s.AccessReady = true; s.LastReason = "access_ready" })
	i.update(func(s *State) { s.Phase = PhaseTunnelConnecting; s.LastReason = "epdg_connecting" })
	err := stages.connect(runCtx, req, i)
	if err == nil {
		err = runCtx.Err()
	}
	if err == nil && req.ShouldRun != nil && !req.ShouldRun() {
		err = context.Canceled
	}
	if err != nil {
		cancel()
		cleanupErr := i.closeResources(context.Background())
		i.mu.Lock()
		i.service = nil
		i.mu.Unlock()
		i.update(func(s *State) {
			s.Phase = PhaseFailed
			s.TunnelReady = false
			s.IMSReady = false
			s.SMSReady = false
			s.LastErrorClass = classifyStartError(err)
			s.LastError = err.Error()
			s.LastReason = err.Error()
		})
		return i, errors.Join(err, cleanupErr)
	}
	go func() { <-runCtx.Done(); _ = i.Stop(context.Background()) }()
	return i, nil
}

func classifyStartError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "protocol_or_transport_failed"
	}
}

func (i *Instance) own(resource io.Closer) error {
	if resource == nil {
		return errors.New("runtimehost: nil session resource")
	}
	i.mu.Lock()
	if !i.stopped && i.ctx.Err() == nil {
		i.resources = append(i.resources, resource)
		i.mu.Unlock()
		return nil
	}
	i.mu.Unlock()
	err := resource.Close()
	if err != nil {
		i.mu.Lock()
		i.resources = append(i.resources, resource)
		i.mu.Unlock()
	}
	return errors.Join(context.Canceled, err)
}

func (i *Instance) update(change func(*State)) {
	if i == nil {
		return
	}
	i.mu.Lock()
	if i.stopped {
		i.mu.Unlock()
		return
	}
	change(&i.state)
	i.state.UpdatedAt = time.Now()
	state := i.state
	observers := append([]Observer(nil), i.observers...)
	drain := i.enqueueLocked(state, observers)
	i.mu.Unlock()
	if drain {
		go i.drainNotifications()
	}
}

func (i *Instance) AddObserver(observer Observer) {
	if i == nil || observer == nil {
		return
	}
	i.mu.Lock()
	i.observers = append(i.observers, observer)
	state := i.state
	drain := i.enqueueLocked(state, []Observer{observer})
	i.mu.Unlock()
	if drain {
		i.drainNotifications()
	}
}

func (i *Instance) closeResources(ctx context.Context) error {
	i.cleanupMu.Lock()
	defer i.cleanupMu.Unlock()
	i.mu.Lock()
	resources := append([]io.Closer(nil), i.resources...)
	i.resources = nil
	i.mu.Unlock()
	var failed []io.Closer
	var errs []error
	for j := len(resources) - 1; j >= 0; j-- {
		if err := ctx.Err(); err != nil {
			failed = append(append([]io.Closer(nil), resources[:j+1]...), failed...)
			errs = append(errs, err)
			break
		}
		if err := resources[j].Close(); err != nil {
			failed = append([]io.Closer{resources[j]}, failed...)
			errs = append(errs, err)
		}
	}
	// A failed close retains ownership for the caller's next Stop attempt.
	i.mu.Lock()
	i.resources = append(failed, i.resources...)
	i.mu.Unlock()
	return errors.Join(errs...)
}

func (i *Instance) Stop(ctx context.Context) error {
	if i == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.mu.Lock()
	wasStopped := i.stopped
	i.stopped = true
	if i.cancel != nil {
		i.cancel()
	}
	i.service = nil
	i.state.Phase = PhaseStopped
	i.state.TunnelReady = false
	i.state.IMSReady = false
	i.state.SMSReady = false
	i.state.UpdatedAt = time.Now()
	state := i.state
	observers := append([]Observer(nil), i.observers...)
	drain := false
	if !wasStopped {
		drain = i.enqueueLocked(state, observers)
	}
	i.mu.Unlock()
	err := i.closeResources(ctx)
	if drain {
		go i.drainNotifications()
	}
	return err
}

func (i *Instance) State() State {
	if i == nil {
		return State{}
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.state
}
func (i *Instance) Service() Service {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.service
}
func (i *Instance) Status() string {
	s := i.State()
	if s.Phase == "" {
		return "VoWiFi: STOPPED"
	}
	return "VoWiFi: " + s.Phase
}
func (i *Instance) Obs() map[string]interface{} {
	s := i.State()
	return map[string]interface{}{"phase": s.Phase, "device_id": s.DeviceID, "network_mode": s.NetworkMode, "tunnel_ready": s.TunnelReady, "ims_ready": s.IMSReady, "sms_ready": s.SMSReady, "last_error": s.LastError}
}
func (i *Instance) GetSMSDeliveryStatus(messageID string) (*messaging.DeliveryStatus, error) {
	if i == nil || i.deliveryStore == nil {
		return nil, messaging.ErrDeliveryNotFound
	}
	return i.deliveryStore.GetSMSDeliveryStatus(messageID)
}

func (i *Instance) SetNotifier(fn func(string)) {
	if i == nil {
		return
	}
	i.mu.Lock()
	i.notifier = fn
	i.mu.Unlock()
}
func (i *Instance) SetSMSNotifier(fn func(string, string, string, time.Time)) {
	if i == nil {
		return
	}
	i.mu.Lock()
	i.smsNotifier = fn
	i.mu.Unlock()
}
func (i *Instance) Dispatch(ctx context.Context, event eventhost.Event) {
	if i == nil || event == nil {
		return
	}
	i.mu.RLock()
	dispatcher, notify, smsNotify := i.dispatch, i.notifier, i.smsNotifier
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return
	}
	deliver := func() {
		if dispatcher != nil {
			dispatcher.Dispatch(ctx, event)
			return
		}
		switch e := event.(type) {
		case eventhost.SMSReceived:
			if smsNotify != nil {
				smsNotify(e.DevID, e.Sender, e.Content, e.Time)
			}
		case eventhost.LogNotify:
			if notify != nil {
				notify(e.Message)
			}
		}
	}
	i.mu.Lock()
	i.notifications = append(i.notifications, notification{deliver: deliver})
	drain := !i.dispatching
	i.dispatching = true
	i.mu.Unlock()
	if drain {
		go i.drainNotifications()
	}
}
