package runtimehost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/iniwex5/vowifi-go/engine/eap"
	"go.uber.org/zap"
	"sync/atomic"

	"time"

	swusim "github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/runtimehost/eventhost"
	"github.com/iniwex5/vowifi-go/runtimehost/identity"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	"github.com/iniwex5/vowifi-go/runtimehost/voicehost"
)

const (
	StartModeMain         = "main"
	PhaseSIMReady         = "sim_ready"
	PhaseAccessReady      = "access_ready"
	PhaseTunnelConnecting = "tunnel_connecting"
	PhaseTunnelReady      = "tunnel_ready"
	PhaseIMSRegistering   = "ims_registering"
	PhaseIMSReady         = "ims_ready"
	PhaseSMSReady         = "sms_ready"
	PhaseReady            = "ready"
	PhaseFailed           = "failed"
)

var ErrAPDUBusy = errors.New("apdu busy")

type Modem interface {
	DeviceID() string
	IsHealthy() bool
	IsSimInserted() bool
	QuerySIMInserted() (bool, error)
	GetRegStatus() (int, string)
	GetNetworkMode() string
	ExecuteATSilent(string, time.Duration) (string, error)
	OpenLogicalChannel(string) (int, error)
	CloseLogicalChannel(int) error
	TransmitAPDU(int, string) (string, error)
	Stop()
}

type modemISIMReader interface {
	GetISIMIdentity() (identity.Identity, error)
}

type LogicalChannelAIDResolver interface {
	ResolveLogicalChannelAID(app string, fallbackAID string) (string, string, error)
}

type ModemAccessAdapter struct {
	modem Modem
}

func NewModemAccessAdapter(modem Modem) *ModemAccessAdapter {
	return &ModemAccessAdapter{modem: modem}
}

func (a *ModemAccessAdapter) Modem() Modem {
	if a == nil {
		return nil
	}
	return a.modem
}

func (a *ModemAccessAdapter) GetISIMIdentity() (identity.Identity, error) {
	if a == nil || a.modem == nil {
		return identity.Identity{}, fmt.Errorf("modem access unavailable")
	}
	if r, ok := a.modem.(modemISIMReader); ok {
		return r.GetISIMIdentity()
	}
	return identity.Identity{}, fmt.Errorf("ISIM identity reader unavailable")
}

func (a *ModemAccessAdapter) ExecuteATSilent(cmd string, timeout time.Duration) (string, error) {
	if a == nil || a.modem == nil {
		return "", fmt.Errorf("modem access unavailable")
	}
	return a.modem.ExecuteATSilent(cmd, timeout)
}

func (a *ModemAccessAdapter) OpenLogicalChannel(aid string) (int, error) {
	if a == nil || a.modem == nil {
		return 0, fmt.Errorf("modem access unavailable")
	}
	return a.modem.OpenLogicalChannel(aid)
}

func (a *ModemAccessAdapter) CloseLogicalChannel(ch int) error {
	if a == nil || a.modem == nil {
		return fmt.Errorf("modem access unavailable")
	}
	return a.modem.CloseLogicalChannel(ch)
}

func (a *ModemAccessAdapter) TransmitAPDU(ch int, apdu string) (string, error) {
	if a == nil || a.modem == nil {
		return "", fmt.Errorf("modem access unavailable")
	}
	return a.modem.TransmitAPDU(ch, apdu)
}

type SIMAdapter interface {
	GetIMSI() (string, error)
	CalculateAKA(rand, autn []byte) (swusim.AKAResult, error)
	Close() error
}

type readerSIMAdapter struct{ provider swusim.AKAProvider }

func NewReaderSIMAdapter(provider swusim.AKAProvider) SIMAdapter {
	return readerSIMAdapter{provider: provider}
}
func (a readerSIMAdapter) GetIMSI() (string, error) {
	if a.provider == nil {
		return "", fmt.Errorf("missing SIM provider")
	}
	if p, ok := a.provider.(swusim.IMSIProvider); ok {
		return p.GetIMSI()
	}
	return "", fmt.Errorf("SIM provider does not expose IMSI")
}
func (a readerSIMAdapter) CalculateAKA(rand, autn []byte) (swusim.AKAResult, error) {
	if a.provider == nil {
		return swusim.AKAResult{}, fmt.Errorf("missing SIM provider")
	}
	return a.provider.CalculateAKA(rand, autn)
}

// Preserve application selection through the host adapter; strict ISIM must
// never degrade into the provider's default USIM operation.
func (a readerSIMAdapter) CalculateAKAWithPreference(rand, autn []byte, preference string) (swusim.AKAResult, error) {
	if a.provider == nil {
		return swusim.AKAResult{}, errors.New("missing SIM provider")
	}
	return calculateWithPreference(a.provider, rand, autn, preference)
}
func (a readerSIMAdapter) CalculateISIMAKA(rand, autn []byte) (swusim.AKAResult, error) {
	return a.CalculateAKAWithPreference(rand, autn, "isim_strict")
}

func calculateWithPreference(provider swusim.AKAProvider, rand, autn []byte, preference string) (swusim.AKAResult, error) {
	switch preference {
	case "", "usim", "auto", "isim", "isim_strict":
	default:
		return swusim.AKAResult{}, fmt.Errorf("unknown AKA application preference %q", preference)
	}
	if p, ok := provider.(swusim.AKAWithPreferenceProvider); ok {
		return p.CalculateAKAWithPreference(rand, autn, preference)
	}
	if preference == "isim_strict" {
		if p, ok := provider.(swusim.ISIMAKAProvider); ok {
			return p.CalculateISIMAKA(rand, autn)
		}
		return swusim.AKAResult{}, errors.New("strict ISIM provider unavailable")
	}
	if preference == "auto" || preference == "isim" {
		if p, ok := provider.(swusim.ISIMAKAProvider); ok {
			result, err := p.CalculateISIMAKA(rand, autn)
			if err == nil || len(result.AUTS) > 0 {
				return result, err
			}
		}
	}
	return provider.CalculateAKA(rand, autn)
}

type selectedSIM struct {
	provider   swusim.AKAProvider
	preference string
}

func (p selectedSIM) CalculateAKA(rand, autn []byte) (swusim.AKAResult, error) {
	return calculateWithPreference(p.provider, rand, autn, p.preference)
}
func (a readerSIMAdapter) Close() error {
	if a.provider == nil {
		return nil
	}
	if p, ok := a.provider.(swusim.CloseProvider); ok {
		return p.Close()
	}
	return nil
}

type DataplanePolicy struct{ Mode string }

type ProxyConfig struct {
	ID       string
	Type     string
	Addr     string
	Address  string
	Username string
	Password string
	Enabled  bool
}

type SessionConfig struct {
	DeviceID      string
	TraceID       string
	DataplaneMode string
	Proxy         *ProxyConfig
}

type State struct {
	Phase          string
	DeviceID       string
	TraceID        string
	DataplaneMode  string
	NetworkMode    string
	SIMReady       bool
	AccessReady    bool
	TunnelReady    bool
	IMSReady       bool
	SMSReady       bool
	RegStatus      int
	RegStatusText  string
	LastErrorClass string
	LastError      string
	LastReason     string
	StartedAt      time.Time
	UpdatedAt      time.Time
}

type Event struct{ State State }

var runtimeLogger atomic.Pointer[zap.Logger]

type traceIDContextKey struct{}

func SetLogger(logger *zap.Logger) { runtimeLogger.Store(logger) }
func Logger() *zap.Logger {
	if l := runtimeLogger.Load(); l != nil {
		return l
	}
	return zap.NewNop()
}
func NewTraceID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fmt.Sprintf("vowifi-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(id[:])
}
func WithTraceID(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, traceIDContextKey{}, id)
}
func TraceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(traceIDContextKey{}).(string)
	return v
}

type Observer interface{ OnRuntimeEvent(context.Context, Event) }

type ObserverFunc func(context.Context, Event)

func (f ObserverFunc) OnRuntimeEvent(ctx context.Context, ev Event) { f(ctx, ev) }

type Service interface {
	SendSMSWithOptions(context.Context, string, string, messaging.SendOptions) (messaging.SendOutcome, error)
	SendUSSD(context.Context, string) (*messaging.USSDResult, error)
	ContinueUSSD(context.Context, string, string) (*messaging.USSDResult, error)
	CancelUSSD(context.Context, string) error
}

type StartRequest struct {
	AuthenticationContext *eap.ReauthContext `json:"-"`
	Mode                  string
	DeviceID              string
	TraceID               string
	Profile               identity.Profile
	Prepared              *identity.PreparedSession
	NetworkMode           string
	VoiceGateway          *voicehost.Gateway
	SIM                   SIMAdapter
	Access                *ModemAccessAdapter
	Dataplane             DataplanePolicy
	Proxy                 *ProxyConfig
	DeliveryStore         messaging.DeliveryStore
	Dispatch              eventhost.Dispatcher
	BeforeStart           func(context.Context, SessionConfig) error
	ShouldRun             func() bool
}
