package runtimehost

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu"
	"github.com/iniwex5/vowifi-go/internal/ims"
	"github.com/iniwex5/vowifi-go/internal/ipsec3gpp"
	"github.com/iniwex5/vowifi-go/internal/netstack"
	"github.com/iniwex5/vowifi-go/runtimehost/eventhost"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	"go.uber.org/zap"
)

func connectSession(ctx context.Context, req StartRequest, inst *Instance) error {
	p := req.Prepared
	if p.EPDGAddr == "" {
		return swu.ErrEPDGAddressMissing
	}
	engineCfg, err := buildSWUConfig(req)
	if err != nil {
		return err
	}
	tunnel, err := swu.Dial(ctx, engineCfg)
	if err != nil {
		return fmt.Errorf("SWu: %w", err)
	}
	if err = inst.own(tunnel); err != nil {
		return err
	}
	inst.mu.Lock()
	inst.migrate = tunnel.UpdateAddresses
	inst.mu.Unlock()
	cfg := tunnel.Configuration()
	if len(cfg.Addresses) == 0 {
		return errors.New("SWu supplied no inner IP address")
	}
	inst.update(func(s *State) {
		s.Phase = PhaseTunnelReady
		s.TunnelReady = true
		s.LastReason = "child_sa_established"
	})
	protected := ipsec3gpp.NewEndpoint(tunnel.InnerPacketEndpoint())
	network, err := netstack.New(ctx, protected, netstack.Config{LocalAddresses: cfg.Addresses, DNS: cfg.DNS, MTU: userNetworkMTU})
	if err != nil {
		return err
	}
	if err = inst.own(network); err != nil {
		return err
	}
	pcscf := make([]string, 0, len(cfg.PCSCF))
	for _, ip := range cfg.PCSCF {
		pcscf = append(pcscf, ip.String())
	}
	if len(pcscf) == 0 {
		pcscf = []string{"pcscf." + p.IMSIdentity.Domain}
	}
	if p.IMSIdentity.IMPI == "" || p.IMSIdentity.IMPU == "" || p.IMSIdentity.Domain == "" {
		return errors.New("prepared IMS identity incomplete")
	}
	localIP := cfg.Addresses[0]
	security, err := newSecurityOffer()
	if err != nil {
		return err
	}
	imsCfg := ims.Config{PrivateIdentity: p.IMSIdentity.IMPI, PublicIdentity: p.IMSIdentity.IMPU, Realm: p.IMSIdentity.Domain, SMSC: p.Profile.SMSC, PCSCF: pcscf, Transport: "udp", SIM: selectedSIM{provider: req.SIM, preference: p.IMSIdentity.AKAAppPreference}, DialContext: network.DialContext, SecurityClient: &security}
	imsCfg.ListenPacket = network.ListenPacket
	imsCfg.ListenTCP = func(c context.Context, protocol, address string) (net.Listener, error) {
		if protocol != "tcp" && protocol != "tcp4" && protocol != "tcp6" {
			return nil, errors.New("invalid IMS listener transport")
		}
		local, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, err
		}
		return network.ListenTCP(c, net.TCPAddrFromAddrPort(local))
	}
	if err = applyIMSProfile(&imsCfg, p.EffectiveCarrier.Parameters, &security); err != nil {
		return err
	}
	applyIMSDeviceIdentity(&imsCfg, p.Profile.IMEI)
	// Detailed SIP diagnostics are opt-in. Leaving the callback nil at normal
	// log levels also avoids generating the redacted request/response strings.
	if log := Logger(); log.Core().Enabled(zap.DebugLevel) {
		imsCfg.OnRegistrationFailure = func(phase string, round int, request, response string) {
			log.Debug("IMS 注册被拒绝（脱敏 SIP 报文）", zap.String("device_id", req.DeviceID), zap.String("trace_id", req.TraceID), zap.String("phase", phase), zap.Int("round", round), zap.String("sip_request", request), zap.String("sip_response", response))
		}
	}
	imsCfg.InstallSecurity = func(ctx context.Context, a ims.SecurityAgreement) (ims.DialContextFunc, error) {
		host, _, err := net.SplitHostPort(a.RemoteAddress)
		if err != nil {
			return nil, err
		}
		remoteIP, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("IMS security requires selected numeric P-CSCF: %w", err)
		}
		var selectedLocal netip.Addr
		for _, ip := range cfg.Addresses {
			if ip.Is4() == remoteIP.Is4() {
				selectedLocal = ip
				break
			}
		}
		if !selectedLocal.IsValid() {
			return nil, errors.New("P-CSCF address family not assigned by SWu")
		}
		params := func(p ims.SecurityParameters) ipsec3gpp.SecurityParameters {
			return ipsec3gpp.SecurityParameters{Algorithm: p.Algorithm, Encryption: p.Encryption, SPIClient: p.SPIClient, SPIServer: p.SPIServer, PortClient: p.PortClient, PortServer: p.PortServer}
		}
		if err := protected.Install(ipsec3gpp.Config{LocalIP: selectedLocal, RemoteIP: remoteIP, Client: params(a.Client), Server: params(a.Server), CK: a.CK, IK: a.IK}); err != nil {
			return nil, err
		}
		return func(c context.Context, proto, address string) (net.Conn, error) {
			return network.DialContextWithLocalPort(c, proto, address, selectedLocal, a.Client.PortClient)
		}, nil
	}
	var imsStateMu sync.Mutex
	imsStarted := false

	imsCfg.OnState = func(ready bool, cause error) {
		imsStateMu.Lock()
		defer imsStateMu.Unlock()
		if imsStarted {
			reportIMSState(ctx, req, inst, ready, cause)
		}
	}

	imsCfg.OnSMS = func(sender, text string, at time.Time) {
		inst.Dispatch(ctx, eventhost.SMSReceived{IMSI: req.Profile.IMSI, DevID: req.DeviceID, Sender: sender, Content: text, Time: at})
	}
	imsCfg.OnStoredSMSWithID = func(id, sender, text string, at time.Time) {
		inst.Dispatch(ctx, eventhost.SMSReceived{EventID: id, IMSI: req.Profile.IMSI, Persisted: true, DevID: req.DeviceID, Sender: sender, Content: text, Time: at})
	}
	installDeliveryCallbacks(&imsCfg, req)
	svc, err := ims.New(imsCfg)
	if err != nil {
		return err
	}
	if err = inst.own(svc); err != nil {
		return err
	}
	inst.update(func(s *State) { s.Phase = PhaseIMSRegistering; s.LastReason = "ims_registering" })
	if err = svc.Start(ctx); err != nil {
		// A failed packet write can close the stack and cancel IMS first.
		// Report that original failure instead of only the resulting cancellation.
		if cause := network.Err(); cause != nil {
			return fmt.Errorf("IMS: %w (registration ended: %v)", cause, err)
		}
		return fmt.Errorf("IMS: %w", err)
	}
	inst.mu.Lock()
	inst.service = &messagingService{service: svc, store: req.DeliveryStore, dispatch: inst, deviceID: req.DeviceID, imsi: req.Profile.IMSI}
	inst.mu.Unlock()
	if err = registerVoice(ctx, req, inst, svc, network, localIP); err != nil {
		return err
	}
	imsStateMu.Lock()
	imsStarted = true
	if svc.Ready() {
		reportIMSState(ctx, req, inst, true, nil)
	} else {
		select {
		case <-svc.Done():
			imsStateMu.Unlock()
			if err := svc.Err(); err != nil {
				return err
			}
			return context.Canceled
		default:
			reportIMSState(ctx, req, inst, false, errors.Join(ims.ErrRecovering, svc.Err()))
		}
	}
	imsStateMu.Unlock()

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-tunnel.Done():
		case <-network.Done():
		}
		inst.update(func(s *State) {
			s.Phase = PhaseFailed
			s.TunnelReady = false
			s.IMSReady = false
			s.SMSReady = false
			s.LastErrorClass = "tunnel_disconnected"
			s.LastReason = "tunnel or inner network closed"
		})
		inst.cancel()
	}()
	return nil
}

func reportIMSState(ctx context.Context, req StartRequest, inst *Instance, ready bool, cause error) {
	if ctx.Err() != nil {
		return
	}
	if req.ShouldRun != nil && !req.ShouldRun() {
		inst.cancel()
		return
	}
	recovering := cause == nil || errors.Is(cause, ims.ErrRecovering)
	inst.update(func(state *State) {
		if ctx.Err() != nil || !state.TunnelReady {
			return
		}
		state.IMSReady, state.SMSReady = ready, ready
		if ready {
			state.Phase = PhaseReady
			state.LastReason = PhaseSMSReady
			state.LastError, state.LastErrorClass = "", ""
		} else if recovering {
			state.Phase = PhaseIMSRegistering
			state.LastReason = "ims_recovering"
			state.LastErrorClass = "ims_recovering"
			if cause != nil {
				state.LastError = cause.Error()
			}
		} else {
			state.Phase = PhaseFailed
			state.LastReason = "ims_disconnected"
			state.LastErrorClass = "ims_disconnected"
			state.LastError = cause.Error()
		}
	})
	if !ready && !recovering {
		inst.cancel()
	}
}

func toSWUProxy(p *ProxyConfig) *swu.ProxyConfig {
	if p == nil {
		return nil
	}
	return &swu.ProxyConfig{ID: p.ID, Type: p.Type, Addr: p.Addr, Address: p.Address, Username: p.Username, Password: p.Password, Enabled: p.Enabled}
}
func newSecurityOffer() (ims.SecurityParameters, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ims.SecurityParameters{}, err
	}
	a, c := binary.BigEndian.Uint32(b[:4]), binary.BigEndian.Uint32(b[4:8])
	if a < 256 {
		a += 256
	}
	if c < 256 {
		c += 256
	}
	if a == c {
		if c == ^uint32(0) {
			c = 256
		} else {
			c++
		}
	}
	port := uint16(20000) + binary.BigEndian.Uint16(b[8:10])%30000
	return ims.SecurityParameters{Algorithm: "hmac-sha-1-96", Encryption: "aes-cbc", SPIClient: a, SPIServer: c, PortClient: port, PortServer: port + 1}, nil
}

type messagingService struct {
	service  *ims.Service
	store    messaging.DeliveryStore
	dispatch eventhost.Dispatcher
	deviceID string
	imsi     string
}

func (s *messagingService) Subscription() messaging.Subscription {
	return messaging.Subscription{DeviceID: s.deviceID, IMSI: s.imsi}
}

func (s *messagingService) SendSMSWithOptions(ctx context.Context, to, text string, options messaging.SendOptions) (messaging.SendOutcome, error) {
	r, err := s.service.SendSMS(ctx, to, text, options.Encoding)
	out := messaging.SendOutcome{MessageID: r.MessageID, PartsTotal: r.PartsTotal, State: "pending", DeliveryState: "pending"}
	if err != nil {
		out.State = "failed"
		out.DeliveryState = "failed"
		if s.store != nil && r.MessageID != "" {
			if status, getErr := s.store.GetSMSDeliveryStatus(r.MessageID); getErr == nil && status != nil {
				out.PartsTotal = status.PartsTotal
				if _, reliable := s.store.(messaging.ReliabilityStore); reliable {
					out.State, out.DeliveryState = status.State, status.DeliveryState
				} else if status.State == "acked" {
					out.State = status.State
					out.DeliveryState = status.State
				} else if persistErr := s.store.UpdateSMSDeliveryState(r.MessageID, "failed", err.Error(), status.Acks, time.Now()); persistErr != nil {
					err = errors.Join(err, persistErr)
				}
			}
		}
		return out, err
	}
	if s.store != nil {
		if status, e := s.store.GetSMSDeliveryStatus(r.MessageID); e == nil && status != nil {
			out.PartsTotal = status.PartsTotal
			out.State = status.State
			out.DeliveryState = status.State
			if status.DeliveryState != "" {
				out.DeliveryState = status.DeliveryState
			}
		}
	}
	// RP-ACK and TP status reports retain their own state. SIP 202 alone is never delivered.
	if s.dispatch != nil {
		s.dispatch.Dispatch(ctx, eventhost.SMSSent{IMSI: s.imsi, DevID: s.deviceID, TargetURI: to, Content: text, TotalParts: r.PartsTotal, Time: time.Now()})
	}
	return out, nil
}
func (s *messagingService) SendUSSD(ctx context.Context, command string) (*messaging.USSDResult, error) {
	r, err := s.service.SendUSSD(ctx, command)
	if err != nil {
		return nil, err
	}
	return publicUSSD(r), nil
}
func (s *messagingService) ContinueUSSD(ctx context.Context, id, input string) (*messaging.USSDResult, error) {
	r, err := s.service.ContinueUSSD(ctx, id, input)
	if err != nil {
		return nil, err
	}
	return publicUSSD(r), nil
}
func (s *messagingService) CancelUSSD(ctx context.Context, id string) error {
	return s.service.CancelUSSD(ctx, id)
}
func publicUSSD(r ims.USSDResult) *messaging.USSDResult {
	status := 0
	if !r.Done {
		status = 1
	}
	return &messaging.USSDResult{Status: status, SessionID: r.SessionID, Text: r.Text, Done: r.Done}
}

func installDeliveryCallbacks(cfg *ims.Config, req StartRequest) {
	store := req.DeliveryStore
	if store == nil {
		return
	}
	cfg.OnSMSStoreError = func(err error) { Logger().Warn("VoWiFi SMS recovery incomplete", zap.Error(err)) }
	cfg.SMSOwner = messaging.Subscription{DeviceID: req.DeviceID, IMSI: req.Profile.IMSI}
	cfg.ReliabilityStore, _ = store.(messaging.ReliabilityStore)
	cfg.InboundStore, _ = store.(messaging.InboundStore)
	var deliveryMu sync.Mutex
	cfg.OnSend = func(id, to, text string, total int) error {
		return store.CreateSMSDelivery(id, req.Profile.IMSI, req.DeviceID, to, text, total, time.Now())
	}
	cfg.OnPart = func(id string, part ims.SentPart) error {
		if cfg.ReliabilityStore != nil {
			return cfg.ReliabilityStore.RecordSMSSIPResult(id, part.PartNo, part.SIPCode, part.State, time.Now())
		}
		if part.State == "accepted" {
			return nil
		}
		deliveryMu.Lock()
		defer deliveryMu.Unlock()
		state := "pending"
		if part.State == "failed" {
			state = "failed"
			if current, err := store.GetSMSDeliveryStatus(id); err == nil && current != nil {
				for _, saved := range current.Parts {
					if saved.PartNo == part.PartNo && saved.CallID == part.CallID && saved.State == "acked" {
						return nil
					}
				}
			}
		}
		at := time.Now()
		if err := store.UpsertSMSDeliveryPart(id, part.PartNo, part.CallID, part.RPMR, state, at); err != nil {
			return err
		}
		if state == "failed" {
			return store.RecomputeSMSDelivery(id, at)
		}
		return nil
	}
	cfg.OnReport = func(r ims.Report) {
		deliveryMu.Lock()
		defer deliveryMu.Unlock()
		state := "acked"
		if r.State == "failed" {
			state = "failed"
		}
		match, err := store.MarkSMSDeliveryPartReport(r.InReplyTo, r.CallID, req.DeviceID, r.RPMR, state, r.SIPCode, r.RPCause, r.Error, r.At)
		if err == nil {
			err = store.RecomputeSMSDelivery(match.MessageID, r.At)
		}
		if err != nil {
			Logger().Warn("VoWiFi SMS report persistence failed", zap.Error(err))
		}
	}
}

// The host hook supplies observed public IPs, which may be NAT addresses that
// cannot be bound locally. Rebind through the OS routing table instead.
func (i *Instance) TriggerMOBIKE(oldIP, newIP string) error {
	if net.ParseIP(strings.TrimSpace(newIP)) == nil {
		return errors.New("invalid MOBIKE address observation")
	}
	i.mu.RLock()
	migrate, ctx, stopped := i.migrate, i.ctx, i.stopped
	i.mu.RUnlock()
	if stopped || migrate == nil || ctx == nil {
		return errors.New("MOBIKE requires an active tunnel")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return migrate(ctx, "")
}
