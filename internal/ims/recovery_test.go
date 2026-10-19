package ims

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func recoveryChallenge(r *bufio.Reader, c net.Conn, initial *message) (*message, error) {
	challenge := response(initial, 401, "Unauthorized")
	challenge.set("www-authenticate", `Digest realm="fresh.ims.test", nonce="`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`", algorithm=AKAv1-MD5, qop="auth"`)
	if err := sendPeer(c, challenge); err != nil {
		return nil, err
	}
	auth, err := readMessage(r)
	if err == nil && (!strings.Contains(auth.get("authorization"), `realm="fresh.ims.test"`) || strings.Contains(auth.get("authorization"), `response=""`)) {
		err = errors.New("missing fresh AKA digest")
	}
	return auth, err
}

func awaitIMSState(t *testing.T, states <-chan bool, want bool) {
	t.Helper()
	select {
	case got := <-states:
		if got != want {
			t.Fatalf("readiness = %v, want %v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("missing readiness %v", want)
	}
}

func TestRefreshFailureSwitchesRegistrarAndAuthenticatesAgain(t *testing.T) {
	oldID := make(chan string, 1)
	release := make(chan struct{})
	states := make(chan bool, 16)
	hints := make(chan time.Duration, 4)
	first := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		auth, err := peerRegister(r, c)
		if err != nil {
			return err
		}
		oldID <- auth.get("call-id")
		ok := response(auth, 200, "OK")
		ok.set("service-route", "<sip:old-route.ims.test;lr>")
		if err = sendPeer(c, ok); err != nil {
			return err
		}
		refresh, err := readMessage(r)
		if err != nil {
			return err
		}
		if refresh.method() != "REGISTER" || !strings.Contains(refresh.get("authorization"), `qop=auth`) {
			return errors.New("refresh lost authentication")
		}
		failed := response(refresh, 503, "Unavailable")
		failed.set("retry-after", "30 (maintenance);duration=60")
		// Exercise a final response followed immediately by EOF.
		return sendPeer(c, failed)
	})
	second := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		initial, err := readMessage(r)
		if err != nil {
			return err
		}
		if initial.method() != "REGISTER" || initial.get("route") != "" || initial.get("security-verify") != "" || !strings.Contains(initial.get("authorization"), `nonce=""`) || initial.get("call-id") == <-oldID {
			return errors.New("new registrar inherited old registration state")
		}
		auth, err := recoveryChallenge(r, c, initial)
		if err != nil {
			return err
		}
		<-release
		ok := response(auth, 200, "OK")
		ok.set("expires", "3600")
		if err = sendPeer(c, ok); err != nil {
			return err
		}
		_, _ = readMessage(r)
		return nil
	})
	first.PCSCF = append(first.PCSCF, second.PCSCF...)
	first.Expires = 100 * time.Millisecond
	first.RecoveryInitial = 10 * time.Millisecond
	first.OnState = func(ready bool, cause error) {
		var rejection *registrationError
		if errors.As(cause, &rejection) {
			hints <- rejection.retryAfter
		}
		states <- ready
	}
	s, err := New(first)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	if err = s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	oldConn, oldGeneration := s.conn, s.generation
	s.mu.Unlock()
	awaitIMSState(t, states, true)
	awaitIMSState(t, states, false)
	if s.Ready() {
		t.Fatal("recovering service is ready")
	}
	if _, err = s.SendSMS(context.Background(), "10086", "do not send", "auto"); !errors.Is(err, ErrNotReady) {
		t.Fatalf("SMS while recovering: %v", err)
	}
	close(release)
	deadline := time.After(2 * time.Second)
	for !s.Ready() {
		select {
		case <-states:
		case <-deadline:
			t.Fatal("registrar failover timed out")
		}
	}
	select {
	case delay := <-hints:
		if delay != 30*time.Second {
			t.Fatalf("lost final Retry-After: %v", delay)
		}
	default:
		t.Fatal("EOF discarded final rejection")
	}
	s.transportFailure(oldConn, oldGeneration, errors.New("late old-flow error"))
	if !s.Ready() || s.Err() != nil {
		t.Fatalf("stale flow destroyed recovery: %v", s.Err())
	}
	select {
	case <-s.Done():
		t.Fatal("IMS recovery terminated the service")
	default:
	}
}

func TestDisconnectDoesNotReplaySMSOnReplacementFlow(t *testing.T) {
	replayed := make(chan struct{}, 1)
	first := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		auth, err := peerRegister(r, c)
		if err != nil {
			return err
		}
		if err = sendPeer(c, response(auth, 200, "OK")); err != nil {
			return err
		}
		m, err := readMessage(r)
		if err != nil {
			return err
		}
		if m.method() != "MESSAGE" {
			return errors.New("expected in-flight SMS")
		}
		return nil // EOF after receiving the SMS; its network outcome is unknown.
	})
	states := make(chan bool, 16)
	second := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		auth, err := peerRegister(r, c)
		if err != nil {
			return err
		}
		if err = sendPeer(c, response(auth, 200, "OK")); err != nil {
			return err
		}
		for {
			m, err := readMessage(r)
			if err != nil {
				return nil
			}
			if m.method() == "MESSAGE" {
				replayed <- struct{}{}
				return errors.New("SMS replayed")
			}
		}
	})
	first.PCSCF = append(first.PCSCF, second.PCSCF...)
	first.OnState = func(ready bool, _ error) { states <- ready }
	s, err := New(first)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitIMSState(t, states, true)
	if _, err = s.SendSMS(context.Background(), "10086", "one attempt", "auto"); err == nil {
		t.Fatal("unacknowledged SMS reported success")
	}
	deadline := time.After(2 * time.Second)
	for !s.Ready() {
		select {
		case <-states:
		case <-deadline:
			t.Fatal("no recovery after disconnect")
		}
	}
	select {
	case <-replayed:
		t.Fatal("SMS was replayed")
	case <-time.After(30 * time.Millisecond):
	}
}

func TestRegistrarRetryPolicyAndExpiry(t *testing.T) {
	s := &Service{cfg: Config{RecoveryInitial: time.Second, RecoveryMax: 4 * time.Second, TemporaryStatusCodes: []int{503, 480}, ForbiddenStatusCodes: []int{403}}}
	for _, tc := range []struct {
		status, failures int
		retry, want      time.Duration
		rotate           bool
	}{
		{503, 1, 0, time.Second, true}, {503, 5, 0, time.Second, true},
		{503, 2, 20 * time.Second, 20 * time.Second, true}, {480, 1, 0, time.Second, true},
		{403, 1, 0, 5 * time.Minute, false}, {403, 1, time.Hour, time.Hour, false},
		{404, 1, 0, 10 * time.Minute, false},
	} {
		delay, rotate := s.recoveryDelay(&registrationError{status: tc.status, retryAfter: tc.retry}, tc.failures)
		if delay != tc.want || rotate != tc.rotate {
			t.Errorf("%+v: delay=%v rotate=%v", tc, delay, rotate)
		}
	}
	for value, want := range map[string]time.Duration{"": 0, "-1": 0, "4294967296": 0, "1 (busy);duration=5": time.Second, "12;duration=5": 12 * time.Second} {
		if got := retryAfterValue(value); got != want {
			t.Errorf("Retry-After %q: %v", value, got)
		}
	}
	for failures, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 32: 4 * time.Second} {
		if got, rotate := s.recoveryDelay(&flowError{net.ErrClosed}, failures); got != want || !rotate {
			t.Errorf("transport retry %d: delay=%v rotate=%v", failures, got, rotate)
		}
	}
	for _, tc := range []struct {
		global, contacts string
		want             time.Duration
		fail             bool
	}{
		{"", "", time.Hour, false}, {"120", "", 120 * time.Second, false},
		{"120", "<sip:other@host>;expires=1, <sip:me@host>;expires=60", time.Minute, false},
		{"120", "<sip:me@host>;expires=0", 0, true}, {"0", "", 0, true},
	} {
		r := &message{Headers: map[string][]string{}}
		r.set("expires", tc.global)
		r.set("contact", tc.contacts)
		got, err := registrationExpiry(r, "<sip:me@host>", time.Hour)
		if (err != nil) != tc.fail || got != tc.want {
			t.Errorf("expiry %+v: %v %v", tc, got, err)
		}
	}
}

func TestRetryAfterWaitsOnLiveFlowAndCancellationStopsRecovery(t *testing.T) {
	for _, status := range []int{503, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			rejected := make(chan time.Time, 1)
			cfg := configPeer(t, func(c net.Conn) error {
				r := bufio.NewReader(c)
				auth, err := peerRegister(r, c)
				if err != nil {
					return err
				}
				if err = sendPeer(c, response(auth, 200, "OK")); err != nil {
					return err
				}
				m, err := readMessage(r)
				if err != nil {
					return err
				}
				fail := response(m, status, "Unavailable")
				fail.set("retry-after", "1")
				if err = sendPeer(c, fail); err != nil {
					return err
				}
				rejected <- time.Now()
				next, err := readMessage(r)
				if status == 403 {
					if err == nil {
						return errors.New("forbidden cooldown ignored")
					}
					return nil
				}
				if err != nil {
					return err
				}
				if time.Since(<-rejected) < 950*time.Millisecond {
					return errors.New("Retry-After ignored")
				}
				ok := response(next, 200, "OK")
				ok.set("expires", "3600")
				if err = sendPeer(c, ok); err != nil {
					return err
				}
				_, _ = readMessage(r)
				return nil
			})
			cfg.Expires = 100 * time.Millisecond
			cfg.RecoveryInitial = 10 * time.Millisecond
			states := make(chan bool, 16)
			cfg.OnState = func(ready bool, _ error) { states <- ready }
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err = s.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			awaitIMSState(t, states, true)
			awaitIMSState(t, states, false)
			if status == 503 {
				awaitIMSState(t, states, true)
			} else {
				start := time.Now()
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
				if time.Since(start) > 200*time.Millisecond {
					t.Fatal("cooldown blocked cancellation")
				}
			}
		})
	}
}

// A listener with no accepted traffic makes port/SPI lifecycle checks independent
// of local port availability; wire registration still uses real TCP peers.
type recoveryListener struct {
	address net.Addr
	done    chan struct{}
	once    sync.Once
}

func (l *recoveryListener) Accept() (net.Conn, error) { <-l.done; return nil, net.ErrClosed }
func (l *recoveryListener) Close() error              { l.once.Do(func() { close(l.done) }); return nil }
func (l *recoveryListener) Addr() net.Addr            { return l.address }

func TestRecoveryRebuildsSecurityAndClosesOldProtectedListener(t *testing.T) {
	states := make(chan bool, 16)
	var agreements []SecurityAgreement
	var listeners []*recoveryListener
	var mu sync.Mutex
	trigger := make(chan struct{})
	protectedPeer := func(first bool) Config {
		return configPeer(t, func(c net.Conn) error {
			r := bufio.NewReader(c)
			m, err := readMessage(r)
			if err != nil {
				return err
			}
			if m.method() != "REGISTER" || m.get("security-verify") == "" || !strings.Contains(m.get("authorization"), `realm="fresh.ims.test"`) || strings.Contains(m.get("authorization"), `response=""`) {
				return errors.New("missing authenticated protected registration")
			}
			if err = sendPeer(c, response(m, 200, "OK")); err != nil {
				return err
			}
			if first {
				<-trigger
				return nil
			}
			_, _ = readMessage(r)
			return nil
		})
	}
	p1, p2 := protectedPeer(true), protectedPeer(false)
	plainPeer := func(protected Config) Config {
		return configPeer(t, func(c net.Conn) error {
			r := bufio.NewReader(c)
			m, err := readMessage(r)
			if err != nil {
				return err
			}
			if m.get("security-client") == "" || !strings.Contains(m.get("authorization"), `nonce=""`) {
				return errors.New("reused old security or auth")
			}
			_, port, _ := net.SplitHostPort(protected.PCSCF[0])
			challenge := response(m, 401, "Unauthorized")
			challenge.set("www-authenticate", `Digest realm="fresh.ims.test", nonce="`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`", algorithm=AKAv1-MD5`)
			challenge.set("security-server", "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=400;spi-s=401;port-c="+port+";port-s="+port)
			if err = sendPeer(c, challenge); err != nil {
				return err
			}
			if _, err = readMessage(r); err == nil {
				return errors.New("AKA response sent without protected association")
			}
			return nil
		})
	}
	cfg, second := plainPeer(p1), plainPeer(p2)
	cfg.PCSCF = append(cfg.PCSCF, second.PCSCF...)
	cfg.SecurityClient = &SecurityParameters{Algorithm: "hmac-sha-1-96", Encryption: "aes-cbc", SPIClient: 256, SPIServer: 257, PortClient: 5070, PortServer: 5071}
	cfg.InstallSecurity = func(_ context.Context, a SecurityAgreement) (DialContextFunc, error) {
		if len(a.CK) != 16 || len(a.IK) != 16 || a.Client.Encryption != "aes-cbc" {
			return nil, errors.New("lost AKA/security")
		}
		mu.Lock()
		agreements = append(agreements, a)
		mu.Unlock()
		return (&net.Dialer{}).DialContext, nil
	}
	cfg.ListenTCP = func(_ context.Context, _, address string) (net.Listener, error) {
		a, err := net.ResolveTCPAddr("tcp", address)
		if err != nil {
			return nil, err
		}
		l := &recoveryListener{address: a, done: make(chan struct{})}
		mu.Lock()
		listeners = append(listeners, l)
		mu.Unlock()
		return l, nil
	}
	cfg.OnState = func(ready bool, _ error) { states <- ready }
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer func() {
		select {
		case <-trigger:
		default:
			close(trigger)
		}
	}()
	if err = s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitIMSState(t, states, true)
	close(trigger)
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ready := <-states:
			if ready {
				goto recovered
			}
		case <-deadline:
			t.Fatal("protected recovery timed out")
		}
	}
recovered:
	mu.Lock()
	defer mu.Unlock()
	if len(agreements) != 2 || len(listeners) != 2 {
		t.Fatalf("agreements/listeners: %d/%d", len(agreements), len(listeners))
	}
	a, b := agreements[0].Client, agreements[1].Client
	if a.SPIClient == b.SPIClient || a.SPIServer == b.SPIServer || a.PortClient == b.PortClient || a.PortServer == b.PortServer {
		t.Fatal("recovery reused security association")
	}
	select {
	case <-listeners[0].done:
	default:
		t.Fatal("old protected listener leaked")
	}
	// A late error from the old listener cannot revoke the new registration.
	s.serverFailure(nil, listeners[0], errors.New("old listener closed"))
	if !s.Ready() {
		t.Fatal("old listener error revoked readiness")
	}
}

func TestRefreshRejectsInvalidAuthenticationWithoutRetry(t *testing.T) {
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		auth, err := peerRegister(r, c)
		if err != nil {
			return err
		}
		if err = sendPeer(c, response(auth, 200, "OK")); err != nil {
			return err
		}
		refresh, err := readMessage(r)
		if err != nil {
			return err
		}
		bad := response(refresh, 401, "Unauthorized")
		bad.set("www-authenticate", `Digest realm="ims.test", nonce="invalid", algorithm=AKAv1-MD5`)
		if err = sendPeer(c, bad); err != nil {
			return err
		}
		if _, err = readMessage(r); err == nil {
			return errors.New("retried invalid AKA challenge")
		}
		return nil
	})
	cfg.Expires = 100 * time.Millisecond
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
		if s.Ready() || s.Err() == nil || errors.Is(s.Err(), ErrRecovering) {
			t.Fatalf("invalid auth state: %v", s.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("invalid AKA challenge did not terminate IMS")
	}
}

func TestRecoveryEndsUSSDWaitAndCancelsOldDialogTraffic(t *testing.T) {
	first := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		if err := registeredVoicePeer(r, c); err != nil {
			return err
		}
		invite, err := expectMethod(r, "INVITE")
		if err != nil {
			return err
		}
		ok := response(invite, 200, "OK")
		ok.set("to", invite.get("to")+";tag=ussd")
		if err = sendPeer(c, ok); err != nil {
			return err
		}
		_, err = expectMethod(r, "ACK")
		return err
	})
	unexpected := make(chan string, 4)
	second := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		if err := registeredVoicePeer(r, c); err != nil {
			return err
		}
		for {
			m, err := readMessage(r)
			if err != nil {
				return nil
			}
			unexpected <- m.Start
		}
	})
	first.PCSCF = append(first.PCSCF, second.PCSCF...)
	states := make(chan bool, 16)
	first.OnState = func(ready bool, _ error) { states <- ready }
	s, err := New(first)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitIMSState(t, states, true)
	oldInvite := s.request("INVITE", "sip:callee@ims.test", "old-voice-dialog")
	oldInvite.set("cseq", "1 INVITE")
	result := make(chan error, 1)
	go func() { _, err := s.SendUSSD(context.Background(), "*123#"); result <- err }()
	select {
	case err := <-result:
		if !errors.Is(err, ErrFlowChanged) {
			t.Fatalf("USSD wait: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("USSD waiter survived broken flow")
	}
	deadline := time.After(time.Second)
	for !s.Ready() {
		select {
		case <-states:
		case <-deadline:
			t.Fatal("recovery timed out")
		}
	}
	a := &VoiceAgent{service: s}
	call := &voiceCall{invite: oldInvite, target: "sip:callee@ims.test"}
	if err = a.ack(call, response(oldInvite, 480, "Unavailable")); !errors.Is(err, ErrFlowChanged) {
		t.Fatalf("old negative ACK: %v", err)
	}
	if err = a.ack(call, response(oldInvite, 200, "OK")); !errors.Is(err, ErrFlowChanged) {
		t.Fatalf("old dialog ACK: %v", err)
	}
	start := time.Now()
	a.cancelInvite(call, oldInvite, make(chan *message), true)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("old CANCEL waiter survived broken flow")
	}
	select {
	case m := <-unexpected:
		t.Fatalf("old dialog migrated: %s", m)
	default:
	}
}

func TestInitialTemporaryRejectionTriesNextPCSCF(t *testing.T) {
	first := configPeer(t, func(c net.Conn) error {
		m, err := readMessage(bufio.NewReader(c))
		if err != nil {
			return err
		}
		return sendPeer(c, response(m, 503, "Unavailable"))
	})
	second := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		if err := registeredVoicePeer(r, c); err != nil {
			return err
		}
		_, _ = readMessage(r)
		return nil
	})
	first.PCSCF = append(first.PCSCF, second.PCSCF...)
	s, err := New(first)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.Ready() {
		t.Fatal("alternate P-CSCF did not register")
	}
}
