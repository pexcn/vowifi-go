package ims

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/engine/sim"
	smscodec "github.com/warthog618/sms"
	"github.com/warthog618/sms/encoding/tpdu"
)

func sendPeer(c net.Conn, m *message) error {
	b, e := m.bytes()
	if e != nil {
		return e
	}
	_, e = c.Write(b)
	return e
}
func configPeer(t *testing.T, handler func(net.Conn) error) Config {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	done := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
		done <- handler(c)
	}()
	t.Cleanup(func() {
		select {
		case e := <-done:
			if e != nil && !errors.Is(e, net.ErrClosed) {
				t.Errorf("peer: %v", e)
			}
		case <-time.After(2 * time.Second):
			t.Error("peer leaked")
		}
	})
	return Config{PrivateIdentity: "001010123456789@ims.test", PublicIdentity: "sip:+15550100@ims.test", Realm: "ims.test", SMSC: "+15550001", PCSCF: []string{l.Addr().String()}, Transport: "tcp", DialContext: (&net.Dialer{}).DialContext, KeepAlive: time.Minute, TransactionTimeout: 3 * time.Second, SIM: akaFunc(func(r, a []byte) (sim.AKAResult, error) {
		return sim.AKAResult{RES: []byte{1, 2, 3, 4, 5, 6, 7, 8}, CK: make([]byte, 16), IK: make([]byte, 16)}, nil
	})}
}
func peerRegister(r *bufio.Reader, c net.Conn) (*message, error) {
	m, e := readMessage(r)
	if e != nil {
		return nil, e
	}
	if m.method() != "REGISTER" {
		return nil, errors.New("expected REGISTER")
	}
	challenge := response(m, 401, "Unauthorized")
	nonce := base64.StdEncoding.EncodeToString(make([]byte, 32))
	challenge.set("www-authenticate", `Digest realm="ims.test", nonce="`+nonce+`", algorithm=AKAv1-MD5, qop="auth"`)
	if e = sendPeer(c, challenge); e != nil {
		return nil, e
	}
	auth, e := readMessage(r)
	if e != nil {
		return nil, e
	}
	if !strings.Contains(auth.get("authorization"), `algorithm=AKAv1-MD5`) || !strings.Contains(auth.get("authorization"), `qop=auth`) {
		return nil, errors.New("missing AKA digest")
	}
	return auth, nil
}
func TestRegisterSMSAndRealRPReceipt(t *testing.T) {
	report := make(chan Report, 1)
	incoming := make(chan string, 1)
	submitted := make(chan struct{})
	var submits atomic.Int32
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		auth, e := peerRegister(r, c)
		if e != nil {
			return e
		}
		if e = sendPeer(c, response(auth, 200, "OK")); e != nil {
			return e
		}
		m, e := readMessage(r)
		if e != nil {
			return e
		}
		if m.method() != "MESSAGE" {
			return errors.New("expected SMS MESSAGE")
		}
		rp, e := parseRP(m.Body)
		if e != nil || rp.Kind != 0 {
			return fmt.Errorf("RP-DATA %#v %v", rp, e)
		}
		p, e := smscodec.Unmarshal(rp.UserData, smscodec.AsMO)
		if e != nil || p.SmsType() != tpdu.SmsSubmit || p.DA.Number() != "10086" {
			return fmt.Errorf("invalid submit %#v %v", p, e)
		}
		if submits.Load() != 2 {
			return errors.New("durable create and part callback must precede transmit")
		}
		if e = sendPeer(c, response(m, 202, "Accepted")); e != nil {
			return e
		}
		<-submitted
		ack := &message{Start: "MESSAGE sip:+15550100@ims.test SIP/2.0", Headers: make(map[string][]string), Body: []byte{3, rp.Reference}}
		ack.set("content-type", "application/vnd.3gpp.sms")
		ack.set("from", "<sip:smsc@ims.test>")
		ack.set("to", m.get("from"))
		ack.set("call-id", "rp-ack")
		ack.set("cseq", "1 MESSAGE")
		ack.set("via", "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKnetwork")
		if e = sendPeer(c, ack); e != nil {
			return e
		}
		receipt, e := readMessage(r)
		if e != nil || receipt.status() != 200 {
			return fmt.Errorf("RP acknowledgement response %#v %v", receipt, e)
		}
		// Send one real SMS-DELIVER; require SIP acceptance and an MO RP-ACK.
		parts, e := smscodec.Encode([]byte("hello from SMSC"), smscodec.AsDeliver, smscodec.From("+15551234"))
		if e != nil {
			return e
		}
		tp, e := parts[0].MarshalBinary()
		if e != nil {
			return e
		}
		mt := []byte{1, 44, 0, 0, byte(len(tp))}
		mt = append(mt, tp...)
		deliver := &message{Start: "MESSAGE sip:+15550100@ims.test SIP/2.0", Headers: make(map[string][]string), Body: mt}
		for k, vs := range ack.Headers {
			deliver.Headers[k] = append([]string(nil), vs...)
		}
		deliver.set("call-id", "mt-deliver")
		deliver.set("cseq", "2 MESSAGE")
		if e = sendPeer(c, deliver); e != nil {
			return e
		}
		sip, e := readMessage(r)
		if e != nil || sip.status() != 200 {
			return fmt.Errorf("MT SIP %#v %v", sip, e)
		}
		rpAck, e := readMessage(r)
		if e != nil || len(rpAck.Body) != 2 || rpAck.Body[0] != 2 || rpAck.Body[1] != 44 {
			return fmt.Errorf("MT RP-ACK %#v %v", rpAck, e)
		}
		if e = sendPeer(c, response(rpAck, 200, "OK")); e != nil {
			return e
		}
		_, _ = readMessage(r)
		return nil
	})
	cfg.OnReport = func(r Report) { report <- r }
	cfg.OnSMS = func(_, text string, _ time.Time) { incoming <- text }
	cfg.OnSend = func(_, _, _ string, _ int) error { submits.Add(1); return nil }
	cfg.OnPart = func(_ string, p SentPart) error {
		if p.State == "pending" {
			submits.Add(1)
		}
		return nil
	}
	s, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	if e = s.Start(ctx); e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	out, e := s.SendSMS(ctx, "10086", "hello 世界", "auto")
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Parts) != 1 || out.Parts[0].State != "accepted" {
		t.Fatalf("SIP acceptance %#v", out)
	}
	select {
	case r := <-report:
		t.Fatalf("fake receipt before network report %#v", r)
	default:
	}
	close(submitted)
	select {
	case r := <-report:
		if r.State != "acked" || r.CallID != out.Parts[0].CallID {
			t.Fatalf("RP report %#v", r)
		}
	case <-ctx.Done():
		t.Fatal("missing RP receipt")
	}
	select {
	case text := <-incoming:
		if text != "hello from SMSC" {
			t.Fatal(text)
		}
	case <-ctx.Done():
		t.Fatal("missing incoming SMS")
	}
}
func TestRejectUnauthenticatedRegistration(t *testing.T) {
	cfg := configPeer(t, func(c net.Conn) error {
		m, e := readMessage(bufio.NewReader(c))
		if e != nil {
			return e
		}
		return sendPeer(c, response(m, 200, "OK"))
	})
	s, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Start(context.Background()); e == nil || s.Ready() {
		t.Fatal("unauthenticated network marked ready")
	}
}
func TestRegistrationRefreshKeepsAuthentication(t *testing.T) {
	refreshed := make(chan struct{})
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		m, e := peerRegister(r, c)
		if e != nil {
			return e
		}
		ok := response(m, 200, "OK")
		ok.set("expires", "1")
		if e = sendPeer(c, ok); e != nil {
			return e
		}
		m, e = readMessage(r)
		if e != nil {
			return e
		}
		if m.method() != "REGISTER" || m.get("authorization") == "" {
			return errors.New("refresh lacks digest")
		}
		if e = sendPeer(c, response(m, 200, "OK")); e != nil {
			return e
		}
		close(refreshed)
		_, _ = readMessage(r)
		return nil
	})
	s, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e = s.Start(ctx); e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	select {
	case <-refreshed:
		if !s.Ready() {
			t.Fatalf("refresh lost readiness %v", s.Err())
		}
	case <-ctx.Done():
		t.Fatal("registration did not refresh")
	}
}
func TestDurableSendFailurePreventsNetworkTransmit(t *testing.T) {
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		m, e := peerRegister(r, c)
		if e != nil {
			return e
		}
		if e = sendPeer(c, response(m, 200, "OK")); e != nil {
			return e
		}
		m, e = readMessage(r)
		if e == nil {
			return fmt.Errorf("unexpected request after durable-store failure: %s", m.Start)
		}
		return nil
	})
	cfg.OnSend = func(_, _, _ string, _ int) error { return errors.New("disk full") }
	s, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.SendSMS(context.Background(), "10086", "hello", ""); e == nil || !strings.Contains(e.Error(), "disk full") {
		t.Fatalf("store failure lost: %v", e)
	}
}

func TestAKAErrorDoesNotBecomeReady(t *testing.T) {
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		m, err := readMessage(r)
		if err != nil {
			return err
		}
		challenge := response(m, 401, "Unauthorized")
		challenge.set("www-authenticate", `Digest realm="ims.test", nonce="`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`", algorithm=AKAv1-MD5`)
		if err = sendPeer(c, challenge); err != nil {
			return err
		}
		m, err = readMessage(r)
		if err == nil {
			return fmt.Errorf("request sent after SIM failure %s", m.Start)
		}
		return nil
	})
	cfg.SIM = akaFunc(func(_, _ []byte) (sim.AKAResult, error) { return sim.AKAResult{}, errors.New("SIM rejected AUTN") })
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "SIM rejected AUTN") || s.Ready() {
		t.Fatalf("authentication failure readiness %v %v", err, s.Ready())
	}
}

func TestCarrierRegisterHeadersAndCancellationReadiness(t *testing.T) {
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		m, err := peerRegister(r, c)
		if err != nil {
			return err
		}
		if m.get("user-agent") != "TestPhone/1" || m.get("p-access-network-info") != "IEEE-802.11" || !strings.Contains(m.get("contact"), ";+g.3gpp.smsip") {
			return fmt.Errorf("missing carrier configuration %#v", m.Headers)
		}
		if err = sendPeer(c, response(m, 200, "OK")); err != nil {
			return err
		}
		_, _ = readMessage(r)
		return nil
	})
	cfg.UserAgent = "TestPhone/1"
	cfg.ContactParameters = "+g.3gpp.smsip"
	cfg.RegisterHeaders = map[string]string{"P-Access-Network-Info": "IEEE-802.11"}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err = s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.LocalAddress() == nil {
		t.Fatal("missing selected endpoint")
	}
	cancel()
	if s.Ready() {
		t.Fatal("cancelled service still ready")
	}
	cfg.RegisterHeaders = map[string]string{"Authorization": "fake"}
	if _, err = New(cfg); err == nil {
		t.Fatal("reserved carrier header accepted")
	}
}

func TestSIPRejectionAndTimeoutReturnErrors(t *testing.T) {
	for _, reject := range []bool{true, false} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			cfg := configPeer(t, func(c net.Conn) error {
				r := bufio.NewReader(c)
				m, err := peerRegister(r, c)
				if err != nil {
					return err
				}
				if err = sendPeer(c, response(m, 200, "OK")); err != nil {
					return err
				}
				m, err = readMessage(r)
				if err != nil {
					return err
				}
				if reject {
					if err = sendPeer(c, response(m, 403, "Forbidden")); err != nil {
						return err
					}
				}
				_, _ = readMessage(r)
				return nil
			})
			cfg.TransactionTimeout = 50 * time.Millisecond
			cfg.OnPart = func(_ string, _ SentPart) error { return nil }
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			out, err := s.SendSMS(context.Background(), "10086", "hello", "")
			if err == nil || len(out.Parts) != 1 || out.Parts[0].State != "failed" {
				t.Fatalf("failed SMS %#v %v", out, err)
			}
		})
	}
}

func TestRegistrationInstallsSecurityBeforeAuthenticatedRetry(t *testing.T) {
	var installs atomic.Int32
	protectedCfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		m, err := readMessage(r)
		if err != nil {
			return err
		}
		if m.method() != "REGISTER" || m.get("authorization") == "" || m.get("security-verify") == "" || m.get("proxy-require") != "sec-agree" || installs.Load() != 1 {
			return fmt.Errorf("unprotected authenticated retry %#v", m)
		}
		if err = sendPeer(c, response(m, 200, "OK")); err != nil {
			return err
		}
		_, _ = readMessage(r)
		return nil
	})
	_, port, err := net.SplitHostPort(protectedCfg.PCSCF[0])
	if err != nil {
		t.Fatal(err)
	}
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		m, err := readMessage(r)
		if err != nil {
			return err
		}
		if m.get("security-client") == "" || m.get("require") != "sec-agree" || m.get("proxy-require") != "sec-agree" {
			return errors.New("missing security offer")
		}
		challenge := response(m, 401, "Unauthorized")
		challenge.set("www-authenticate", `Digest realm="ims.test", nonce="`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`", algorithm=AKAv1-MD5`)
		challenge.set("security-server", "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=400;spi-s=401;port-c="+port+";port-s="+port)
		if err = sendPeer(c, challenge); err != nil {
			return err
		}
		m, err = readMessage(r)
		if err == nil {
			return errors.New("authenticated REGISTER sent on original association")
		}
		return nil
	})
	// Reserve the actual protected terminal server port for the injected listener.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	serverPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	cfg.ListenTCP = func(_ context.Context, _, address string) (net.Listener, error) {
		if listener.Addr().String() != address {
			return nil, fmt.Errorf("wrong server bind %s", address)
		}
		return listener, nil
	}
	cfg.SecurityClient = &SecurityParameters{Algorithm: "hmac-sha-1-96", Encryption: "aes-cbc", SPIClient: 200, SPIServer: 201, PortClient: 5070, PortServer: serverPort}
	cfg.InstallSecurity = func(_ context.Context, a SecurityAgreement) (DialContextFunc, error) {
		if len(a.CK) != 16 || len(a.IK) != 16 || a.Server.SPIClient != 400 || a.Client.SPIClient != 200 || a.RemoteAddress == "" {
			return nil, errors.New("bad AKA security material")
		}
		installs.Add(1)
		return (&net.Dialer{}).DialContext, nil
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if installs.Load() != 1 || !s.Ready() {
		t.Fatal("secured registration failed")
	}
}
