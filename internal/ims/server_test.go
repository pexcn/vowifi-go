package ims

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pexcn/vowifi-go/engine/sim"
	smscodec "github.com/warthog618/sms"
)

func udpFixture(t *testing.T) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	return c
}
func packetRead(c net.PacketConn) (*message, net.Addr, error) {
	buf := make([]byte, 65536)
	n, from, err := c.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}
	m, err := readMessage(bufio.NewReader(bytes.NewReader(buf[:n])))
	return m, from, err
}
func packetWrite(c net.PacketConn, to net.Addr, m *message) error {
	b, err := m.bytes()
	if err != nil {
		return err
	}
	_, err = c.WriteTo(b, to)
	return err
}
func TestProtectedServerPairReceivesSMSAndRepliesOnReceivingPair(t *testing.T) {
	initial, remoteServer, remoteClient, terminalServer := udpFixture(t), udpFixture(t), udpFixture(t), udpFixture(t)
	remoteServerPort := remoteServer.LocalAddr().(*net.UDPAddr).Port
	remoteClientPort := remoteClient.LocalAddr().(*net.UDPAddr).Port
	terminalServerPort := terminalServer.LocalAddr().(*net.UDPAddr).Port
	errs := make(chan error, 2)
	go func() {
		m, from, err := packetRead(initial)
		if err != nil {
			errs <- err
			return
		}
		r := response(m, 401, "Unauthorized")
		r.set("www-authenticate", `Digest realm="ims.test", nonce="`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`", algorithm=AKAv1-MD5`)
		r.set("security-server", fmt.Sprintf("ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=400;spi-s=401;port-c=%d;port-s=%d", remoteClientPort, remoteServerPort))
		errs <- packetWrite(initial, from, r)
	}()
	go func() {
		reg, from, err := packetRead(remoteServer)
		if err != nil {
			errs <- err
			return
		}
		if reg.method() != "REGISTER" || !strings.Contains(reg.get("contact"), terminalServer.LocalAddr().String()) {
			errs <- fmt.Errorf("REGISTER Contact must advertise protected server-s: %#v", reg)
			return
		}
		if err = packetWrite(remoteServer, from, response(reg, 200, "OK")); err != nil {
			errs <- err
			return
		}
		ack, from, err := packetRead(remoteServer)
		if err != nil {
			errs <- err
			return
		}
		if ack.method() != "MESSAGE" || !bytes.Equal(ack.Body, []byte{2, 44}) {
			errs <- fmt.Errorf("MT RP-ACK was not sent over client-c -> server-s: %#v", ack)
			return
		}
		errs <- packetWrite(remoteServer, from, response(ack, 200, "OK"))
	}()
	cfg := Config{PrivateIdentity: "00101@ims.test", PublicIdentity: "sip:+15550100@ims.test", Realm: "ims.test", PCSCF: []string{initial.LocalAddr().String()}, Transport: "udp", DialContext: (&net.Dialer{}).DialContext, TransactionTimeout: time.Second, KeepAlive: time.Minute, SIM: akaFunc(func(_, _ []byte) (sim.AKAResult, error) {
		return sim.AKAResult{RES: []byte{1, 2, 3, 4}, CK: make([]byte, 16), IK: make([]byte, 16)}, nil
	})}
	cfg.SecurityClient = &SecurityParameters{Algorithm: "hmac-sha-1-96", Encryption: "aes-cbc", SPIClient: 200, SPIServer: 201, PortClient: 5070, PortServer: uint16(terminalServerPort)}
	cfg.InstallSecurity = func(context.Context, SecurityAgreement) (DialContextFunc, error) {
		return (&net.Dialer{}).DialContext, nil
	}
	cfg.ListenPacket = func(_ context.Context, network, address string) (net.PacketConn, error) {
		if network != "udp" || address != terminalServer.LocalAddr().String() {
			return nil, fmt.Errorf("wrong listener request %s %s", network, address)
		}
		return terminalServer, nil
	}
	received := make(chan string, 1)
	cfg.OnSMS = func(_, text string, _ time.Time) { received <- text }
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	parts, err := smscodec.Encode([]byte("protected inbound"), smscodec.AsDeliver, smscodec.From("+15551234"))
	if err != nil {
		t.Fatal(err)
	}
	tp, err := parts[0].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	incoming := &message{Start: "MESSAGE sip:+15550100@ims.test SIP/2.0", Headers: map[string][]string{}, Body: append([]byte{1, 44, 0, 0, byte(len(tp))}, tp...)}
	incoming.set("via", "SIP/2.0/UDP "+remoteClient.LocalAddr().String()+";branch=z9hG4bKinbound")
	incoming.set("from", "<sip:smsc@ims.test>;tag=network")
	incoming.set("to", "<sip:+15550100@ims.test>")
	incoming.set("call-id", "protected-inbound")
	incoming.set("cseq", "1 MESSAGE")
	incoming.set("content-type", "application/vnd.3gpp.sms")
	if err = packetWrite(remoteClient, terminalServer.LocalAddr(), incoming); err != nil {
		t.Fatal(err)
	}
	reply, from, err := packetRead(remoteClient)
	if err != nil || reply.status() != 200 || from.String() != terminalServer.LocalAddr().String() {
		t.Fatalf("SIP response must use server-s -> client-c: %v %v %v", reply, from, err)
	}
	// Retransmissions are served through the same receiving protected pair.
	if err = packetWrite(remoteClient, terminalServer.LocalAddr(), incoming); err != nil {
		t.Fatal(err)
	}
	reply, from, err = packetRead(remoteClient)
	if err != nil || reply.status() != 200 || from.String() != terminalServer.LocalAddr().String() {
		t.Fatalf("cached reply wrong port pair %v %v %v", reply, from, err)
	}
	select {
	case text := <-received:
		if text != "protected inbound" {
			t.Fatal(text)
		}
	case <-ctx.Done():
		t.Fatal("inbound SMS never delivered")
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	select {
	case text := <-received:
		t.Fatalf("retransmission delivered twice: %s", text)
	default:
	}
}

func TestSecurityWithoutInjectedServerListenerFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, peer := net.Pipe()
	defer c.Close()
	defer peer.Close()
	// startSecureServer requires a real, numeric inner transport endpoint.
	s := &Service{cfg: Config{Transport: "udp"}, ctx: ctx, cancel: cancel, conn: &addressedConn{Conn: c, local: &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 5070}}}
	err := s.startSecureServer(ctx, SecurityParameters{PortServer: 5071}, SecurityParameters{PortClient: 6000}, "10.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "injected tunnel packet listener") {
		t.Fatalf("missing listener accepted: %v", err)
	}
}

type addressedConn struct {
	net.Conn
	local net.Addr
}

func (c *addressedConn) LocalAddr() net.Addr { return c.local }

func TestProtectedServerRejectsOtherSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	terminal, expected, wrong := udpFixture(t), udpFixture(t), udpFixture(t)
	client, peer := net.Pipe()
	defer peer.Close()
	s := &Service{cfg: Config{Transport: "udp"}, ctx: ctx, cancel: cancel, conn: client, serverUDP: terminal, serverPeer: expected.LocalAddr().String(), serverResponses: map[string]cachedResponse{}}
	s.wg.Add(1)
	go s.serveSecurePackets(terminal)
	defer s.Close()
	m := &message{Start: "OPTIONS sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
	m.set("via", "SIP/2.0/UDP "+wrong.LocalAddr().String()+";branch=z9hG4bKwrong")
	m.set("call-id", "wrong-peer")
	m.set("cseq", "1 OPTIONS")
	if err := packetWrite(wrong, terminal.LocalAddr(), m); err != nil {
		t.Fatal(err)
	}
	_ = wrong.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	_, _, err := packetRead(wrong)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("unexpected peer was accepted: %v", err)
	}
}

func TestProtectedTCPServerRepliesOnAcceptedConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	remote, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	_ = remote.SetDeadline(time.Now().Add(3 * time.Second))
	client, unused := net.Pipe()
	defer unused.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Service{cfg: Config{Transport: "tcp"}, ctx: ctx, cancel: cancel, conn: client, serverTCP: listener, serverPeer: remote.LocalAddr().String(), serverResponses: map[string]cachedResponse{}, serverConns: map[net.Conn]struct{}{}}
	s.wg.Add(1)
	go s.serveSecureTCP(listener)
	defer s.Close()
	req := &message{Start: "OPTIONS sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
	req.set("via", "SIP/2.0/TCP "+remote.LocalAddr().String()+";branch=z9hG4bKserverstream")
	req.set("call-id", "server-tcp")
	req.set("cseq", "1 OPTIONS")
	r := bufio.NewReader(remote)
	for i := 0; i < 2; i++ {
		if err = sendPeer(remote, req); err != nil {
			t.Fatal(err)
		}
		reply, err := readMessage(r)
		if err != nil || reply.status() != 200 {
			t.Fatalf("protected stream response %#v %v", reply, err)
		}
	}
}
