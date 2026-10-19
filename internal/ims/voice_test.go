package ims

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/internal/voice/media"
	"github.com/iniwex5/vowifi-go/runtimehost/voicehost"
)

func voiceListen(ctx context.Context, network, address string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}
func voiceAnswer(inv *message, code int, body []byte) *message {
	r := response(inv, code, "Test")
	r.set("to", inv.get("to")+";tag=remote")
	r.set("contact", "<sip:callee@ims.test:5070>")
	if len(body) > 0 {
		r.set("content-type", "application/sdp")
		r.Body = body
	}
	return r
}
func startVoice(t *testing.T, cfg Config) *VoiceAgent {
	t.Helper()
	cfg.LocalAddress = "127.0.0.1"
	s, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	a, e := NewVoiceAgent(s, VoiceConfig{LocalAddress: "127.0.0.1", ListenPacket: voiceListen})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Close() })
	return a
}
func registeredVoicePeer(r *bufio.Reader, c net.Conn) error {
	m, e := peerRegister(r, c)
	if e != nil {
		return e
	}
	return sendPeer(c, response(m, 200, "OK"))
}
func expectMethod(r *bufio.Reader, method string) (*message, error) {
	m, e := readMessage(r)
	if e != nil {
		return nil, e
	}
	if m.method() != method {
		return nil, fmt.Errorf("expected %s, got %s", method, m.Start)
	}
	return m, nil
}
func TestVoiceAnsweredPRACKRTPAndRemoteBye(t *testing.T) {
	rtp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer rtp.Close()
	remote := media.Description{Address: net.ParseIP("127.0.0.1"), RTP: rtp.LocalAddr().(*net.UDPAddr).Port, RTCP: 5001, Codecs: []media.Codec{{Payload: 0, Name: "PCMU", Rate: 8000, Channels: 1}}}
	sdp, e := remote.SDP()
	if e != nil {
		t.Fatal(e)
	}
	mediaReady := make(chan struct{})
	var finalSent, connected atomic.Bool
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		if e := registeredVoicePeer(r, c); e != nil {
			return e
		}
		inv, e := expectMethod(r, "INVITE")
		if e != nil {
			return e
		}
		if inv.get("authorization") == "" {
			return errors.New("voice INVITE omitted AKA digest")
		}
		offer, e := media.ParseSDP(inv.Body)
		if e != nil || offer.Address.String() != "127.0.0.1" {
			return fmt.Errorf("invalid tunnel SDP %#v %v", offer, e)
		}
		early := voiceAnswer(inv, 183, sdp)
		early.set("require", "100rel")
		early.set("rseq", "77")
		if e = sendPeer(c, early); e != nil {
			return e
		}
		p, e := expectMethod(r, "PRACK")
		if e != nil {
			return e
		}
		if p.get("rack") != "77 "+strings.Fields(inv.get("cseq"))[0]+" INVITE" || p.get("to") != early.get("to") {
			return fmt.Errorf("bad reliable provisional acknowledgement %#v", p)
		}
		if connected.Load() {
			return errors.New("connected before final response")
		}
		if e = sendPeer(c, response(p, 200, "OK")); e != nil {
			return e
		}
		answer := voiceAnswer(inv, 200, nil)
		finalSent.Store(true)
		if e = sendPeer(c, answer); e != nil {
			return e
		}
		ack, e := expectMethod(r, "ACK")
		if e != nil {
			return e
		}
		if ack.get("cseq") != strings.Fields(inv.get("cseq"))[0]+" ACK" || ack.Start != "ACK sip:callee@ims.test:5070 SIP/2.0" {
			return fmt.Errorf("bad 2xx ACK %s %s", ack.Start, ack.get("cseq"))
		}
		if e = sendPeer(c, answer); e != nil {
			return e
		}
		if _, e = expectMethod(r, "ACK"); e != nil {
			return fmt.Errorf("missing repeated 2xx ACK: %w", e)
		}
		<-mediaReady
		bye := &message{Start: "BYE sip:local@ims.test SIP/2.0", Headers: make(map[string][]string)}
		bye.set("from", answer.get("to"))
		bye.set("to", inv.get("from"))
		bye.set("call-id", inv.get("call-id"))
		bye.set("cseq", "80 BYE")
		bye.set("via", "SIP/2.0/TCP 127.0.0.1;branch=z9hG4bKbye")
		if e = sendPeer(c, bye); e != nil {
			return e
		}
		ok, e := readMessage(r)
		if e != nil || ok.status() != 200 {
			return fmt.Errorf("remote BYE response %#v %v", ok, e)
		}
		_, _ = readMessage(r)
		return nil
	})
	a := startVoice(t, cfg)
	result := make(chan struct {
		r voicehost.SimulateCallResult
		e error
	}, 1)
	go func() {
		r, e := a.SimulateCall(context.Background(), voicehost.SimulateCallRequest{Callee: "10086", OnConnected: func() {
			if !finalSent.Load() {
				t.Error("callback before answer")
			}
			connected.Store(true)
		}})
		result <- struct {
			r voicehost.SimulateCallResult
			e error
		}{r, e}
	}()
	_ = rtp.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 2048)
	n, _, e := rtp.ReadFrom(b)
	if e != nil {
		close(mediaReady)
		t.Fatal(e)
	}
	if n != 172 || b[0] != 0x80 || b[1] != 0 || b[12] != 0xff {
		t.Fatalf("invalid actual silent RTP %x", b[:n])
	}
	close(mediaReady)
	select {
	case out := <-result:
		if out.e != nil || !out.r.Success || out.r.Reason != "remote_hangup" || !connected.Load() {
			t.Fatalf("call result %#v %v", out.r, out.e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("call did not finish")
	}
}
func TestVoiceRejectedDoesNotReportConnected(t *testing.T) {
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		if e := registeredVoicePeer(r, c); e != nil {
			return e
		}
		inv, e := expectMethod(r, "INVITE")
		if e != nil {
			return e
		}
		answer := voiceAnswer(inv, 486, nil)
		if e = sendPeer(c, answer); e != nil {
			return e
		}
		ack, e := expectMethod(r, "ACK")
		if e != nil {
			return e
		}
		if ack.get("via") != inv.get("via") || ack.get("cseq") != strings.Fields(inv.get("cseq"))[0]+" ACK" || ack.get("to") != answer.get("to") {
			return errors.New("non-2xx ACK lost original transaction")
		}
		_, _ = readMessage(r)
		return nil
	})
	a := startVoice(t, cfg)
	var connected atomic.Bool
	r, e := a.SimulateCall(context.Background(), voicehost.SimulateCallRequest{Callee: "10086", OnConnected: func() { connected.Store(true) }})
	if e == nil || r.Success || connected.Load() {
		t.Fatalf("rejected call falsely connected %#v %v", r, e)
	}
}
func TestVoiceCancelLateAnswerACKAndBYE(t *testing.T) {
	provisional := make(chan struct{})
	cleaned := make(chan struct{})
	sdp := []byte("v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 5000 RTP/AVP 0\r\n")
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		if e := registeredVoicePeer(r, c); e != nil {
			return e
		}
		inv, e := expectMethod(r, "INVITE")
		if e != nil {
			return e
		}
		if e = sendPeer(c, voiceAnswer(inv, 180, nil)); e != nil {
			return e
		}
		close(provisional)
		cancel, e := expectMethod(r, "CANCEL")
		if e != nil {
			return e
		}
		if cancel.get("via") != inv.get("via") || cancel.get("cseq") != strings.Fields(inv.get("cseq"))[0]+" CANCEL" {
			return errors.New("CANCEL must share original INVITE transaction")
		}
		if e = sendPeer(c, response(cancel, 200, "OK")); e != nil {
			return e
		}
		if e = sendPeer(c, voiceAnswer(inv, 200, sdp)); e != nil {
			return e
		}
		if _, e = expectMethod(r, "ACK"); e != nil {
			return e
		}
		bye, e := expectMethod(r, "BYE")
		if e != nil {
			return e
		}
		if e = sendPeer(c, response(bye, 200, "OK")); e != nil {
			return e
		}
		close(cleaned)
		_, _ = readMessage(r)
		return nil
	})
	a := startVoice(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-provisional; cancel() }()
	var connected atomic.Bool
	r, e := a.SimulateCall(ctx, voicehost.SimulateCallRequest{Callee: "10086", OnConnected: func() { connected.Store(true) }})
	if !errors.Is(e, context.Canceled) || r.Success || connected.Load() {
		t.Fatalf("cancelled call falsely connected %#v %v", r, e)
	}
	select {
	case <-cleaned:
	case <-time.After(4 * time.Second):
		t.Fatal("late answer left remote dialog alive")
	}
}
