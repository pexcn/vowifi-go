package ims

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/internal/voice/media"
	"github.com/iniwex5/vowifi-go/runtimehost/voicehost"
)

type delayedAnswerWriteConn struct{ net.Conn }

func (c delayedAnswerWriteConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err == nil && bytes.HasPrefix(b, []byte("SIP/2.0 200 ")) &&
		strings.Contains(strings.ToLower(string(b)), "\r\ncseq: 1 invite\r\n") {
		// The peer can consume the answer and send ACK/UPDATE before the
		// caller returns from Write, as also happens under CI scheduling.
		time.Sleep(10 * time.Millisecond)
	}
	return n, err
}

func TestControlledIncomingAnswerMediaDTMFHoldAndBye(t *testing.T) {
	remote, err := media.NewSession(t.Context(), voiceListen, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	offer, err := remote.Local.SDP()
	if err != nil {
		t.Fatal(err)
	}
	begin := make(chan struct{})
	mediaReady := make(chan struct{})
	peerDone := make(chan error, 1)
	cfg := configPeer(t, func(conn net.Conn) (err error) {
		defer func() { peerDone <- err }()
		reader := bufio.NewReader(conn)
		if err = registeredVoicePeer(reader, conn); err != nil {
			return err
		}
		<-begin
		inv := &message{Start: "INVITE sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
		for k, v := range map[string]string{"via": "SIP/2.0/TCP ims.test;branch=z9hG4bKincoming", "from": "<sip:caller@ims.test>;tag=caller", "to": "<sip:user@ims.test>", "call-id": "incoming-controlled", "cseq": "1 INVITE", "contact": "<sip:caller@ims.test>", "content-type": "application/sdp"} {
			inv.set(k, v)
		}
		inv.Body = offer
		if err = sendPeer(conn, inv); err != nil {
			return err
		}
		ring, err := readMessage(reader)
		if err != nil || ring.status() != 180 {
			return fmt.Errorf("ringing: %v %v", ring, err)
		}
		answer, err := readMessage(reader)
		if err != nil || answer.status() != 200 {
			return fmt.Errorf("answer: %v %v", answer, err)
		}
		description, err := media.ParseSDP(answer.Body)
		if err != nil {
			return err
		}
		if err = remote.SetRemote(description); err != nil {
			return err
		}
		ack := &message{Start: "ACK sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
		for _, key := range []string{"via", "from", "call-id"} {
			copyHeader(ack, inv, key)
		}
		ack.set("to", answer.get("to"))
		ack.set("cseq", "1 ACK")
		if err = sendPeer(conn, ack); err != nil {
			return err
		}
		// Exercise in-dialog UPDATE and peer re-INVITE before client media.
		for _, method := range []string{"UPDATE", "INVITE"} {
			seq := 2
			if method == "INVITE" {
				seq = 3
			}
			update := &message{Start: method + " sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
			for _, key := range []string{"from", "call-id"} {
				copyHeader(update, inv, key)
			}
			update.set("to", answer.get("to"))
			update.set("via", "SIP/2.0/TCP ims.test;branch=z9hG4bK"+method)
			update.set("cseq", fmt.Sprintf("%d %s", seq, method))
			update.set("content-type", "application/sdp")
			update.Body = offer
			if err = sendPeer(conn, update); err != nil {
				return err
			}
			updated, e := readMessage(reader)
			if e != nil || updated.status() != 200 {
				return fmt.Errorf("%s response: %v %v", method, updated, e)
			}
			if method == "INVITE" {
				ack.set("cseq", "3 ACK")
				if err = sendPeer(conn, ack); err != nil {
					return err
				}
			}
		}
		close(mediaReady)
		for _, method := range []string{"INFO", "INVITE", "ACK", "INVITE", "ACK", "BYE"} {
			m, e := expectMethod(reader, method)
			if e != nil {
				return e
			}
			if method == "ACK" {
				continue
			}
			r := response(m, 200, "OK")
			if method == "INFO" && !strings.Contains(string(m.Body), "Signal=5") {
				return fmt.Errorf("invalid DTMF %q", m.Body)
			}
			if method == "INVITE" {
				desc, e := media.ParseSDP(m.Body)
				if e != nil {
					return e
				}
				reply := remote.Local
				reply.Direction = desc.Direction
				r.Body, e = reply.SDP()
				if e != nil {
					return e
				}
				r.set("content-type", "application/sdp")
				r.set("contact", "<sip:caller@ims.test>")
			}
			if err = sendPeer(conn, r); err != nil {
				return err
			}
		}
		return nil
	})
	dial := cfg.DialContext
	cfg.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return delayedAnswerWriteConn{conn}, nil
	}
	a := startVoice(t, cfg)
	a.cfg.EnableCallControl = true
	close(begin)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var id string
	for id == "" {
		for _, call := range a.Calls() {
			if call.State == "ringing" {
				id = call.ID
			}
		}
		if id == "" {
			select {
			case <-ctx.Done():
				t.Fatal("incoming call not exposed")
			case <-time.After(time.Millisecond):
			}
		}
	}
	if _, err = a.Answer(ctx, id, voicehost.CallRequest{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-mediaReady:
	case <-ctx.Done():
		t.Fatal("missing ACK")
	}
	packet := make([]byte, 172)
	packet[0] = 0x80
	if err = remote.WriteMedia(ctx, false, packet); err != nil {
		t.Fatal(err)
	}
	frame, err := a.ReadMedia(ctx, id)
	if err != nil || !bytes.Equal(frame.Packet, packet) {
		t.Fatalf("inbound media: %x %v", frame.Packet, err)
	}
	if err = a.WriteMedia(ctx, id, frame); err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	go remote.ReadMedia(ctx, func(control bool, b []byte) error {
		if !control {
			received <- bytes.Clone(b)
		}
		return nil
	})
	select {
	case b := <-received:
		if !bytes.Equal(b, packet) {
			t.Fatal("client media changed")
		}
	case <-ctx.Done():
		t.Fatal("client RTP missing")
	}
	if err = a.SendDTMF(ctx, id, "5", 160); err != nil {
		t.Fatal(err)
	}
	if err = a.Hold(ctx, id, true); err != nil {
		t.Fatal(err)
	}
	if err = a.WriteMedia(ctx, id, frame); err == nil {
		t.Fatal("media transmitted during hold")
	}
	if err = a.Hold(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	if err = a.Hangup(ctx, id); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-peerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("call cleanup hung")
	}
}

func TestControlledOutgoingSRTPDialAndMedia(t *testing.T) {
	remote, err := media.NewSession(t.Context(), voiceListen, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	remote.Local.Crypto, err = media.NewSDESCrypto()
	if err != nil {
		t.Fatal(err)
	}
	peerDone := make(chan error, 1)
	cfg := configPeer(t, func(conn net.Conn) (err error) {
		defer func() { peerDone <- err }()
		reader := bufio.NewReader(conn)
		if err = registeredVoicePeer(reader, conn); err != nil {
			return err
		}
		invite, err := expectMethod(reader, "INVITE")
		if err != nil {
			return err
		}
		offer, err := media.ParseSDP(invite.Body)
		if err != nil {
			return err
		}
		if err = remote.SetRemote(offer); err != nil {
			return err
		}
		body, err := remote.Local.SDP()
		if err != nil {
			return err
		}
		if err = sendPeer(conn, voiceAnswer(invite, 200, body)); err != nil {
			return err
		}
		if _, err = expectMethod(reader, "ACK"); err != nil {
			return err
		}
		bye, err := expectMethod(reader, "BYE")
		if err != nil {
			return err
		}
		return sendPeer(conn, response(bye, 200, "OK"))
	})
	a := startVoice(t, cfg)
	a.cfg.EnableCallControl = true
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	info, err := a.Dial(ctx, voicehost.CallRequest{Callee: "+1234567890", Secure: true})
	if err != nil || info.State != "connected" || !info.Secure {
		t.Fatalf("controlled SRTP call %+v %v", info, err)
	}
	packet := make([]byte, 172)
	packet[0] = 0x80
	if err = remote.WriteMedia(ctx, false, packet); err != nil {
		t.Fatal(err)
	}
	frame, err := a.ReadMedia(ctx, info.ID)
	if err != nil || !bytes.Equal(frame.Packet, packet) {
		t.Fatalf("SRTP media bridge: %v", err)
	}
	if err = a.Hangup(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-peerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("outgoing cleanup hung")
	}
}

func TestControlledIncomingPRACKAndCancel(t *testing.T) {
	begin := make(chan struct{})
	peerDone := make(chan error, 1)
	remote, err := media.NewSession(t.Context(), voiceListen, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	body, _ := remote.Local.SDP()
	cfg := configPeer(t, func(conn net.Conn) (err error) {
		defer func() { peerDone <- err }()
		r := bufio.NewReader(conn)
		if err = registeredVoicePeer(r, conn); err != nil {
			return err
		}
		<-begin
		inv := &message{Start: "INVITE sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
		for k, v := range map[string]string{"via": "SIP/2.0/TCP ims.test;branch=z9hG4bKcancel", "from": "<sip:caller@ims.test>;tag=remote", "to": "<sip:user@ims.test>", "call-id": "cancel-controlled", "cseq": "1 INVITE", "contact": "<sip:caller@ims.test>", "require": "100rel", "content-type": "application/sdp"} {
			inv.set(k, v)
		}
		inv.Body = body
		if err = sendPeer(conn, inv); err != nil {
			return err
		}
		ring, err := readMessage(r)
		if err != nil || ring.status() != 180 || ring.get("rseq") != "1" {
			return fmt.Errorf("reliable ringing: %v %v", ring, err)
		}
		prack := &message{Start: "PRACK sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
		for _, key := range []string{"from", "call-id"} {
			copyHeader(prack, inv, key)
		}
		prack.set("to", ring.get("to"))
		prack.set("via", "SIP/2.0/TCP ims.test;branch=z9hG4bKprack")
		prack.set("cseq", "2 PRACK")
		prack.set("rack", "1 1 INVITE")
		if err = sendPeer(conn, prack); err != nil {
			return err
		}
		reply, err := readMessage(r)
		if err != nil || reply.status() != 200 {
			return fmt.Errorf("PRACK: %v %v", reply, err)
		}
		cancel := &message{Start: "CANCEL sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
		for _, key := range []string{"via", "from", "to", "call-id"} {
			copyHeader(cancel, inv, key)
		}
		cancel.set("cseq", "1 CANCEL")
		if err = sendPeer(conn, cancel); err != nil {
			return err
		}
		for _, code := range []int{200, 487} {
			reply, err = readMessage(r)
			if err != nil || reply.status() != code {
				return fmt.Errorf("CANCEL result: %v %v", reply, err)
			}
		}
		return nil
	})
	a := startVoice(t, cfg)
	a.cfg.EnableCallControl = true
	close(begin)
	select {
	case err = <-peerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CANCEL hung")
	}
	if _, err = a.Answer(t.Context(), "cancel-controlled", voicehost.CallRequest{}); err == nil {
		t.Fatal("cancelled dialog resurrected")
	}
}
