package ims

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/internal/voice/media"
	"github.com/iniwex5/vowifi-go/runtimehost/voicehost"
)

// Signal when Hangup reaches its ACK wait, so the peer sends ACK only after
// the hangup operation has started. No scheduling sleeps are needed.
type observedACKWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *observedACKWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestIncomingHangupDoesNotBlockACK(t *testing.T) {
	for _, cancelBeforeACK := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel_before_ack=%v", cancelBeforeACK), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			remote, err := media.NewSession(ctx, voiceListen, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			defer remote.Close()
			offer, err := remote.Local.SDP()
			if err != nil {
				t.Fatal(err)
			}
			begin, sendACK := make(chan struct{}), make(chan struct{})
			hangupDone := make(chan struct{})
			finishPeer := sync.OnceFunc(func() { close(hangupDone) })
			peerDone := make(chan error, 1)
			cfg := configPeer(t, func(conn net.Conn) (err error) {
				defer func() { peerDone <- err }()
				r := bufio.NewReader(conn)
				if err = registeredVoicePeer(r, conn); err != nil {
					return err
				}
				<-begin
				inv := &message{Start: "INVITE sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
				for key, value := range map[string]string{
					"via": "SIP/2.0/TCP ims.test;branch=z9hG4bKhangup", "from": "<sip:caller@ims.test>;tag=caller",
					"to": "<sip:user@ims.test>", "call-id": "hangup-before-ack", "cseq": "1 INVITE",
					"contact": "<sip:caller@ims.test>", "content-type": "application/sdp",
				} {
					inv.set(key, value)
				}
				inv.Body = offer
				if err = sendPeer(conn, inv); err != nil {
					return err
				}
				for _, code := range []int{180, 200} {
					answer, e := readMessage(r)
					if e != nil || answer.status() != code {
						return fmt.Errorf("incoming response %d: %v %v", code, answer, e)
					}
					if code != 200 {
						continue
					}
					<-sendACK
					ack := &message{Start: "ACK sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
					for _, key := range []string{"via", "from", "call-id"} {
						copyHeader(ack, inv, key)
					}
					ack.set("to", answer.get("to"))
					ack.set("cseq", "1 ACK")
					if err = sendPeer(conn, ack); err != nil {
						return err
					}
				}
				bye, err := expectMethod(r, "BYE")
				if err != nil {
					return err
				}
				if err = sendPeer(conn, response(bye, 200, "OK")); err != nil {
					return err
				}
				// Keep the registered flow open until the transaction consumes
				// the BYE response; transport loss is a separate recovery case.
				<-hangupDone
				return nil
			})
			a := startVoice(t, cfg)
			a.cfg.EnableCallControl = true
			releaseACK := sync.OnceFunc(func() { close(sendACK) })
			t.Cleanup(finishPeer)
			t.Cleanup(releaseACK)
			close(begin)
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
			hangupCtx, cancelHangup := context.WithCancel(ctx)
			defer cancelHangup()
			observed := &observedACKWaitContext{Context: hangupCtx, waiting: make(chan struct{})}
			result := make(chan error, 1)
			go func() { result <- a.Hangup(observed, id) }()
			select {
			case <-observed.waiting:
			case <-ctx.Done():
				t.Fatal("Hangup did not wait for ACK")
			}
			if cancelBeforeACK {
				cancelHangup()
				if err = <-result; !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled hangup: %v", err)
				}
				live, lookupErr := a.liveCall(id)
				if lookupErr != nil || live.ctx.Err() != nil {
					t.Fatal("cancelled hangup terminated the call before ACK")
				}
				releaseACK()
				err = a.Hangup(ctx, id)
			} else {
				releaseACK()
				err = <-result
			}
			if err != nil {
				t.Fatalf("hangup after ACK: %v", err)
			}
			finishPeer()
			select {
			case err = <-peerDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("BYE transaction did not finish")
			}
		})
	}
}
