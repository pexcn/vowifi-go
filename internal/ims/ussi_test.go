package ims

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestUSSDXML(t *testing.T) {
	b, err := encodeUSSD("<菜单>&1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeUSSD(b)
	if err != nil || got != "<菜单>&1" {
		t.Fatalf("XML %q %v", got, err)
	}
	for _, bad := range []string{`<ussd-data xmlns="evil"><ussd-string>x</ussd-string></ussd-data>`, `<ussd-data/><ussd-data/>`, `<ussd-data><error-code>42</error-code></ussd-data>`} {
		if _, err := decodeUSSD([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestUSSDDialogContinueAndCancel(t *testing.T) {
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		reg, err := peerRegister(r, c)
		if err != nil {
			return err
		}
		if err = sendPeer(c, response(reg, 200, "OK")); err != nil {
			return err
		}
		invite, err := readMessage(r)
		if err != nil {
			return err
		}
		if invite.method() != "INVITE" || !strings.HasPrefix(invite.get("content-type"), "multipart/mixed;") {
			return errors.New("expected USSI INVITE")
		}
		text, present, err := decodeUSSDContent(invite)
		if err != nil || !present || text != "*123#" {
			return fmt.Errorf("USSI code %q %v", text, err)
		}
		ok := response(invite, 200, "OK")
		ok.set("to", invite.get("to")+";tag=network")
		ok.set("contact", "<sip:ussd@ims.test>")
		ok.set("content-type", "application/vnd.3gpp.ussd+xml")
		ok.Body, _ = encodeUSSD("1. Balance")
		if err = sendPeer(c, ok); err != nil {
			return err
		}
		ack, err := readMessage(r)
		if err != nil {
			return err
		}
		if ack.method() != "ACK" || ack.get("to") != ok.get("to") || !strings.Contains(ack.Start, "sip:ussd@ims.test") {
			return errors.New("wrong dialog ACK")
		}
		info, err := readMessage(r)
		if err != nil {
			return err
		}
		text, err = decodeUSSD(info.Body)
		if err != nil || text != "1" || info.method() != "INFO" || info.get("info-package") != "g.3gpp.ussd" || info.get("to") != ok.get("to") {
			return fmt.Errorf("USSI continuation %#v %v", info, err)
		}
		if err = sendPeer(c, response(info, 200, "OK")); err != nil {
			return err
		}
		menu := &message{Start: "INFO sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
		menu.set("from", ok.get("to"))
		menu.set("to", invite.get("from"))
		menu.set("call-id", invite.get("call-id"))
		menu.set("cseq", "10 INFO")
		menu.set("via", "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKussd")
		menu.set("content-type", "application/vnd.3gpp.ussd+xml")
		menu.Body, _ = encodeUSSD("Balance 10")
		if err = sendPeer(c, menu); err != nil {
			return err
		}
		reply, err := readMessage(r)
		if err != nil || reply.status() != 200 {
			return fmt.Errorf("INFO receipt %v %v", reply, err)
		}
		bye, err := readMessage(r)
		if err != nil {
			return err
		}
		if bye.method() != "BYE" || bye.get("to") != ok.get("to") {
			return errors.New("wrong cancellation BYE")
		}
		if err = sendPeer(c, response(bye, 200, "OK")); err != nil {
			return err
		}
		_, _ = readMessage(r)
		return nil
	})
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	if err = s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first, err := s.SendUSSD(ctx, "*123#")
	if err != nil || first.Text != "1. Balance" || first.Done {
		t.Fatalf("first %#v %v", first, err)
	}
	next, err := s.ContinueUSSD(ctx, first.SessionID, "1")
	if err != nil || next.Text != "Balance 10" || next.Done {
		t.Fatalf("next %#v %v", next, err)
	}
	if err = s.CancelUSSD(ctx, first.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ContinueUSSD(ctx, first.SessionID, "1"); err == nil {
		t.Fatal("cancelled dialog still usable")
	}
}

func networkUSSDRequest(invite, answer *message, method, cseq string, content *message) *message {
	m := &message{Start: method + " sip:user@ims.test SIP/2.0", Headers: map[string][]string{}}
	m.set("from", answer.get("to"))
	m.set("to", invite.get("from"))
	m.set("call-id", invite.get("call-id"))
	m.set("cseq", cseq+" "+method)
	m.set("via", "SIP/2.0/TCP ims.test;branch=z9hG4bK"+cseq)
	m.set("content-type", content.get("content-type"))
	m.Body = content.Body
	return m
}

func TestUSSDMultipartDialogAndImmediateMenu(t *testing.T) {
	for _, initial := range []string{"multipart", "SDP then INFO"} {
		t.Run(initial, func(t *testing.T) {
			menu := ussdMultipart(t, []string{"application/sdp", "application/vnd.3gpp.ussd+xml; charset=utf-8"}, []string{
				"v=0\r\n", `<ussd-data xmlns="http://www.3gpp.org/ims/ussd/1.0"><ussd-string>1. 余额
2. 充值</ussd-string></ussd-data>`,
			})
			result := ussdMultipart(t, []string{"application/3gpp-ussd+xml"}, []string{
				`<ussd-data xmlns="application/vnd.3gpp.ussd+xml"><ussd-string>余额 10€</ussd-string></ussd-data>`,
			})
			cfg := configPeer(t, func(c net.Conn) error {
				r := bufio.NewReader(c)
				reg, err := peerRegister(r, c)
				if err != nil {
					return err
				}
				if err = sendPeer(c, response(reg, 200, "OK")); err != nil {
					return err
				}
				invite, err := readMessage(r)
				if err != nil {
					return err
				}
				answer := response(invite, 200, "OK")
				answer.set("to", invite.get("to")+";tag=menu-network")
				answer.set("contact", "<sip:menu@ims.test>")
				answer.add("record-route", "<sip:first.ims.test;lr>")
				answer.add("record-route", "<sip:second.ims.test;lr>")
				answer.set("content-type", menu.get("content-type"))
				answer.Body = menu.Body
				if initial == "SDP then INFO" {
					answer.set("content-type", "application/sdp")
					answer.Body = []byte("v=0\r\nm=audio 0 RTP/AVP 0\r\n")
				}
				wire, err := answer.bytes()
				if err != nil {
					return err
				}
				if initial == "SDP then INFO" {
					info, err := networkUSSDRequest(invite, answer, "INFO", "10", menu).bytes()
					if err != nil {
						return err
					}
					// Both arrive together: dialog identity must be learned by dispatch,
					// rather than relying on the SendUSSD goroutine being scheduled.
					wire = append(wire, info...)
				}
				if _, err = c.Write(wire); err != nil {
					return err
				}
				for ack, receipt := false, initial == "multipart"; !ack || !receipt; {
					m, err := readMessage(r)
					if err != nil {
						return err
					}
					switch {
					case m.method() == "ACK":
						if m.Start != "ACK sip:menu@ims.test SIP/2.0" || m.get("to") != answer.get("to") ||
							strings.Join(m.Headers["route"], ",") != "<sip:second.ims.test;lr>,<sip:first.ims.test;lr>" {
							return fmt.Errorf("wrong confirmed dialog ACK: %v", m)
						}
						ack = true
					case m.status() == 200 && m.get("cseq") == "10 INFO":
						receipt = true
					default:
						return fmt.Errorf("unexpected initial exchange: %s %s", m.Start, m.get("cseq"))
					}
				}
				info, err := readMessage(r)
				if err != nil {
					return err
				}
				text, present, err := decodeUSSDContent(info)
				if err != nil || !present || text != "1" || info.method() != "INFO" || info.get("to") != answer.get("to") ||
					info.get("content-disposition") != "render;handling=optional" || info.get("route") != "<sip:second.ims.test;lr>" {
					return fmt.Errorf("continuation: %v %q %v", info, text, err)
				}
				ok := response(info, 200, "OK")
				if initial == "multipart" {
					ok.set("content-type", result.get("content-type"))
					ok.Body = result.Body
				}
				if err = sendPeer(c, ok); err != nil {
					return err
				}
				if initial == "multipart" {
					bye, err := readMessage(r)
					if err != nil || bye.method() != "BYE" || bye.get("to") != answer.get("to") {
						return fmt.Errorf("cancel: %v %v", bye, err)
					}
					if err = sendPeer(c, response(bye, 200, "OK")); err != nil {
						return err
					}
				} else {
					bad := networkUSSDRequest(invite, answer, "INFO", "11", menu)
					bad.Body = []byte("--network-menu.boundary_42\r\nContent-Type: application/vnd.3gpp.ussd+xml\r\n\r\n<broken>")
					if err = sendPeer(c, bad); err != nil {
						return err
					}
					receipt, err := readMessage(r)
					if err != nil || receipt.status() != 400 {
						return fmt.Errorf("malformed menu receipt: %v %v", receipt, err)
					}
					if err = sendPeer(c, networkUSSDRequest(invite, answer, "BYE", "12", result)); err != nil {
						return err
					}
					receipt, err = readMessage(r)
					if err != nil || receipt.status() != 200 {
						return fmt.Errorf("final BYE receipt: %v %v", receipt, err)
					}
				}
				_, _ = readMessage(r)
				return nil
			})
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			if err = s.Start(ctx); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			first, err := s.SendUSSD(ctx, "*100#")
			if err != nil || first.Text != "1. 余额\n2. 充值" || first.SessionID == "" || first.Done {
				t.Fatalf("first = %+v, %v", first, err)
			}
			next, err := s.ContinueUSSD(ctx, first.SessionID, "1")
			if err != nil || next.Text != "余额 10€" || next.Done != (initial == "SDP then INFO") {
				t.Fatalf("next = %+v, %v", next, err)
			}
			if !next.Done {
				if err = s.CancelUSSD(ctx, first.SessionID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = s.ContinueUSSD(ctx, first.SessionID, "1"); err == nil {
				t.Fatal("closed dialog still reusable")
			}
		})
	}
}

func TestUSSDRejectedAndInvalidAnswersCleanUp(t *testing.T) {
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		reg, err := peerRegister(r, c)
		if err != nil {
			return err
		}
		if err = sendPeer(c, response(reg, 200, "OK")); err != nil {
			return err
		}
		for _, code := range []int{400, 200} {
			invite, err := readMessage(r)
			if err != nil || invite.method() != "INVITE" {
				return fmt.Errorf("INVITE: %v %v", invite, err)
			}
			answer := response(invite, code, "Test")
			answer.set("to", invite.get("to")+";tag=network")
			answer.set("contact", "<sip:ussd@ims.test>")
			if code == 200 {
				answer.set("content-type", "application/vnd.3gpp.ussd+xml")
				answer.Body = []byte(`<ussd-data xmlns="urn:invalid"><ussd-string>x</ussd-string></ussd-data>`)
			}
			if err = sendPeer(c, answer); err != nil {
				return err
			}
			ack, err := readMessage(r)
			if err != nil || ack.method() != "ACK" || code == 400 && ack.get("via") != invite.get("via") {
				return fmt.Errorf("ACK: %v %v", ack, err)
			}
			if code == 200 {
				bye, err := readMessage(r)
				if err != nil || bye.method() != "BYE" || bye.get("to") != answer.get("to") {
					return fmt.Errorf("invalid answer cleanup: %v %v", bye, err)
				}
				if err = sendPeer(c, response(bye, 200, "OK")); err != nil {
					return err
				}
			}
		}
		_, _ = readMessage(r)
		return nil
	})
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	if err = s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, want := range []string{"400", "namespace"} {
		if _, err = s.SendUSSD(ctx, "*100#"); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("send error = %v, want %s", err, want)
		}
		s.ussdMu.Lock()
		remaining := len(s.ussd)
		s.ussdMu.Unlock()
		if remaining != 0 {
			t.Fatalf("failed send left %d dialogs", remaining)
		}
	}
}
