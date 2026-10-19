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
		if invite.method() != "INVITE" || !isUSSD(invite) {
			return errors.New("expected USSI INVITE")
		}
		text, err := decodeUSSD(invite.Body)
		if err != nil || text != "*123#" {
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
