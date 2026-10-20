package media

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestSRTPAuthenticationReplayAndRollover(t *testing.T) {
	a := &Session{}
	b := &Session{}
	var err error
	a.Local.Crypto, err = NewSDESCrypto()
	if err != nil {
		t.Fatal(err)
	}
	b.Local.Crypto, err = NewSDESCrypto()
	if err != nil {
		t.Fatal(err)
	}
	if err = a.configureProtection(Description{Crypto: b.Local.Crypto}); err != nil {
		t.Fatal(err)
	}
	if err = b.configureProtection(Description{Crypto: a.Local.Crypto}); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint16{65534, 65535, 0, 1} {
		raw := make([]byte, 16)
		raw[0] = 0x80
		binary.BigEndian.PutUint16(raw[2:], seq)
		binary.BigEndian.PutUint32(raw[8:], 42)
		encrypted, err := a.protection.send.EncryptRTP(nil, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		bad := bytes.Clone(encrypted)
		bad[len(bad)-1] ^= 1
		if _, err = b.unprotectPacket(bad, false); err == nil {
			t.Fatal("bad SRTP authentication accepted")
		}
		plain, err := b.unprotectPacket(encrypted, false)
		if err != nil || !bytes.Equal(plain, raw) {
			t.Fatal("SRTP rollover", seq, err)
		}
		if _, err = b.unprotectPacket(encrypted, false); err == nil {
			t.Fatal("SRTP replay accepted")
		}
	}
	report := []byte{0x80, 201, 0, 1, 0, 0, 0, 42}
	encrypted, err := a.protection.send.EncryptRTCP(nil, report, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := b.unprotectPacket(encrypted, true); err != nil || !bytes.Equal(plain, report) {
		t.Fatal("SRTCP", err)
	}
	if _, err = b.unprotectPacket(encrypted, true); err == nil {
		t.Fatal("SRTCP replay accepted")
	}
}
func TestAMRActualPacketRelay(t *testing.T) {
	// Relay encoded octet-aligned AMR frames; this does not test a transcoder.
	listen := func(_ context.Context, network, address string) (net.PacketConn, error) {
		return net.ListenPacket(network, address)
	}
	source, err := NewSession(t.Context(), listen, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := NewSession(t.Context(), listen, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	codecs, params, err := CodecOffer([]string{"AMR"})
	if err != nil {
		t.Fatal(err)
	}
	source.Local.Codecs, source.Local.Params = codecs, params
	target.Local.Codecs, target.Local.Params = codecs, params
	if err = source.SetRemote(target.Local); err != nil {
		t.Fatal(err)
	}
	if err = target.SetRemote(source.Local); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 45)
	packet[0] = 0x80
	packet[1] = 96
	packet[12] = 0xf0
	packet[13] = 0x3c
	if err = validateEncodedMedia(packet, codecs[0]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	got := make(chan []byte, 1)
	go target.ReadMedia(ctx, func(control bool, b []byte) error {
		if !control {
			got <- bytes.Clone(b)
			cancel()
		}
		return nil
	})
	if err = source.WriteMedia(ctx, false, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if !bytes.Equal(b, packet) {
			t.Fatal("AMR payload changed")
		}
	case <-ctx.Done():
		t.Fatal("AMR media missing")
	}
	packet = packet[:len(packet)-1]
	if err = validateEncodedMedia(packet, codecs[0]); err == nil {
		t.Fatal("truncated AMR frame accepted")
	}
}

func TestSRTPWireAndTelephoneEvents(t *testing.T) {
	listen := func(_ context.Context, network, address string) (net.PacketConn, error) {
		return net.ListenPacket(network, address)
	}
	a, err := NewSession(t.Context(), listen, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewSession(t.Context(), listen, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, s := range []*Session{a, b} {
		s.Local.Crypto, err = NewSDESCrypto()
		if err != nil {
			t.Fatal(err)
		}
		s.Local.Codecs, s.Local.Params = WithTelephoneEvents(s.Local.Codecs)
	}
	if err = a.SetRemote(b.Local); err != nil {
		t.Fatal(err)
	}
	if err = b.SetRemote(a.Local); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	packets := make(chan []byte, 16)
	done := make(chan error, 1)
	go func() {
		done <- b.ReadMedia(ctx, func(control bool, p []byte) error {
			if !control {
				packets <- bytes.Clone(p)
			}
			return nil
		})
	}()
	raw := make([]byte, 172)
	raw[0] = 0x80
	binary.BigEndian.PutUint32(raw[8:], 1)
	if err = a.WriteMedia(ctx, false, raw); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-packets:
		if !bytes.Equal(p, raw) {
			t.Fatal("wire SRTP decode mismatch")
		}
	case <-ctx.Done():
		t.Fatal("wire SRTP missing")
	}
	if err = a.WriteMedia(ctx, false, raw); err == nil {
		t.Fatal("outbound SRTP nonce reused")
	}
	if err = a.SendTelephoneEvent(ctx, '5', 40*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ended := 0
	var timestamp uint32
	var last uint16
	for n := 0; n < 4; n++ {
		select {
		case p := <-packets:
			if p[1]&127 != 101 || p[12] != 5 {
				t.Fatalf("wrong telephone event %x", p)
			}
			if n == 0 {
				timestamp = binary.BigEndian.Uint32(p[4:])
			} else if binary.BigEndian.Uint32(p[4:]) != timestamp || int16(binary.BigEndian.Uint16(p[2:])-last) <= 0 {
				t.Fatal("telephone event clock/sequence changed")
			}
			last = binary.BigEndian.Uint16(p[2:])
			if p[13]&128 != 0 {
				ended++
				if binary.BigEndian.Uint16(p[14:]) != 320 {
					t.Fatal("DTMF duration")
				}
			}
		case <-ctx.Done():
			t.Fatal("telephone event packets missing")
		}
	}
	if ended != 3 {
		t.Fatal("telephone event end retransmissions", ended)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("media readers leaked")
	}
}
