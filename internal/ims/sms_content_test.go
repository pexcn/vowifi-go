package ims

import (
	"bytes"
	"encoding/base64"
	smscodec "github.com/warthog618/sms"
	"github.com/warthog618/sms/encoding/tpdu"
	"strings"
	"testing"
)

func TestSMSEnvelopesAndOpaqueBinary(t *testing.T) {
	raw := []byte{1, 7, 0, 0, 1, 0xff}
	encoded := base64.StdEncoding.EncodeToString(raw)
	for _, multipart := range []bool{false, true} {
		m := &message{Headers: map[string][]string{}}
		if !multipart {
			m.set("content-type", "application/vnd.3gpp.sms")
			m.set("content-transfer-encoding", "base64")
			m.Body = []byte(encoded)
		} else {
			m.set("content-type", "multipart/mixed; boundary=fixture")
			m.Body = []byte("--fixture\r\nContent-Type: application/vnd.3gpp.sms\r\nContent-Transfer-Encoding: base64\r\n\r\n" + encoded + "\r\n--fixture--\r\n")
		}
		got, err := smsBody(m)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("SMS envelope: %x %v", got, err)
		}
	}
	m := &message{Headers: map[string][]string{}}
	m.set("content-type", "multipart/mixed; boundary=x")
	m.Body = []byte("--x\r\nContent-Type: application/vnd.3gpp.sms\r\n\r\na\r\n--x\r\nContent-Type: application/vnd.3gpp.sms\r\n\r\nb\r\n--x--\r\n")
	if _, err := smsBody(m); err == nil {
		t.Fatal("ambiguous envelope accepted")
	}
	parts, err := smscodec.Encode([]byte{0, 0xff, 0x80}, smscodec.To("10086"), smscodec.As8Bit)
	if err != nil {
		t.Fatal(err)
	}
	parts[0].PID = 0x7f
	text, err := decodeInboundParts([]*tpdu.TPDU{&parts[0]})
	if err != nil || !strings.Contains(string(text), "00ff80") || !strings.Contains(string(text), "decrypt=not_attempted") {
		t.Fatalf("opaque binary SMS: %s %v", text, err)
	}
}
