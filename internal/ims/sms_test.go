package ims

import (
	"strings"
	"testing"
	"time"

	smscodec "github.com/warthog618/sms"
)

func TestRPCodecRejectsMalformed(t *testing.T) {
	for _, b := range [][]byte{{}, {1}, {1, 1, 255}, {1, 1, 0, 0, 5, 1}, {3, 1, 0x41, 2, 1}, {5, 1, 0}, {9, 1}, {3, 1, 1}, {1, 1, 0, 0, 0, 5}} {
		if _, e := parseRP(b); e == nil {
			t.Fatalf("accepted malformed RPDU %x", b)
		}
	}
	b, e := rpData(3, []byte{0x91, 0x21}, []byte{1, 2, 3})
	if e != nil {
		t.Fatal(e)
	}
	m, e := parseRP(b)
	if e != nil || m.Reference != 3 || string(m.UserData) != string([]byte{1, 2, 3}) {
		t.Fatalf("RP roundtrip %#v %v", m, e)
	}
}
func TestConcatOutOfOrderAndUnicode(t *testing.T) {
	text := strings.Repeat("你好世界", 60)
	parts, e := smscodec.Encode([]byte(text), smscodec.AsDeliver, smscodec.From("+15550100"))
	if e != nil || len(parts) < 2 {
		t.Fatalf("encode %d %v", len(parts), e)
	}
	var got []string
	s := &Service{cfg: Config{OnSMS: func(_, v string, _ time.Time) { got = append(got, v) }}, concats: make(map[string]*concatMessage)}
	for i := len(parts) - 1; i >= 0; i-- {
		s.deliverTPDU(&parts[i])
		if i > 0 && len(got) != 0 {
			t.Fatal("incomplete multipart delivered")
		}
	}
	if len(got) != 1 || got[0] != text {
		t.Fatalf("reassembled %#v", got)
	}
}

func TestRPReportCannotConsumeDifferentSubmission(t *testing.T) {
	var reports []Report
	s := &Service{cfg: Config{OnReport: func(r Report) { reports = append(reports, r) }}, serverResponses: map[string]cachedResponse{}, smsPending: map[byte]smsReference{7: {CallID: "current-submit", At: time.Now()}}}
	m := &message{Start: "MESSAGE sip:user@ims.test SIP/2.0", Headers: map[string][]string{}, Body: []byte{3, 7}}
	m.set("content-type", "application/vnd.3gpp.sms")
	m.set("in-reply-to", "stale-submit")
	s.receiveSMS(m)
	if len(reports) != 0 || len(s.smsPending) != 1 {
		t.Fatal("stale report consumed active reference")
	}
	m.set("in-reply-to", "current-submit")
	s.receiveSMS(m)
	if len(reports) != 1 || reports[0].State != "acked" || reports[0].CallID != "current-submit" || len(s.smsPending) != 0 {
		t.Fatalf("real RP-ACK %#v", reports)
	}
	s.receiveSMS(m)
	if len(reports) != 1 {
		t.Fatal("duplicate report emitted")
	}
}
