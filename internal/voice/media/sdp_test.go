package media

import (
	"net"
	"strings"
	"testing"
)

func TestSDPRoundTripAndCodecNegotiation(t *testing.T) {
	d := Description{Address: net.ParseIP("2001:db8::1"), RTP: 4000, RTCP: 4003, Codecs: []Codec{{0, "PCMU", 8000, 1}, {8, "PCMA", 8000, 1}}, Direction: "sendrecv"}
	b, e := d.SDP()
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseSDP(b)
	if e != nil || !got.Address.Equal(d.Address) || got.RTP != 4000 || got.RTCP != 4003 || len(got.Codecs) != 2 {
		t.Fatalf("round trip %#v %v", got, e)
	}
	_, r, e := MatchCodec(d.Codecs, []Codec{{96, "pcma", 8000, 1}})
	if e != nil || r.Payload != 96 {
		t.Fatalf("match %#v %v", r, e)
	}
	if _, _, e = MatchCodec(d.Codecs, []Codec{{96, "AMR", 8000, 1}}); e == nil {
		t.Fatal("claimed nonexistent AMR transcoder")
	}
}
func TestRejectUnsupportedOrMalformedSDP(t *testing.T) {
	base := "v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 5000 RTP/AVP 0\r\n"
	for _, b := range []string{strings.Replace(base, "RTP/AVP", "RTP/SAVP", 1), strings.Replace(base, "5000", "0", 1), strings.Replace(base, "192.0.2.2", "224.0.0.1", 1), base + "a=rtcp-mux\r\n", base + "a=rtcp:5001 IN IP4 192.0.2.3\r\n", base + "a=rtpmap:0 PCMU/invalid\r\n"} {
		if _, e := ParseSDP([]byte(b)); e == nil {
			t.Fatalf("accepted invalid/unsupported SDP %q", b)
		}
	}
}

func TestSDPSessionDirectionAndStaticPayload(t *testing.T) {
	sdp := "v=0\r\nc=IN IP4 192.0.2.2\r\na=recvonly\r\nm=audio 5000 RTP/AVP 0\r\n"
	d, e := ParseSDP([]byte(sdp))
	if e != nil || d.Direction != "recvonly" {
		t.Fatalf("session direction %#v %v", d, e)
	}
	for _, bad := range []string{strings.Replace(sdp, "IP4 192.0.2.2", "IP6 192.0.2.2", 1), sdp + "a=rtpmap:0 AMR/8000\r\n", sdp + "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:secret\r\n"} {
		if _, e := ParseSDP([]byte(bad)); e == nil {
			t.Fatalf("accepted unsupported SDP %q", bad)
		}
	}
}
