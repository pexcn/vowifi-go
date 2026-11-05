package ims

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
)

// Network fixtures deliberately use a boundary different from the sender's.
func ussdMultipart(t *testing.T, types, bodies []string) *message {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	if err := w.SetBoundary("network-menu.boundary_42"); err != nil {
		t.Fatal(err)
	}
	for i, kind := range types {
		part, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {kind}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, bodies[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &message{Headers: map[string][]string{"content-type": {`Multipart/Mixed; boundary="network-menu.boundary_42"`}}, Body: b.Bytes()}
}

func TestUSSDContentFormatsAndLimits(t *testing.T) {
	standard := `<ussd-data xmlns="http://www.3gpp.org/ims/ussd/1.0"><ussd-string>余额 &amp; 菜单</ussd-string></ussd-data>`
	original := `<ussd-data xmlns="application/vnd.3gpp.ussd+xml"><ussd-string>余额 &amp; 菜单</ussd-string></ussd-data>`
	plain := func(kind, body string) *message {
		return &message{Headers: map[string][]string{"content-type": {kind}}, Body: []byte(body)}
	}
	mixed := ussdMultipart(t, []string{"application/sdp", ussdLegacyContentType, "text/plain"}, []string{"v=0\r\n", original, "other part"})
	truncated := ussdMultipart(t, []string{ussdContentType}, []string{original})
	truncated.Body = truncated.Body[:len(truncated.Body)-8]
	for _, tt := range []struct {
		name    string
		m       *message
		text    string
		present bool
		bad     bool
	}{
		{"URI namespace", plain(ussdContentType+"; charset=utf-8", standard), "余额 & 菜单", true, false},
		{"original namespace", plain(ussdContentType, original), "余额 & 菜单", true, false},
		{"legacy media type", plain(ussdLegacyContentType, original), "余额 & 菜单", true, false},
		{"no namespace", plain(ussdContentType, `<ussd-data><ussd-string>1</ussd-string></ussd-data>`), "1", true, false},
		{"empty string is a result", plain(ussdContentType, `<ussd-data><ussd-string/></ussd-data>`), "", true, false},
		{"multipart", mixed, "余额 & 菜单", true, false},
		{"SDP answer", plain("application/sdp", "v=0\r\n"), "", false, false},
		{"multipart SDP answer", ussdMultipart(t, []string{"application/sdp"}, []string{"v=0\r\n"}), "", false, false},
		{"unknown media type", plain("text/plain", original), "", false, true},
		{"invalid media type", plain("multipart/mixed; boundary=\"", original), "", false, true},
		{"missing boundary", plain("multipart/mixed", original), "", false, true},
		{"truncated multipart", truncated, "", false, true},
		{"duplicate XML", ussdMultipart(t, []string{ussdContentType, ussdContentType}, []string{original, original}), "", false, true},
		{"unknown parts only", ussdMultipart(t, []string{"text/plain"}, []string{original}), "", false, true},
		{"invalid namespace", plain(ussdContentType, strings.ReplaceAll(standard, ussdNamespace, "urn:other")), "", false, true},
		{"trailing XML", plain(ussdContentType, original+original), "", false, true},
		{"oversize XML", plain(ussdContentType, strings.Repeat(" ", 65537)), "", false, true},
		{"oversize XML part", ussdMultipart(t, []string{ussdContentType}, []string{strings.Repeat(" ", 65537)}), "", false, true},
		{"oversize envelope", plain("multipart/mixed; boundary=x", strings.Repeat(" ", maxMessage+1)), "", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			text, present, err := decodeUSSDContent(tt.m)
			if (err != nil) != tt.bad || !tt.bad && (text != tt.text || present != tt.present) {
				t.Fatalf("content = %q, %t, %v", text, present, err)
			}
		})
	}
}

func TestUSSDInviteWireAndBodyAuthentication(t *testing.T) {
	for _, address := range []string{"192.0.2.10", "2001:db8::10"} {
		t.Run(address, func(t *testing.T) {
			s := &Service{
				cfg: Config{PublicIdentity: "sip:+15550100@ims.test", Realm: "auth.test", Transport: "tcp", LocalAddress: address,
					RegisterHeaders: map[string]string{"p-access-network-info": "IEEE-802.11"}},
				contact: `<sip:user@192.0.2.10:5062;transport=tcp>;+sip.instance="<urn:uuid:fixture>";audio`,
				routes:  []string{"<sip:proxy.ims.test;lr>"}, securityVerify: "ipsec-3gpp;alg=hmac-sha-1-96",
				auth:     challenge{Realm: "auth.test", Nonce: "fixed-nonce", Algorithm: "MD5", QOP: "auth-int"},
				authName: "authorization", password: []byte("binary-res"),
			}
			m, err := s.ussdInvite("*100#", "ussd-call")
			if err != nil {
				t.Fatal(err)
			}
			if err = s.authorize(m); err != nil {
				t.Fatal(err)
			}
			wire, err := m.bytes()
			if err != nil {
				t.Fatal(err)
			}
			m, err = readMessage(bufio.NewReader(bytes.NewReader(wire)))
			if err != nil {
				t.Fatal(err)
			}
			uri := "sip:*100%23;phone-context=ims.test@ims.test;user=dialstring"
			if m.Start != "INVITE "+uri+" SIP/2.0" || m.get("to") != "<"+uri+">" {
				t.Fatalf("dialstring = %s, To=%s", m.Start, m.get("to"))
			}
			for k, want := range map[string]string{
				"p-preferred-identity": "<sip:+15550100@ims.test>", "p-access-network-info": "IEEE-802.11",
				"p-preferred-service": "urn:urn-7:3gpp-service.ims.icsi.mmtel", "recv-info": "g.3gpp.ussd",
				"security-verify": s.securityVerify, "require": "sec-agree", "proxy-require": "sec-agree",
				"contact": s.contact, "route": s.routes[0], "content-length": strconv.Itoa(len(m.Body)),
			} {
				if m.get(k) != want {
					t.Errorf("%s = %q, want %q", k, m.get(k), want)
				}
			}
			if !strings.Contains(m.get("accept-contact"), "icsi.mmtel") || strings.Contains(m.get("supported"), "100rel") {
				t.Fatalf("service capabilities: %v", m.Headers)
			}
			mediaType, params, err := mime.ParseMediaType(m.get("content-type"))
			if err != nil || mediaType != "multipart/mixed" {
				t.Fatalf("MIME: %q, %v", mediaType, err)
			}
			reader := multipart.NewReader(bytes.NewReader(m.Body), params["boundary"])
			sdp, err := reader.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			sdpBody, err := io.ReadAll(sdp)
			if err != nil {
				t.Fatal(err)
			}
			family := "IP4"
			if strings.Contains(address, ":") {
				family = "IP6"
			}
			if sdp.Header.Get("Content-Type") != "application/sdp" || !strings.Contains(string(sdpBody), "c=IN "+family+" "+address+"\r\n") ||
				!strings.Contains(string(sdpBody), "m=audio 0 RTP/AVP 106 112 104 110 102 108 96 97\r\n") {
				t.Fatalf("SDP offer = %q", sdpBody)
			}
			xmlPart, err := reader.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			xmlBody, err := io.ReadAll(xmlPart)
			if err != nil {
				t.Fatal(err)
			}
			wantXML := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
				`<ussd-data xmlns="application/vnd.3gpp.ussd+xml"><language>en</language><ussd-string>*100#</ussd-string></ussd-data>`
			if xmlPart.Header.Get("Content-Type") != "application/vnd.3gpp.ussd+xml" ||
				xmlPart.Header.Get("Content-Disposition") != "render;handling=optional" || string(xmlBody) != wantXML {
				t.Fatalf("XML part: %v, %q", xmlPart.Header, xmlBody)
			}
			if _, err = reader.NextPart(); err != io.EOF {
				t.Fatalf("MIME end = %v", err)
			}
			// Check Digest against the serialized multipart body, not just its XML.
			p, err := parameters(strings.TrimPrefix(m.get("authorization"), "Digest "), ',')
			if err != nil {
				t.Fatal(err)
			}
			h := func(v string) string { return fmt.Sprintf("%x", md5.Sum([]byte(v))) }
			ha1 := h(p["username"] + ":auth.test:binary-res")
			ha2 := h("INVITE:" + uri + ":" + h(string(m.Body)))
			want := h(ha1 + ":fixed-nonce:" + p["nc"] + ":" + p["cnonce"] + ":auth-int:" + ha2)
			if p["uri"] != uri || p["qop"] != "auth-int" || p["response"] != want {
				t.Fatalf("multipart authentication = %v", p)
			}
		})
	}
}
