package ims

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	ussdContentType       = "application/vnd.3gpp.ussd+xml"
	ussdLegacyContentType = "application/3gpp-ussd+xml"
	ussdNamespace         = "http://www.3gpp.org/ims/ussd/1.0"
	ussdBoundary          = "vohive_ussd"
	ussdAccept            = "application/sdp, " + ussdContentType + ", " + ussdLegacyContentType + ", multipart/mixed"
)

var errUSSDContentType = errors.New("unsupported USSD content type")

type ussdDocument struct {
	XMLName   xml.Name `xml:"ussd-data"`
	Namespace string   `xml:"xmlns,attr,omitempty"`
	Language  string   `xml:"language,omitempty"`
	Text      string   `xml:"ussd-string"`
	ErrorCode string   `xml:"error-code,omitempty"`
}

func encodeUSSD(text string) ([]byte, error) {
	if len(text) > 4096 {
		return nil, errors.New("USSD text too long")
	}
	// Match the original USSI envelope; readers also accept the URI namespace.
	body, err := xml.Marshal(ussdDocument{Namespace: ussdContentType, Language: "en", Text: text})
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}
func decodeUSSD(b []byte) (string, error) {
	if len(b) > 65536 {
		return "", errors.New("USSD XML too large")
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	var doc ussdDocument
	if e := d.Decode(&doc); e != nil {
		return "", e
	}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if data, ok := tok.(xml.CharData); !ok || strings.TrimSpace(string(data)) != "" {
			return "", errors.New("trailing USSD XML content")
		}
	}
	if doc.XMLName.Local != "ussd-data" || doc.XMLName.Space != "" && doc.XMLName.Space != ussdNamespace && doc.XMLName.Space != ussdContentType {
		return "", errors.New("invalid USSD XML namespace")
	}
	if doc.ErrorCode != "" {
		return "", fmt.Errorf("USSD remote error %s", doc.ErrorCode)
	}
	if len(doc.Text) > 4096 {
		return "", errors.New("USSD response too long")
	}
	return doc.Text, nil
}

// decodeUSSDContent distinguishes an SDP-only answer (the menu follows in INFO)
// from a USSD document, including a deliberately empty ussd-string.
func decodeUSSDContent(m *message) (string, bool, error) {
	if len(m.Body) > maxMessage {
		return "", false, errors.New("USSD body too large")
	}
	mediaType, params, err := mime.ParseMediaType(m.get("content-type"))
	if err != nil {
		return "", false, fmt.Errorf("%w: %v", errUSSDContentType, err)
	}
	body := m.Body
	switch mediaType {
	case ussdContentType, ussdLegacyContentType:
	case "application/sdp":
		return "", false, nil
	case "multipart/mixed":
		if params["boundary"] == "" {
			return "", false, errors.New("USSD multipart boundary missing")
		}
		reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		body = nil
		hasSDP := false
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", false, fmt.Errorf("USSD multipart: %w", err)
			}
			kind, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if err != nil {
				return "", false, fmt.Errorf("USSD MIME part: %w", err)
			}
			if kind != ussdContentType && kind != ussdLegacyContentType {
				hasSDP = hasSDP || kind == "application/sdp"
				continue
			}
			if body != nil {
				return "", false, errors.New("multiple USSD XML parts")
			}
			body, err = io.ReadAll(io.LimitReader(part, 65537))
			if err != nil {
				return "", false, fmt.Errorf("USSD MIME part: %w", err)
			}
			if len(body) > 65536 {
				return "", false, errors.New("USSD XML too large")
			}
		}
		if body == nil {
			if !hasSDP {
				return "", false, errUSSDContentType
			}
			return "", false, nil
		}
	default:
		return "", false, errUSSDContentType
	}
	text, err := decodeUSSD(body)
	return text, true, err
}

func (s *Service) ussdHeaders(m *message) {
	m.set("p-preferred-identity", "<"+sipURI(s.cfg.PublicIdentity)+">")
	m.set("accept", ussdAccept)
	if pani := s.cfg.RegisterHeaders["p-access-network-info"]; pani != "" {
		m.set("p-access-network-info", pani)
	}
	if m.get("security-verify") != "" {
		m.set("require", "sec-agree")
		m.set("proxy-require", "sec-agree")
		m.set("supported", "sec-agree")
	}
}

func (s *Service) ussdInvite(code, id string) (*message, error) {
	body, err := encodeUSSD(code)
	if err != nil {
		return nil, err
	}
	domain := s.cfg.Realm
	if _, host, ok := strings.Cut(sipURI(s.cfg.PublicIdentity), "@"); ok {
		domain = host
	}
	// SIP dialstrings keep '*'; delimiters in user input must not change the URI.
	user := strings.NewReplacer("%2A", "*", "@", "%40", ":", "%3A").Replace(url.PathEscape(code))
	uri := "sip:" + user + ";phone-context=" + domain + "@" + domain + ";user=dialstring"
	m := s.request("INVITE", uri, id)
	s.ussdHeaders(m)
	m.set("content-type", `multipart/mixed;boundary="`+ussdBoundary+`"`)
	m.set("recv-info", "g.3gpp.ussd")
	m.set("allow", "INVITE, ACK, CANCEL, BYE, MESSAGE, INFO, OPTIONS")
	m.set("p-preferred-service", "urn:urn-7:3gpp-service.ims.icsi.mmtel")
	m.set("accept-contact", `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";audio`)
	// Do not advertise 100rel, video, SRVCC or network-initiated USSI here:
	// the established mobile-originated USSD dialog does not implement them.
	address := s.cfg.LocalAddress
	if address == "" {
		if local := s.LocalAddress(); local != nil {
			address, _, _ = net.SplitHostPort(local.String())
		}
	}
	ip := net.ParseIP(strings.Trim(address, "[]"))
	if ip == nil {
		return nil, errors.New("USSD requires a local IP address")
	}
	family := "IP4"
	if ip.To4() == nil {
		family = "IP6"
	}
	stamp := time.Now().UnixMilli()
	sdp := fmt.Sprintf("v=0\r\no=- %d %d IN %s %s\r\ns=-\r\nc=IN %s %s\r\nt=0 0\r\n",
		stamp, stamp, family, ip, family, ip) + ussdAudioSDP
	m.Body = []byte("--" + ussdBoundary + "\r\nContent-Type: application/sdp\r\n\r\n" + sdp +
		"\r\n--" + ussdBoundary + "\r\nContent-Type: " + ussdContentType +
		"\r\nContent-Disposition: render;handling=optional\r\n\r\n" + string(body) +
		"\r\n--" + ussdBoundary + "--\r\n")
	return m, nil
}

// The original USSI SDP rejects the audio stream (port 0); no media is opened.
const ussdAudioSDP = "m=audio 0 RTP/AVP 106 112 104 110 102 108 96 97\r\n" +
	"b=AS:153\r\nb=RS:600\r\nb=RR:2000\r\n" +
	"a=rtpmap:106 EVS/16000/1\r\na=fmtp:106 br=5.9-24.4;bw=nb-wb;ch-aw-recv=-1;max-red=0\r\n" +
	"a=rtpmap:112 EVS/16000/1\r\na=fmtp:112 br=9.6-128;bw=swb;ch-aw-recv=-1;max-red=0\r\n" +
	"a=rtpmap:104 AMR-WB/16000/1\r\na=fmtp:104 mode-change-capability=2;max-red=0\r\n" +
	"a=rtpmap:110 AMR-WB/16000/1\r\na=fmtp:110 octet-align=1;mode-change-capability=2;max-red=0\r\n" +
	"a=rtpmap:102 AMR/8000/1\r\na=fmtp:102 mode-change-capability=2;max-red=0\r\n" +
	"a=rtpmap:108 AMR/8000/1\r\na=fmtp:108 octet-align=1;mode-change-capability=2;max-red=0\r\n" +
	"a=rtpmap:96 telephone-event/16000\r\na=fmtp:96 0-15\r\n" +
	"a=rtpmap:97 telephone-event/8000\r\na=fmtp:97 0-15\r\n" +
	"a=sendrecv\r\na=maxptime:240\r\na=ptime:20\r\n"
