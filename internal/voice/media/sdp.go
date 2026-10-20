// Package media implements RTP inside an authenticated IMS tunnel. It relays
// matching codecs and never advertises a transcoder.
package media

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Codec struct {
	Payload  uint8
	Name     string
	Rate     int
	Channels int
}
type Description struct {
	Address   net.IP
	RTP, RTCP int
	Codecs    []Codec
	Direction string
	Crypto    *SDESCrypto
	Params    map[uint8]string
}

func ParseSDP(b []byte) (Description, error) {
	var d Description
	var err error
	d.Direction = "sendrecv"
	d.Params = make(map[uint8]string)
	secure := false
	var sessionIP net.IP
	sessionDirection := "sendrecv"
	audio := false
	seen := false
	payloads := map[int]bool{}
	codecs := map[int]Codec{}
	if len(b) > 65536 {
		return d, errors.New("SDP too large")
	}
	for _, raw := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "m=") {
			f := strings.Fields(line[2:])
			if len(f) < 4 {
				return d, errors.New("invalid SDP media")
			}
			audio = f[0] == "audio" && !seen
			if !audio {
				continue
			}
			seen = true
			secure = f[2] == "RTP/SAVP"
			if f[2] != "RTP/AVP" && !secure {
				return d, errors.New("unsupported secure or non-AVP RTP profile")
			}
			n, e := strconv.Atoi(f[1])
			if e != nil || n <= 0 || n > 65534 {
				return d, errors.New("invalid SDP audio port")
			}
			d.RTP = n
			d.RTCP = n + 1
			d.Address = sessionIP
			d.Direction = sessionDirection
			for _, v := range f[3:] {
				p, e := strconv.Atoi(v)
				if e != nil || p < 0 || p > 127 {
					return d, errors.New("invalid SDP payload")
				}
				payloads[p] = true
				switch p {
				case 0:
					codecs[p] = Codec{0, "PCMU", 8000, 1}
				case 8:
					codecs[p] = Codec{8, "PCMA", 8000, 1}
				}
			}
			continue
		}
		if strings.HasPrefix(line, "c=") {
			f := strings.Fields(line[2:])
			if len(f) != 3 || f[0] != "IN" || f[1] != "IP4" && f[1] != "IP6" {
				return d, errors.New("invalid SDP connection")
			}
			ip := net.ParseIP(f[2])
			if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || (f[1] == "IP4") != (ip.To4() != nil) {
				return d, errors.New("unsupported SDP address")
			}
			if !seen {
				sessionIP = ip
			} else if audio {
				d.Address = ip
			}
			continue
		}
		if !seen {
			switch line {
			case "a=sendonly", "a=recvonly", "a=inactive", "a=sendrecv":
				sessionDirection = strings.TrimPrefix(line, "a=")
			}
		}
		if !audio {
			continue
		}
		if strings.HasPrefix(line, "a=fingerprint:") {
			return d, errors.New("DTLS media unsupported")
		}
		if strings.HasPrefix(line, "a=crypto:") {
			if !secure || d.Crypto != nil {
				return d, errors.New("unexpected or multiple SDES attributes")
			}
			d.Crypto, err = parseSDESCrypto(strings.TrimPrefix(line, "a=crypto:"))
			if err != nil {
				return d, err
			}
		}
		if strings.HasPrefix(line, "a=fmtp:") {
			v := strings.Fields(strings.TrimPrefix(line, "a=fmtp:"))
			if len(v) < 2 {
				return d, errors.New("invalid codec parameters")
			}
			payload, err := strconv.ParseUint(v[0], 10, 7)
			if err != nil {
				return d, err
			}
			if _, ok := d.Params[uint8(payload)]; ok {
				return d, errors.New("duplicate codec parameters")
			}
			d.Params[uint8(payload)] = strings.Join(v[1:], " ")
		}

		if strings.HasPrefix(line, "a=rtpmap:") {
			f := strings.Fields(strings.TrimPrefix(line, "a=rtpmap:"))
			if len(f) != 2 {
				return d, errors.New("invalid SDP rtpmap")
			}
			p, e := strconv.Atoi(f[0])
			parts := strings.Split(f[1], "/")
			if e != nil || len(parts) < 2 || len(parts) > 3 {
				return d, errors.New("invalid SDP codec")
			}
			rate, e := strconv.Atoi(parts[1])
			if e != nil || rate <= 0 {
				return d, errors.New("invalid SDP clock")
			}
			channels := 1
			if len(parts) == 3 {
				channels, e = strconv.Atoi(parts[2])
				if e != nil || channels < 1 {
					return d, errors.New("invalid SDP channels")
				}
			}
			if p < 0 || p > 127 {
				return d, errors.New("invalid SDP codec payload")
			}
			if payloads[p] {
				mapped := Codec{uint8(p), strings.ToUpper(parts[0]), rate, channels}
				if (p == 0 && mapped.Name != "PCMU" || p == 8 && mapped.Name != "PCMA") || ((p == 0 || p == 8) && (rate != 8000 || channels != 1)) {
					return d, errors.New("invalid static RTP codec mapping")
				}
				codecs[p] = mapped
			}
		}
		if strings.HasPrefix(line, "a=rtcp:") {
			f := strings.Fields(strings.TrimPrefix(line, "a=rtcp:"))
			if len(f) != 1 && len(f) != 4 {
				return d, errors.New("invalid RTCP address")
			}
			p, e := strconv.Atoi(f[0])
			if e != nil || p <= 0 || p > 65535 {
				return d, errors.New("invalid RTCP port")
			}
			if len(f) == 4 && (f[1] != "IN" || net.ParseIP(f[3]) == nil || !net.ParseIP(f[3]).Equal(d.Address)) {
				return d, errors.New("separate RTCP address unsupported")
			}
			d.RTCP = p
		}
		switch line {
		case "a=sendonly", "a=recvonly", "a=inactive", "a=sendrecv":
			d.Direction = strings.TrimPrefix(line, "a=")
		case "a=rtcp-mux":
			return d, errors.New("RTCP multiplexing unsupported")
		}
	}
	if secure && d.Crypto == nil {
		return d, errors.New("SRTP profile requires SDES keys")
	}
	if !seen || d.Address == nil {
		return d, errors.New("SDP has no usable audio connection")
	}
	for p := 0; p < 128; p++ {
		if c, ok := codecs[p]; ok {
			d.Codecs = append(d.Codecs, c)
		}
	}
	if len(d.Codecs) == 0 {
		return d, errors.New("SDP has no supported codecs")
	}
	return d, nil
}
func (d Description) SDP() ([]byte, error) {
	if d.Address == nil || d.Address.IsUnspecified() || d.RTP <= 0 || d.RTCP <= 0 || len(d.Codecs) == 0 {
		return nil, errors.New("incomplete local media")
	}
	family := "IP4"
	if d.Address.To4() == nil {
		family = "IP6"
	}
	var ps []string
	for _, c := range d.Codecs {
		ps = append(ps, strconv.Itoa(int(c.Payload)))
	}
	profile := "RTP/AVP"
	if d.Crypto != nil {
		profile = "RTP/SAVP"
	}
	text := fmt.Sprintf("v=0\r\no=- 1 1 IN %s %s\r\ns=VoWiFi\r\nc=IN %s %s\r\nt=0 0\r\nm=audio %d %s %s\r\na=rtcp:%d\r\n", family, d.Address, family, d.Address, d.RTP, profile, strings.Join(ps, " "), d.RTCP)
	for _, c := range d.Codecs {
		text += fmt.Sprintf("a=rtpmap:%d %s/%d", c.Payload, c.Name, c.Rate)
		if c.Channels > 1 {
			text += fmt.Sprintf("/%d", c.Channels)
		}
		text += "\r\n"
	}
	for payload, params := range d.Params {
		if strings.ContainsAny(params, "\r\n") {
			return nil, errors.New("invalid SDP parameters")
		}
		text += fmt.Sprintf("a=fmtp:%d %s\r\n", payload, params)
	}
	if d.Crypto != nil {
		text += d.Crypto.attribute() + "\r\n"
	}
	direction := d.Direction
	if direction == "" {
		direction = "sendrecv"
	}
	text += "a=" + direction + "\r\n"
	return []byte(text), nil
}
func MatchCodec(a, b []Codec) (Codec, Codec, error) {
	for _, l := range a {
		for _, r := range b {
			if strings.EqualFold(l.Name, r.Name) && l.Rate == r.Rate && l.Channels == r.Channels {
				return l, r, nil
			}
		}
	}
	return Codec{}, Codec{}, errors.New("no common audio codec")
}
