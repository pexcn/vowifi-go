package ims

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type DialContextFunc func(context.Context, string, string) (net.Conn, error)
type SecurityParameters struct {
	Algorithm, Encryption  string
	SPIClient, SPIServer   uint32
	PortClient, PortServer uint16
}
type SecurityAgreement struct {
	Client, Server SecurityParameters
	CK, IK         []byte
	RemoteAddress  string
}

var ErrUnsupportedSecurity = errors.New("IMS security agreement unsupported")

func (p SecurityParameters) header() string {
	return fmt.Sprintf("ipsec-3gpp;alg=%s;ealg=%s;prot=esp;mod=trans;spi-c=%d;spi-s=%d;port-c=%d;port-s=%d", p.Algorithm, p.Encryption, p.SPIClient, p.SPIServer, p.PortClient, p.PortServer)
}
func parseSecurity(s string) (SecurityParameters, error) {
	ps, e := splitQuoted(s, ';')
	if e != nil || len(ps) < 2 || !strings.EqualFold(ps[0], "ipsec-3gpp") {
		return SecurityParameters{}, ErrUnsupportedSecurity
	}
	m, e := parameters(strings.Join(ps[1:], ";"), ';')
	if e != nil {
		return SecurityParameters{}, e
	}
	p := SecurityParameters{Algorithm: m["alg"], Encryption: m["ealg"]}
	if m["prot"] != "" && m["prot"] != "esp" || m["mod"] != "" && m["mod"] != "trans" {
		return p, ErrUnsupportedSecurity
	}
	if p.Algorithm != "hmac-sha-1-96" && p.Algorithm != "hmac-md5-96" {
		return p, ErrUnsupportedSecurity
	}
	if p.Encryption != "null" && p.Encryption != "aes-cbc" {
		return p, ErrUnsupportedSecurity
	}
	for _, v := range []struct {
		k    string
		bits int
		dst  *uint32
	}{{"spi-c", 32, &p.SPIClient}, {"spi-s", 32, &p.SPIServer}} {
		n, e := strconv.ParseUint(m[v.k], 10, v.bits)
		if e != nil || n == 0 {
			return p, errors.New("invalid Security-Server SPI")
		}
		*v.dst = uint32(n)
	}
	pc, e := strconv.ParseUint(m["port-c"], 10, 16)
	if e != nil || pc == 0 {
		return p, errors.New("invalid Security-Server client port")
	}
	psv, e := strconv.ParseUint(m["port-s"], 10, 16)
	if e != nil || psv == 0 {
		return p, errors.New("invalid Security-Server server port")
	}
	p.PortClient = uint16(pc)
	p.PortServer = uint16(psv)
	return p, nil
}

// selectSecurity chooses only mechanisms actually offered by this endpoint.
// Security-Verify still carries the complete original server list (RFC 3329).
func selectSecurity(raw string, offered SecurityParameters) (SecurityParameters, error) {
	alternatives, err := splitQuoted(raw, ',')
	if err != nil {
		return SecurityParameters{}, err
	}
	var selected SecurityParameters
	best := -1.0
	for _, alternative := range alternatives {
		p, err := parseSecurity(strings.TrimSpace(alternative))
		if err != nil {
			continue
		}
		if p.Algorithm != offered.Algorithm || p.Encryption != offered.Encryption {
			continue
		}
		fields, err := splitQuoted(alternative, ';')
		if err != nil {
			continue
		}
		params, err := parameters(strings.Join(fields[1:], ";"), ';')
		if err != nil {
			continue
		}
		q := 1.0
		if rawq, ok := params["q"]; ok {
			q, err = strconv.ParseFloat(rawq, 64)
			if err != nil || q < 0 || q > 1 {
				continue
			}
		}
		if q > best {
			selected, best = p, q
		}
	}
	if best < 0 {
		return SecurityParameters{}, ErrUnsupportedSecurity
	}
	return selected, nil
}
