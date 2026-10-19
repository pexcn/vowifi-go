package ims

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/pexcn/vowifi-go/engine/sim"
)

type challenge struct{ Realm, Nonce, Algorithm, QOP, Opaque string }

func parseChallenge(s string) (challenge, error) {
	if len(s) < 7 || !strings.EqualFold(s[:7], "Digest ") {
		return challenge{}, errors.New("unsupported SIP authentication scheme")
	}
	p, e := parameters(s[7:], ',')
	if e != nil {
		return challenge{}, e
	}
	c := challenge{p["realm"], p["nonce"], p["algorithm"], p["qop"], p["opaque"]}
	if c.Realm == "" || c.Nonce == "" {
		return c, errors.New("missing digest realm or nonce")
	}
	if c.Algorithm == "" {
		c.Algorithm = "MD5"
	}
	return c, nil
}
func digestHash(algorithm string) (func() hash.Hash, error) {
	switch strings.ToUpper(strings.TrimSuffix(strings.ToUpper(algorithm), "-SESS")) {
	case "MD5", "AKAV1-MD5":
		return md5.New, nil
	case "SHA-256":
		return sha256.New, nil
	case "SHA-512-256":
		return sha512.New512_256, nil
	}
	return nil, fmt.Errorf("unsupported digest algorithm %q", algorithm)
}
func hashHex(h func() hash.Hash, s string) string {
	x := h()
	_, _ = x.Write([]byte(s))
	return hex.EncodeToString(x.Sum(nil))
}

// digestResponse is RFC 7616 with binary AKA RES as the password (RFC 3310).
func digestResponse(c challenge, user string, password []byte, method, uri string, body []byte, nc uint32, cnonce string) (string, string, error) {
	h, e := digestHash(c.Algorithm)
	if e != nil {
		return "", "", e
	}
	qop := ""
	if c.QOP != "" {
		for _, q := range strings.Split(c.QOP, ",") {
			if strings.TrimSpace(q) == "auth" {
				qop = "auth"
				break
			}
			if strings.TrimSpace(q) == "auth-int" {
				qop = "auth-int"
			}
		}
		if qop == "" {
			return "", "", errors.New("unsupported digest qop")
		}
	}
	a1 := hashHex(h, user+":"+c.Realm+":"+string(password))
	if strings.HasSuffix(strings.ToUpper(c.Algorithm), "-SESS") {
		a1 = hashHex(h, a1+":"+c.Nonce+":"+cnonce)
	}
	a2 := method + ":" + uri
	if qop == "auth-int" {
		a2 += ":" + hashHex(h, string(body))
	}
	ha2 := hashHex(h, a2)
	mid := c.Nonce + ":"
	if qop != "" {
		mid += fmt.Sprintf("%08x:%s:%s:", nc, cnonce, qop)
	}
	return hashHex(h, a1+":"+mid+ha2), qop, nil
}
func authHeader(c challenge, user string, password []byte, method, uri string, body []byte, nc uint32, cnonce, auts string) (string, error) {
	r, q, e := digestResponse(c, user, password, method, uri, body, nc, cnonce)
	if e != nil {
		return "", e
	}
	if auts != "" {
		r = ""
	}
	s := "Digest username=" + strconv.Quote(user) + ", realm=" + strconv.Quote(c.Realm) + ", nonce=" + strconv.Quote(c.Nonce) + ", uri=" + strconv.Quote(uri) + ", response=" + strconv.Quote(r) + ", algorithm=" + c.Algorithm
	if c.Opaque != "" {
		s += ", opaque=" + strconv.Quote(c.Opaque)
	}
	if q != "" {
		s += ", qop=" + q + fmt.Sprintf(", nc=%08x, cnonce=%s", nc, strconv.Quote(cnonce))
	}
	if auts != "" {
		s += ", auts=" + strconv.Quote(auts)
	}
	return s, nil
}
func akaPassword(ctx context.Context, p sim.AKAProvider, c challenge) (sim.AKAResult, error) {
	if !strings.EqualFold(c.Algorithm, "AKAv1-MD5") {
		return sim.AKAResult{}, fmt.Errorf("IMS requires AKAv1-MD5; received %q", c.Algorithm)
	}
	nonce, e := base64.StdEncoding.DecodeString(c.Nonce)
	if e != nil || len(nonce) < 32 {
		return sim.AKAResult{}, errors.New("AKA nonce must contain RAND and AUTN")
	}
	if p == nil {
		return sim.AKAResult{}, errors.New("missing IMS SIM provider")
	}
	if e = ctx.Err(); e != nil {
		return sim.AKAResult{}, e
	}
	r, e := p.CalculateAKA(nonce[:16], nonce[16:32])
	if len(r.AUTS) > 0 {
		if len(r.AUTS) != 14 {
			return sim.AKAResult{}, errors.New("invalid AKA AUTS length")
		}
		return r, nil
	}
	if e != nil {
		return r, e
	}
	if len(r.RES) < 4 || len(r.RES) > 16 || len(r.CK) != 16 || len(r.IK) != 16 {
		return sim.AKAResult{}, errors.New("invalid AKA result dimensions")
	}
	return r, nil
}
