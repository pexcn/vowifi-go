package ims

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/pexcn/vowifi-go/engine/sim"
)

func TestDigestRFC2617Vector(t *testing.T) {
	c := challenge{Realm: "testrealm@host.com", Nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093", Algorithm: "MD5", QOP: "auth"}
	got, q, e := digestResponse(c, "Mufasa", []byte("Circle Of Life"), "GET", "/dir/index.html", nil, 1, "0a4f113b")
	if e != nil || q != "auth" || got != "6629fae49393a05397450978507c4ef1" {
		t.Fatalf("RFC vector = %q,%q,%v", got, q, e)
	}
}
func TestDigestParsingAndUnsupported(t *testing.T) {
	c, e := parseChallenge(`Digest realm="a,b", nonce="xyz", qop="auth,auth-int", algorithm=AKAv1-MD5`)
	if e != nil || c.Realm != "a,b" || c.QOP != "auth,auth-int" {
		t.Fatalf("challenge %#v %v", c, e)
	}
	for _, raw := range []string{`Basic realm="a"`, `Digest realm="a", nonce="x", nonce="y"`, `Digest realm="unterminated, nonce=x`} {
		if _, e := parseChallenge(raw); e == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if _, _, e = digestResponse(challenge{Algorithm: "AKAv2-MD5"}, "", nil, "", "", nil, 1, ""); e == nil {
		t.Fatal("unsupported AKA v2 accepted")
	}
}

type akaFunc func([]byte, []byte) (sim.AKAResult, error)

func (f akaFunc) CalculateAKA(r, a []byte) (sim.AKAResult, error) { return f(r, a) }
func TestAKAUsesBinaryRESAndAUTS(t *testing.T) {
	n := make([]byte, 32)
	for i := range n {
		n[i] = byte(i)
	}
	c := challenge{Nonce: base64.StdEncoding.EncodeToString(n), Algorithm: "AKAv1-MD5"}
	p := akaFunc(func(r, a []byte) (sim.AKAResult, error) {
		if len(r) != 16 || r[0] != 0 || a[0] != 16 {
			t.Fatal("incorrect nonce split")
		}
		return sim.AKAResult{AUTS: make([]byte, 14)}, sim.ErrSyncFailure
	})
	r, e := akaPassword(context.Background(), p, c)
	if e != nil || len(r.AUTS) != 14 {
		t.Fatalf("AUTS %v %v", r, e)
	}
	header, e := authHeader(c, "u", nil, "REGISTER", "sip:x", nil, 1, "c", base64.StdEncoding.EncodeToString(r.AUTS))
	if e != nil || !strings.Contains(header, `response=""`) || !strings.Contains(header, `auts="`) {
		t.Fatalf("AUTS digest %s %v", header, e)
	}
}
