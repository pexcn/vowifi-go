package eap

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/iniwex5/vowifi-go/engine/sim"
	"math/big"
	"testing"
)

type fakeSIM struct {
	calls int
	sync  bool
}

func (f *fakeSIM) CalculateAKA(r, a []byte) (sim.AKAResult, error) {
	f.calls++
	if f.sync {
		return sim.AKAResult{AUTS: bytes.Repeat([]byte{3}, 14)}, sim.ErrSyncFailure
	}
	return sim.AKAResult{RES: []byte{1, 2, 3, 4, 5, 6, 7, 8}, CK: bytes.Repeat([]byte{7}, 16), IK: bytes.Repeat([]byte{9}, 16)}, nil
}
func TestSHA1CompressionStandardVector(t *testing.T) {
	var b [64]byte
	copy(b[:], "abc")
	b[3] = 128
	b[63] = 24
	got := sha1Compress(b)
	want := sha1.Sum([]byte("abc"))
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("compression: %x", got)
	}
}
func TestFIPS186AdditionAndNoPadding(t *testing.T) {
	seed := bytes.Repeat([]byte{255}, 20)
	got, e := FIPS186PRF(seed, 60)
	if e != nil {
		t.Fatal(e)
	}
	x := new(big.Int).SetBytes(seed)
	mod := new(big.Int).Lsh(big.NewInt(1), 160)
	var expected []byte
	for i := 0; i < 3; i++ {
		var block [64]byte
		x.FillBytes(block[:20])
		g := sha1Compress(block)
		expected = append(expected, g...)
		x.Add(x, new(big.Int).SetBytes(g))
		x.Add(x, big.NewInt(1))
		x.Mod(x, mod)
	}
	if !bytes.Equal(got, expected) {
		t.Fatal("FIPS carry/chaining mismatch")
	}
	padded := sha1.Sum(seed)
	if bytes.Equal(got[:20], padded[:]) {
		t.Fatal("incorrect padded SHA1 in PRF")
	}
}
func challenge(t *testing.T, id string) ([]byte, Keys) {
	t.Helper()
	k, e := DeriveKeys(id, bytes.Repeat([]byte{9}, 16), bytes.Repeat([]byte{7}, 16))
	if e != nil {
		t.Fatal(e)
	}
	p := Packet{Code: Request, Identifier: 1, Type: AKA, Subtype: Challenge, Attributes: []Attribute{{ATRAND, make([]byte, 18)}, {ATAUTN, make([]byte, 18)}, {ATMAC, make([]byte, 18)}}}
	b, e := Sign(k.KAut, p)
	if e != nil {
		t.Fatal(e)
	}
	return b, k
}
func TestAKAValidAndInvalidMAC(t *testing.T) {
	f := &fakeSIM{}
	c := Client{Identity: "0001010000000001@example", Provider: f}
	b, k := challenge(t, c.Identity)
	bad := append([]byte{}, b...)
	bad[len(bad)-1] ^= 1
	if _, _, e := c.Handle(context.Background(), bad); e == nil {
		t.Fatal("bad MAC accepted")
	}
	reply, done, e := c.Handle(context.Background(), b)
	if e != nil || done {
		t.Fatal(e)
	}
	if e = VerifyMAC(k.KAut, reply, nil); e != nil {
		t.Fatal(e)
	}
	p, _ := Parse(reply)
	res, _ := p.Get(ATRES)
	if binary.BigEndian.Uint16(res) != 64 {
		t.Fatal("RES length wrong")
	}
	result, _ := (Packet{Code: Success, Identifier: 1}).Marshal()
	_, done, e = c.Handle(context.Background(), result)
	if e != nil || !done {
		t.Fatal(e)
	}
}
func TestAKAAUTSAndPrematureSuccess(t *testing.T) {
	c := Client{Identity: "test", Provider: &fakeSIM{sync: true}}
	b, _ := challenge(t, c.Identity)
	r, _, e := c.Handle(context.Background(), b)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := Parse(r)
	auts, ok := p.Get(ATAUTS)
	if p.Subtype != SynchronizationFailure || !ok || len(auts) != 14 {
		t.Fatal("AUTS response")
	}
	success, _ := (Packet{Code: Success}).Marshal()
	if _, _, e = c.Handle(context.Background(), success); e == nil {
		t.Fatal("success before challenge")
	}
	if !errors.Is(sim.ErrSyncFailure, sim.ErrSyncFailure) {
		t.Fatal("sentinel")
	}
}
func FuzzParseEAP(f *testing.F) {
	f.Add([]byte{1, 1, 0, 8, 23, 1, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Parse(b) })
}

// RFC 4186 Appendix A.3 publishes the EAP-SIM master key and expansion. The
// FIPS 186-2 expansion is shared with EAP-AKA (RFC 4187 section 7).
func TestFIPS186PublishedVector(t *testing.T) {
	seed, _ := hex.DecodeString("e576d5ca332e9930018bf1baee2763c795b3c712")
	want, _ := hex.DecodeString("536e5ebc4465582aa6a8ec9986ebb62025af1942efcbf4bc72b3943421f2a97439d45aeaf4e30601983e972b6cfd46d1c363773365690d09cd44976b525f47d3a60a985e955c53b090b2e4b73719196a402542968fd14a888f46b9a7886e4488")
	got, err := FIPS186PRF(seed, len(want))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("published FIPS186 expansion: %x (%v)", got, err)
	}
}
func TestSuccessIdentifierMustMatchLastResponse(t *testing.T) {
	c := Client{Identity: "test", Provider: &fakeSIM{}}
	b, _ := challenge(t, c.Identity)
	if _, _, err := c.Handle(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	success, _ := (Packet{Code: Success, Identifier: 2}).Marshal()
	if _, _, err := c.Handle(context.Background(), success); err == nil {
		t.Fatal("success with unmatched identifier accepted")
	}
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func withCheckcode(t *testing.T, b []byte, key, checkcode []byte) []byte {
	t.Helper()
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	p.Attributes = append(p.Attributes, Attribute{ATCheckcode, append([]byte{0xab, 0xcd}, checkcode...)}) // reserved ignored on reception
	b, err = Sign(key, p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestAKAIdentityCheckcodeStandardTranscript(t *testing.T) {
	// Exact wire bytes, including nonzero identity-attribute reserved bytes and
	// response padding. Expected SHA1 values were computed separately with Python
	// hashlib, not by Client.checkcode or the packet encoder under test.
	first := decodeHex(t, "0111000c170500000a01aabb")
	firstReply := decodeHex(t, "02110010170500000e02000474657374")
	second := decodeHex(t, "0112000c170500000d010000")
	secondReply := decodeHex(t, "02120010170500000e02000474657374")
	want := decodeHex(t, "6c99e2c1108541df47f8b91c33dc1083d66b4520")
	c := Client{Identity: "test", Provider: &fakeSIM{}, ChallengeMode: "checkcode"}
	// Plain EAP Identity is excluded from AT_CHECKCODE.
	if _, _, err := c.Handle(context.Background(), decodeHex(t, "0101000501")); err != nil {
		t.Fatal(err)
	}
	got, _, err := c.Handle(context.Background(), first)
	if err != nil || !bytes.Equal(got, firstReply) {
		t.Fatalf("identity response: %x %v", got, err)
	}
	// Retransmits are included only once, and a pair is not committed until a
	// subsequent different-ID AKA Identity or AKA Challenge acknowledges it.
	if len(c.identityTranscript) != 0 {
		t.Fatal("unacknowledged identity pair committed")
	}
	got, _, err = c.Handle(context.Background(), first)
	if err != nil || !bytes.Equal(got, firstReply) {
		t.Fatal(err)
	}
	got, _, err = c.Handle(context.Background(), second)
	if err != nil || !bytes.Equal(got, secondReply) {
		t.Fatalf("second identity: %x %v", got, err)
	}
	if !bytes.Equal(c.checkcode(), decodeHex(t, "fccc7fe27c124400474a908d6fec62b53b374887")) {
		t.Fatal("first acknowledged pair checksum")
	}
	b, k := challenge(t, c.Identity)
	b = withCheckcode(t, b, k.KAut, want)
	got, _, err = c.Handle(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyMAC(k.KAut, got, nil); err != nil {
		t.Fatal(err)
	}
	p, err := Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := p.Get(ATCheckcode)
	if !ok || !bytes.Equal(v, append([]byte{0, 0}, want...)) {
		t.Fatalf("response checkcode: %x", v)
	}
}
func TestAKAIncorrectCheckcodeRejectsAcrossModes(t *testing.T) {
	for _, mode := range []string{"minimal", "omit", "checkcode"} {
		t.Run(mode, func(t *testing.T) {
			c := Client{Identity: "test", Provider: &fakeSIM{}, ChallengeMode: mode}
			if _, _, err := c.Handle(context.Background(), decodeHex(t, "0111000c170500000a01aabb")); err != nil {
				t.Fatal(err)
			}
			b, k := challenge(t, c.Identity)
			b = withCheckcode(t, b, k.KAut, make([]byte, 20))
			if _, _, err := c.Handle(context.Background(), b); err == nil || c.Keys != nil || c.challenged {
				t.Fatal("invalid transcript accepted", err)
			}
		})
	}
}
func TestAKACheckcodeOfferModesAndEmptyTranscript(t *testing.T) {
	for _, mode := range []string{"minimal", "omit", "checkcode"} {
		for _, offered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", mode, offered), func(t *testing.T) {
				c := Client{Identity: "test", Provider: &fakeSIM{}, ChallengeMode: mode}
				b, k := challenge(t, c.Identity)
				if offered {
					b = withCheckcode(t, b, k.KAut, nil)
				}
				got, _, err := c.Handle(context.Background(), b)
				if err != nil {
					t.Fatal(err)
				}
				p, err := Parse(got)
				if err != nil {
					t.Fatal(err)
				}
				value, present := p.Get(ATCheckcode)
				want := mode == "checkcode" || mode == "minimal" && offered
				if present != want || present && !bytes.Equal(value, []byte{0, 0}) {
					t.Fatalf("offered=%v mode=%s checkcode=%x present=%v", offered, mode, value, present)
				}
			})
		}
	}
}
func TestAKAExtendedIdentityRequiresServerCheckcode(t *testing.T) {
	c := Client{Identity: "test", Provider: &fakeSIM{}}
	// Unknown skippable extension in AKA Identity requires transcript protection
	// in the subsequent challenge under RFC4187 section10.13.
	if _, _, err := c.Handle(context.Background(), decodeHex(t, "01110010170500000a010000c901beef")); err != nil {
		t.Fatal(err)
	}
	b, _ := challenge(t, c.Identity)
	if _, _, err := c.Handle(context.Background(), b); err == nil {
		t.Fatal("missing required checkcode accepted")
	}
	for _, malformed := range []string{"01010010170100008602000001020304"} {
		_, err := Parse(decodeHex(t, malformed))
		if err == nil {
			t.Fatal("malformed AT_CHECKCODE accepted")
		}
	}
}
