package eap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestAKAPrimeRFC5448VectorAndAMF(t *testing.T) {
	ik := fromHex(t, "9744871ad32bf9bbd1dd5ce54e3e2e5a")
	ck := fromHex(t, "5349fbe098649f948f5d2e973a81c00f")
	autn := fromHex(t, "bb52e91c747ac3ab2a5c23d15ee351d5")
	k, err := DerivePrimeKeys("0555444333222111", "WLAN", autn, ik, ck)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		got  []byte
		want string
	}{
		{k.KEncr, "766fa0a6c317174b812d52fbcd11a179"},
		{k.KAut, "0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea"},
		{k.KRe, "cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a"},
		{k.MSK, "67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a"},
	} {
		if !bytes.Equal(tc.got, fromHex(t, tc.want)) {
			t.Fatalf("RFC 5448 mismatch: %x", tc.got)
		}
	}
	autn[6] &= 0x7f
	if _, err := DerivePrimeKeys("0555444333222111", "WLAN", autn, ik, ck); err == nil {
		t.Fatal("AMF separation not checked")
	}
}
func primeChallenge(t *testing.T, identity string, kdfs ...uint16) (Packet, Keys) {
	t.Helper()
	autn := make([]byte, 16)
	autn[6] = 0x80
	keys, err := DerivePrimeKeys(identity, "WLAN", autn, bytes.Repeat([]byte{9}, 16), bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	p := Packet{Code: Request, Identifier: 7, Type: AKAPrime, Subtype: Challenge, Attributes: []Attribute{{ATRAND, make([]byte, 18)}, {ATAUTN, append([]byte{0, 0}, autn...)}, {ATKDFInput, append([]byte{0, 4}, []byte("WLAN")...)}}}
	for _, v := range kdfs {
		p.Attributes = append(p.Attributes, Attribute{ATKDF, binary.BigEndian.AppendUint16(nil, v)})
	}
	p.Attributes = append(p.Attributes, Attribute{ATMAC, make([]byte, 18)})
	return p, keys
}
func TestAKAPrimeNegotiationBindingAndMAC(t *testing.T) {
	c := Client{Identity: "test", PrimeNetworkName: "WLAN", Provider: &fakeSIM{}}
	p, k := primeChallenge(t, c.Identity, 2, 1)
	wire, _ := Sign(k.KAut, p)
	reply, _, err := c.Handle(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := Parse(reply)
	if err != nil || len(selected.Attributes) != 1 || selected.Attributes[0].Type != ATKDF {
		t.Fatal("KDF selection was not isolated", err)
	}
	p, k = primeChallenge(t, c.Identity, 1, 2, 1)
	p.Identifier++
	wire, _ = Sign(k.KAut, p)
	reply, done, err := c.Handle(context.Background(), wire)
	if err != nil || done {
		t.Fatal(err)
	}
	if err = VerifyMAC(k.KAut, reply, nil); err != nil {
		t.Fatal(err)
	}
	success, _ := (Packet{Code: Success, Identifier: p.Identifier}).Marshal()
	if _, done, err := c.Handle(context.Background(), success); err != nil || !done {
		t.Fatal(err)
	}
	for _, kind := range []string{"network", "amf", "mac", "duplicate-kdf", "kdf-change"} {
		t.Run(kind, func(t *testing.T) {
			c := Client{Identity: "test", PrimeNetworkName: "WLAN", Provider: &fakeSIM{}}
			p, k := primeChallenge(t, c.Identity, 1)
			switch kind {
			case "network":
				c.PrimeNetworkName = "HRPD"
			case "amf":
				p.Attributes[1].Value[8] &= 0x7f
			case "duplicate-kdf":
				p.Attributes = append(p.Attributes, Attribute{ATKDF, []byte{0, 1}})
			case "kdf-change":
				first, keys := primeChallenge(t, c.Identity, 2, 1)
				b, _ := Sign(keys.KAut, first)
				if _, _, err := c.Handle(context.Background(), b); err != nil {
					t.Fatal(err)
				}
			}
			wire, _ := Sign(k.KAut, p)
			if kind == "mac" {
				wire[len(wire)-1] ^= 1
			}
			if _, _, err := c.Handle(context.Background(), wire); err == nil || c.Keys != nil {
				t.Fatal("invalid prime challenge accepted")
			}
		})
	}
}
