package eap

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"strings"
	"testing"
)

// Synthetic server-side identity provisioning; no device identities or AKA
// material from operator logs are used in these fixtures.
func encryptedIdentityAttributes(t *testing.T, keys Keys) []Attribute {
	t.Helper()
	p := Packet{Code: Request, Type: AKA, Subtype: Challenge}
	for _, a := range []struct {
		typ   byte
		value string
	}{{132, "next-alias"}, {133, "reauth@ims.test"}} {
		p.Attributes = append(p.Attributes, Attribute{a.typ, append(binary.BigEndian.AppendUint16(nil, uint16(len(a.value))), a.value...)})
	}
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	plain := b[8:]
	if n := 16 - len(plain)%16; n != 16 {
		plain = append(plain, 6, byte(n/4)) // RFC padding attribute, not PKCS#7.
		plain = append(plain, make([]byte, n-2)...)
	}
	iv := bytes.Repeat([]byte{0x42}, 16)
	block, err := aes.NewCipher(keys.KEncr)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)
	return []Attribute{{ATIV, append([]byte{0, 0}, iv...)}, {ATEncrData, append([]byte{0, 0}, ciphertext...)}}
}

func TestAKAChallengeAcceptsOptionalEncryptedIdentities(t *testing.T) {
	for _, protected := range []bool{false, true} {
		name := "full-auth"
		if protected {
			name = "protected-result"
		}
		t.Run(name, func(t *testing.T) {
			c := Client{Identity: "test", Provider: &fakeSIM{}}
			b, keys := challenge(t, c.Identity)
			p, _ := Parse(b)
			attrs := encryptedIdentityAttributes(t, keys)
			// Reserved fields are covered by AT_MAC but ignored on reception.
			attrs[0].Value[0], attrs[1].Value[1] = 0xab, 0xcd
			p.Attributes = append(p.Attributes, attrs...)
			if protected {
				p.Attributes = append(p.Attributes, Attribute{135, []byte{0, 0}})
			}
			b, err := Sign(keys.KAut, p)
			if err != nil {
				t.Fatal(err)
			}
			reply, done, err := c.Handle(context.Background(), b)
			if err != nil || done {
				t.Fatalf("challenge: done=%v err=%v", done, err)
			}
			if err = VerifyMAC(keys.KAut, reply, nil); err != nil {
				t.Fatal(err)
			}
			r, err := Parse(reply)
			if err != nil {
				t.Fatal(err)
			}
			res, ok := r.Get(ATRES)
			if !ok || !bytes.Equal(res[2:], []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
				t.Fatal("lost SIM authentication response")
			}
			if _, ok = r.Get(ATEncrData); ok {
				t.Fatal("encrypted identity offer echoed")
			}
			if c.Identity != "test" || !bytes.Equal(c.Keys.MSK, keys.MSK) {
				t.Fatal("optional identity replaced full-auth identity or keys")
			}
			success, _ := (Packet{Code: Success, Identifier: p.Identifier}).Marshal()
			if protected {
				if _, _, err = c.Handle(context.Background(), success); err == nil {
					t.Fatal("protected result bypassed")
				}
				notify := Packet{Code: Request, Identifier: 2, Type: AKA, Subtype: Notification, Attributes: []Attribute{{ATNotification, []byte{0x80, 0}}, {ATMAC, make([]byte, 18)}}}
				request, err := Sign(keys.KAut, notify)
				if err != nil {
					t.Fatal(err)
				}
				ack, done, err := c.Handle(context.Background(), request)
				if err != nil || done {
					t.Fatalf("protected notification: %v", err)
				}
				if err = VerifyMAC(keys.KAut, ack, nil); err != nil {
					t.Fatal(err)
				}
				success, _ = (Packet{Code: Success, Identifier: 2}).Marshal()
			}
			if _, done, err = c.Handle(context.Background(), success); err != nil || !done {
				t.Fatalf("full authentication: done=%v err=%v", done, err)
			}
		})
	}
}

func TestAKAEncryptedIdentitiesRemainCoveredByServerMAC(t *testing.T) {
	for _, typ := range []byte{ATIV, ATEncrData} {
		c := Client{Identity: "test", Provider: &fakeSIM{}}
		b, keys := challenge(t, c.Identity)
		p, _ := Parse(b)
		p.Attributes = append(p.Attributes, encryptedIdentityAttributes(t, keys)...)
		b, err := Sign(keys.KAut, p)
		if err != nil {
			t.Fatal(err)
		}
		p, _ = Parse(b)
		for i := range p.Attributes {
			if p.Attributes[i].Type == typ {
				p.Attributes[i].Value[2] ^= 1
			}
		}
		b, err = p.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		reply, done, err := c.Handle(context.Background(), b)
		if err == nil || !strings.Contains(err.Error(), "MAC verification failed") || done || len(reply) != 0 || c.Keys != nil || c.challenged {
			t.Fatalf("tampered attribute %d: reply=%x done=%v err=%v", typ, reply, done, err)
		}
	}
}

func TestAKARejectsMalformedEncryptedIdentityAttributes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs []Attribute
	}{
		{"missing-ciphertext", []Attribute{{ATIV, make([]byte, 18)}}},
		{"missing-iv", []Attribute{{ATEncrData, make([]byte, 18)}}},
		{"short-iv", []Attribute{{ATIV, make([]byte, 14)}, {ATEncrData, make([]byte, 18)}}},
		{"long-iv", []Attribute{{ATIV, make([]byte, 22)}, {ATEncrData, make([]byte, 18)}}},
		{"empty-ciphertext", []Attribute{{ATIV, make([]byte, 18)}, {ATEncrData, make([]byte, 2)}}},
		{"short-ciphertext", []Attribute{{ATIV, make([]byte, 18)}, {ATEncrData, make([]byte, 14)}}},
		{"non-block-ciphertext", []Attribute{{ATIV, make([]byte, 18)}, {ATEncrData, make([]byte, 22)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Client{Identity: "test", Provider: &fakeSIM{}}
			b, keys := challenge(t, c.Identity)
			p, _ := Parse(b)
			p.Attributes = append(p.Attributes, tc.attrs...)
			b, err := Sign(keys.KAut, p)
			if err != nil {
				t.Fatal(err)
			}
			reply, done, err := c.Handle(context.Background(), b)
			if err == nil || done || len(reply) != 0 || c.Keys != nil || c.challenged {
				t.Fatalf("malformed offer accepted: %v", err)
			}
		})
	}
}

func TestEncryptedIdentityOfferDoesNotEnableFastReauthentication(t *testing.T) {
	c := Client{Identity: "test", Provider: &fakeSIM{}}
	b, keys := challenge(t, c.Identity)
	p, _ := Parse(b)
	p.Attributes = append(p.Attributes, encryptedIdentityAttributes(t, keys)...)
	b, err := Sign(keys.KAut, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = c.Handle(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	reauth, _ := (Packet{Code: Request, Identifier: 2, Type: AKA, Subtype: 13}).Marshal()
	if _, _, err = c.Handle(context.Background(), reauth); err == nil || !strings.Contains(err.Error(), "unsupported AKA subtype 13") {
		t.Fatalf("fast reauthentication enabled: %v", err)
	}
}
