package eap

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

func provisionReauth(t *testing.T, method byte) (*ReauthContext, Keys) {
	t.Helper()
	cache := &ReauthContext{}
	c := Client{Identity: "test", Provider: &fakeSIM{}, Reauth: cache, Binding: "test@epdg"}
	var p Packet
	var keys Keys
	if method == AKAPrime {
		c.PrimeNetworkName = "WLAN"
		p, keys = primeChallenge(t, "test", 1)
	} else {
		b, k := challenge(t, "test")
		keys = k
		p, _ = Parse(b)
	}
	attrs, err := encryptAttributes(method, []Attribute{{133, append(binary.BigEndian.AppendUint16(nil, uint16(len("reauth@ims.test"))), []byte("reauth@ims.test")...)}}, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Attributes = append(p.Attributes, attrs...)
	wire, err := Sign(keys.KAut, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Handle(context.Background(), wire); err != nil {
		t.Fatal(err)
	}
	if cache.state != nil {
		t.Fatal("credential published before final authentication")
	}
	if err := c.Commit(); err == nil {
		t.Fatal("cache committed before EAP success")
	}
	success, _ := (Packet{Code: Success, Identifier: p.Identifier}).Marshal()
	if _, done, err := c.Handle(context.Background(), success); err != nil || !done {
		t.Fatal(err)
	}
	if cache.state != nil {
		t.Fatal("EAP success alone published credential")
	}
	if err := c.Commit(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	return cache, keys
}
func reauthRequest(t *testing.T, method byte, keys Keys, counter uint16, next string) ([]byte, []byte) {
	t.Helper()
	nonce := bytes.Repeat([]byte{0x43}, 16)
	attrs := []Attribute{{ATCounter, binary.BigEndian.AppendUint16(nil, counter)}, {ATNonceS, append([]byte{0, 0}, nonce...)}}
	if next != "" {
		attrs = append(attrs, Attribute{133, append(binary.BigEndian.AppendUint16(nil, uint16(len(next))), []byte(next)...)})
	}
	encrypted, err := encryptAttributes(method, attrs, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := Packet{Code: Request, Identifier: 9, Type: method, Subtype: Reauthentication, Attributes: append(encrypted, Attribute{ATMAC, make([]byte, 18)})}
	b, err := Sign(keys.KAut, p)
	if err != nil {
		t.Fatal(err)
	}
	return b, nonce
}
func initializeReauth(t *testing.T, cache *ReauthContext, method byte) *Client {
	t.Helper()
	c := &Client{Identity: "test", Reauth: cache, Binding: "test@epdg"}
	if method == AKAPrime {
		c.PrimeNetworkName = "WLAN"
	}
	b, _ := (Packet{Code: Request, Identifier: 1, Type: Identity}).Marshal()
	r, _, err := c.Handle(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := Parse(r)
	if string(id.Data) != "reauth@ims.test" {
		t.Fatal("reauth identity not used")
	}
	return c
}
func TestReauthenticationCommitCounterSingleUseAndUncertainty(t *testing.T) {
	for _, method := range []byte{AKA, AKAPrime} {
		t.Run(map[byte]string{AKA: "aka", AKAPrime: "prime"}[method], func(t *testing.T) {
			cache, keys := provisionReauth(t, method)
			c := initializeReauth(t, cache, method)
			wire, nonce := reauthRequest(t, method, keys, 1, "next@ims.test")
			response, done, err := c.Handle(context.Background(), wire)
			if err != nil || done {
				t.Fatal(err)
			}
			if err := VerifyMAC(keys.KAut, response, nonce); err != nil {
				t.Fatal(err)
			}
			replay, _, err := c.Handle(context.Background(), wire)
			if err != nil || !bytes.Equal(replay, response) {
				t.Fatal("reauth retransmission changed", err)
			}
			if cache.state.counter != 0 || cache.state.identity != "reauth@ims.test" {
				t.Fatal("counter committed before final IKE AUTH")
			}
			if bytes.Equal(c.Keys.MSK, keys.MSK) || !bytes.Equal(c.Keys.KAut, keys.KAut) {
				t.Fatal("wrong reauth key lifetime")
			}
			success, _ := (Packet{Code: Success, Identifier: 9}).Marshal()
			if _, done, err := c.Handle(context.Background(), success); err != nil || !done {
				t.Fatal(err)
			}
			if err := c.Commit(); err != nil {
				t.Fatal(err)
			}
			if cache.state.counter != 1 || cache.state.identity != "next@ims.test" {
				t.Fatal("credential commit")
			}
			// Once a fast identity has been exposed, an uncertain failure consumes it.
			c2 := &Client{Identity: "test", Reauth: cache, Binding: "test@epdg"}
			b, _ := (Packet{Code: Request, Identifier: 1, Type: Identity}).Marshal()
			c2.Handle(context.Background(), b)
			c2.Close()
			if cache.state != nil {
				t.Fatal("uncertain single-use identity retained")
			}
		})
	}
}
func TestReauthenticationStaleCounterBindingAndLateCommit(t *testing.T) {
	cache, keys := provisionReauth(t, AKA)
	c := initializeReauth(t, cache, AKA)
	wire, nonce := reauthRequest(t, AKA, keys, 0, "ignored@ims.test")
	r, done, err := c.Handle(context.Background(), wire)
	if err != nil || done {
		t.Fatal(err)
	}
	if err := VerifyMAC(keys.KAut, r, nonce); err != nil {
		t.Fatal(err)
	}
	p, _ := Parse(r)
	attrs, _, err := encryptedAttributes(p, keys)
	if err != nil {
		t.Fatal(err)
	}
	inner := Packet{Attributes: attrs}
	if _, ok := inner.Get(ATCounterTooSmall); !ok {
		t.Fatal("stale counter did not request full AKA")
	}
	if c.Keys != nil || c.pending != nil {
		t.Fatal("stale keys installed")
	}
	c.Close()
	cache, _ = provisionReauth(t, AKA)
	c = initializeReauth(t, cache, AKA)
	cache.Clear()
	c.success = true
	c.pending = &reauthState{identity: "late"}
	c.Commit()
	if cache.state != nil {
		t.Fatal("late commit resurrected invalidated context")
	}
	cache, _ = provisionReauth(t, AKA)
	other := &Client{Identity: "other", Reauth: cache, Binding: "another-subscription"}
	b, _ := (Packet{Code: Request, Identifier: 1, Type: Identity}).Marshal()
	r, _, err = other.Handle(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	p, _ = Parse(r)
	if string(p.Data) != "other" {
		t.Fatal("cross-subscription credential reuse")
	}
	other.Close()
}
