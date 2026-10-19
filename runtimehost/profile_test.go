package runtimehost

import (
	"strings"
	"testing"

	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/internal/ims"
	"github.com/iniwex5/vowifi-go/runtimehost/carrier"
	"github.com/iniwex5/vowifi-go/runtimehost/identity"
)

func TestCarrierProfileNegotiatesOnlyAllowedPairedAlgorithms(t *testing.T) {
	for _, tt := range []struct {
		mcc, mnc string
		bits     uint16
	}{{"310", "280", 128}, {"454", "000", 256}, {"234", "33", 128}} {
		cfg := carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{MCC: tt.mcc, MNC: tt.mnc})
		req := testRequest()
		req.Prepared = &identity.PreparedSession{Profile: identity.Profile{IMSI: "001010123456789", MCC: tt.mcc, MNC: tt.mnc}, EPDGAddr: cfg.EPDGAddr, EffectiveCarrier: cfg}
		got, err := buildSWUConfig(req)
		if err != nil {
			t.Fatal(err)
		}
		if got.EncryptionKeyBits != tt.bits || got.PRF != vc.PRFSHA256 || got.Integrity != vc.HMACSHA256128 {
			t.Fatalf("profile changed %+v", got)
		}
		if !strings.HasPrefix(got.NAI, "0001010123456789@nai.epc.") || got.APN != "ims" {
			t.Fatalf("NAI/APN: %s %s", got.NAI, got.APN)
		}
	}
}
func TestUnsupportedCarrierDoesNotSilentlyOfferDifferentAlgorithms(t *testing.T) {
	c := carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{MCC: "530", MNC: "24"})
	req := testRequest()
	req.Prepared.EffectiveCarrier = c
	if _, err := buildSWUConfig(req); err == nil || !strings.Contains(err.Error(), "no supported IKE/ESP pair") {
		t.Fatalf("unsupported profile silently changed: %v", err)
	}
}
func TestIMSPolicyPreservesRealmHeadersAndOffer(t *testing.T) {
	c := carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{MCC: "310", MNC: "280"})
	cfg := ims.Config{}
	security := ims.SecurityParameters{SPIClient: 1001, SPIServer: 1002, PortClient: 40000, PortServer: 40001}
	if err := applyIMSProfile(&cfg, c.Parameters, &security); err != nil {
		t.Fatal(err)
	}
	if cfg.Realm != c.Parameters.IMSRealm || cfg.RegisterHeaders["supported"] != "path,sec-agree,gruu" || cfg.SecurityClient.Algorithm != "hmac-sha-1-96" || cfg.SecurityClient.Encryption != "aes-cbc" {
		t.Fatalf("carrier IMS settings lost %+v", cfg)
	}
}
