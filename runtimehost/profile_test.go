package runtimehost

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
	"github.com/iniwex5/vowifi-go/engine/swu"
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
		if !got.EAPOnlyAuthentication {
			t.Fatal("SWu carrier profile did not offer RFC 5998 EAP-only authentication")
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

func TestCarrierProfileExplicitPRFAndStrictPairing(t *testing.T) {
	for _, tc := range []struct {
		ike, esp string
		want     swu.IKEProfile
	}{
		{"aes256-sha256-prfsha1-modp2048", "aes256-sha256", swu.IKEProfile{256, vc.PRFSHA1, vc.HMACSHA256128, 14}},
		{"aes128-sha1-prfsha256-modp2048", "aes128-sha1", swu.IKEProfile{128, vc.PRFSHA256, vc.HMACSHA196, 14}},
		{" AES128-SHA1-PRFSHA1-MODP1024 ", " AES128-SHA1 ", swu.IKEProfile{128, vc.PRFSHA1, vc.HMACSHA196, 2}},
		{"aes128-sha256-prfsha256-modp2048", "aes128-sha256", swu.IKEProfile{128, vc.PRFSHA256, vc.HMACSHA256128, 14}},
		{"aes256-sha256-prfsha512-modp2048", "aes256-sha256", swu.IKEProfile{}},
		{"aes256-sha256-prfunknown-modp2048", "aes256-sha256", swu.IKEProfile{}},
		{"aes256-sha256-prfsha1-modp3072", "aes256-sha256", swu.IKEProfile{}},
		{"aes256-sha256-prfsha1-modp2048-extra", "aes256-sha256", swu.IKEProfile{}},
		{"aes256-sha256-prfsha1", "aes256-sha256", swu.IKEProfile{}},
		{"aes192-sha256-prfsha1-modp2048", "aes192-sha256", swu.IKEProfile{}},
		{"aes256-sha256-prfsha1-modp2048", "aes256-sha1", swu.IKEProfile{}},
		{"aes256-sha256-prfsha1-modp2048", "aes128-sha256", swu.IKEProfile{}},
	} {
		t.Run(tc.ike+"/"+tc.esp, func(t *testing.T) {
			req := testRequest()
			req.Prepared.EffectiveCarrier.Parameters.IKEProposals = []string{tc.ike}
			req.Prepared.EffectiveCarrier.Parameters.ESPProposals = []string{tc.esp}
			got, err := buildSWUConfig(req)
			if tc.want == (swu.IKEProfile{}) {
				if !errors.Is(err, errUnsupportedCarrierProposals) {
					t.Fatalf("invalid or unpaired algorithms accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p := swu.IKEProfile{got.EncryptionKeyBits, got.PRF, got.Integrity, got.DHGroup}
			if p != tc.want {
				t.Fatalf("profile = %+v, want %+v", p, tc.want)
			}
		})
	}
}

type proposalCaptureTransport struct {
	packet []byte
	closed bool
}

func (c *proposalCaptureTransport) Write(_ context.Context, packet []byte) error {
	c.packet = append([]byte(nil), packet...)
	return nil
}
func (c *proposalCaptureTransport) Read(context.Context) ([]byte, error) {
	return nil, context.Canceled // Stop after the real IKE_SA_INIT has been encoded.
}
func (c *proposalCaptureTransport) Close() error { c.closed = true; return nil }

func TestO2CarrierProfileEmitsIndependentPRFInIKEInit(t *testing.T) {
	req := testRequest()
	req.Prepared.EffectiveCarrier = carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{MCC: "262", MNC: "03"})
	cfg, err := buildSWUConfig(req)
	if err != nil {
		t.Fatal(err)
	}
	capture := &proposalCaptureTransport{}
	cfg.Transport, cfg.EPDGAddr = capture, "127.0.0.1:500"
	if _, err = swu.Dial(context.Background(), cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("dial did not reach capture transport: %v", err)
	}
	if !capture.closed {
		t.Fatal("failed handshake leaked its transport")
	}
	m, err := ikev2.Parse(capture.packet)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := ikev2.One(m.Payloads, ikev2.SA)
	if err != nil {
		t.Fatal(err)
	}
	proposals, err := ikev2.ParseProposals(sa)
	if err != nil {
		t.Fatal(err)
	}
	want := []ikev2.Transform{{Type: 1, ID: 12, KeyBits: 256}, {Type: 2, ID: 2}, {Type: 3, ID: 12}, {Type: 4, ID: 14}}
	if m.Header.Exchange != ikev2.SAInit || len(proposals) != 1 || !reflect.DeepEqual(proposals[0].Transforms, want) {
		t.Fatalf("O2 wire proposal changed: %+v", proposals)
	}
}

func TestUnsupportedCarrierStartupReportsConfigurationFailure(t *testing.T) {
	req := testRequest()
	req.Prepared.EffectiveCarrier = carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{MCC: "530", MNC: "24"})
	inst, err := Start(context.Background(), req)
	if !errors.Is(err, errUnsupportedCarrierProposals) || inst == nil {
		t.Fatalf("unsupported carrier started: %v", err)
	}
	defer inst.Stop(context.Background())
	state := inst.State()
	if state.LastErrorClass != "unsupported_carrier_proposals" || state.TunnelReady || state.IMSReady || state.SMSReady {
		t.Fatalf("configuration failure state: %+v", state)
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

func TestIMSProfileSelectsInitialDigestVariant(t *testing.T) {
	for _, tc := range []struct {
		mcc, mnc string
		plain    bool
	}{{"234", "33", false}, {"001", "01", true}} {
		c := carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{MCC: tc.mcc, MNC: tc.mnc})
		cfg := ims.Config{UsePlainDigestPlaceholder: !tc.plain}
		security := ims.SecurityParameters{SPIClient: 1001, SPIServer: 1002, PortClient: 40000, PortServer: 40001}
		if err := applyIMSProfile(&cfg, c.Parameters, &security); err != nil {
			t.Fatal(err)
		}
		if cfg.UsePlainDigestPlaceholder != tc.plain {
			t.Fatalf("%s/%s initial Digest variant ignored", tc.mcc, tc.mnc)
		}
	}
}
