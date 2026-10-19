package e911

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/engine/eap"
	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/runtimehost/carrier"
)

type httpFunc func(*HTTPRequest) (*HTTPResponse, error)

func (f httpFunc) Do(r *HTTPRequest) (*HTTPResponse, error) { return f(r) }

type simFixture struct {
	calls  int
	result sim.AKAResult
	err    error
}

func (s *simFixture) CalculateAKA(rand, autn []byte) (sim.AKAResult, error) {
	s.calls++
	return s.result, s.err
}
func entitlementRequest() Request {
	return Request{Carrier: carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{MCC: "310", MNC: "280"}), Identity: Identity{IMSI: "310280000000001", MCC: "310", MNC: "280", IMEI: "356306952701762", SIPUsername: "user@private.att.net", DisplayName: "VoHive"}}
}
func decodeActions(t *testing.T, r *HTTPRequest) []map[string]any {
	t.Helper()
	if r.Context == nil {
		t.Fatal("operation context missing")
	}
	if _, ok := r.Context.Deadline(); !ok {
		t.Fatal("operation deadline missing")
	}
	g, err := gzip.NewReader(bytes.NewReader(r.Body))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	b, err := io.ReadAll(g)
	if err != nil {
		t.Fatal(err)
	}
	var a []map[string]any
	if err = json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	return a
}
func response(t *testing.T, v any, compressed bool) *HTTPResponse {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if compressed {
		var out bytes.Buffer
		g := gzip.NewWriter(&out)
		g.Write(b)
		g.Close()
		b = out.Bytes()
	}
	return &HTTPResponse{StatusCode: 200, Body: b}
}
func signedChallenge(t *testing.T, identity string, r sim.AKAResult) ([]byte, []byte) {
	t.Helper()
	k, err := eap.DeriveKeys(identity, r.IK, r.CK)
	if err != nil {
		t.Fatal(err)
	}
	b, err := eap.Sign(k.KAut, eap.Packet{Code: eap.Request, Identifier: 17, Type: eap.AKA, Subtype: eap.Challenge, Attributes: []eap.Attribute{{Type: eap.ATRAND, Value: make([]byte, 18)}, {Type: eap.ATAUTN, Value: make([]byte, 18)}, {Type: eap.ATMAC, Value: make([]byte, 18)}}})
	if err != nil {
		t.Fatal(err)
	}
	return b, k.KAut
}
func TestATTChallengeTokenAndWebsheet(t *testing.T) {
	req := entitlementRequest()
	req.Carrier.AKAAppPreference = "usim"
	p := &simFixture{result: sim.AKAResult{RES: []byte{1, 2, 3, 4, 5, 6, 7, 8}, IK: bytes.Repeat([]byte{0x11}, 16), CK: bytes.Repeat([]byte{0x22}, 16)}}
	req.AKAProvider = p
	permanent := "0310280000000001@nai.epc.mnc280.mcc310.3gppnetwork.org"
	challenge, key := signedChallenge(t, permanent, p.result)
	calls := 0
	req.Client = httpFunc(func(r *HTTPRequest) (*HTTPResponse, error) {
		a := decodeActions(t, r)
		calls++
		switch calls {
		case 1:
			if len(a) != 3 || a[0]["action-name"] != "getAuthentication" || a[1]["action-name"] != "getPhoneServicesAccountStatus" || a[2]["action-name"] != "getEntitlement" {
				t.Fatalf("actions %+v", a)
			}
			b, _ := base64.StdEncoding.DecodeString(a[0]["subscriber-id"].(string))
			packet, err := eap.Parse(b)
			if err != nil || string(packet.Data) != permanent || packet.Identifier != 0 {
				t.Fatalf("subscriber id %x %v", b, err)
			}
			if a[0]["unique-id"] != req.Identity.IMEI {
				t.Fatal("explicit IMEI missing")
			}
			return response(t, []any{map[string]any{"status": 1003, "response-id": a[0]["request-id"], "challenge": base64.StdEncoding.EncodeToString(challenge)}}, true), nil
		case 2:
			if len(a) != 1 || a[0]["action-name"] != "postChallenge" {
				t.Fatalf("post challenge %+v", a)
			}
			b, _ := base64.StdEncoding.DecodeString(a[0]["payload"].(string))
			if err := eap.VerifyMAC(key, b, nil); err != nil {
				t.Fatal(err)
			}
			packet, err := eap.Parse(b)
			if err != nil || packet.Identifier != 17 || packet.Subtype != eap.Challenge {
				t.Fatalf("EAP reply %+v %v", packet, err)
			}
			return response(t, []any{map[string]any{"status": 1000, "response-id": a[0]["request-id"], "token": "carrier-token"}}, false), nil
		case 3:
			if a[0]["token"] != "carrier-token" {
				t.Fatal("authenticated token not reused")
			}
			return response(t, []any{map[string]any{"status": 1000, "response-id": a[1]["request-id"], "address-update-url": "https://address.att.example/update", "address-update-url-post-data": "token=carrier-form"}}, true), nil
		default:
			t.Fatal("unbounded retry")
			return nil, nil
		}
	})
	sheet, err := StartEmergencyAddressUpdate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if sheet.URL != "https://address.att.example/update" || sheet.UserData != "token=carrier-form" || calls != 3 || p.calls != 1 {
		t.Fatalf("sheet %+v HTTP=%d SIM=%d", sheet, calls, p.calls)
	}
}
func TestChallengeMustVerifyServerMACBeforePosting(t *testing.T) {
	req := entitlementRequest()
	req.Carrier.AKAAppPreference = "usim"
	p := &simFixture{result: sim.AKAResult{RES: []byte{1, 2, 3, 4}, IK: make([]byte, 16), CK: make([]byte, 16)}}
	req.AKAProvider = p
	challenge, _ := signedChallenge(t, "0310280000000001@nai.epc.mnc280.mcc310.3gppnetwork.org", p.result)
	challenge[len(challenge)-1] ^= 1
	calls := 0
	req.Client = httpFunc(func(r *HTTPRequest) (*HTTPResponse, error) {
		calls++
		a := decodeActions(t, r)
		return response(t, []any{map[string]any{"status": 1003, "response-id": a[0]["request-id"], "challenge": base64.StdEncoding.EncodeToString(challenge)}}, false), nil
	})
	if _, err := StartEmergencyAddressUpdate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("bad MAC accepted: %v", err)
	}
	if calls != 1 {
		t.Fatal("unverified challenge posted")
	}
}
func TestUnsupportedProviderAndCancelledContextDoNoHTTP(t *testing.T) {
	req := entitlementRequest()
	req.Client = httpFunc(func(*HTTPRequest) (*HTTPResponse, error) { t.Fatal("unexpected HTTP"); return nil, nil })
	req.Carrier.E911.Provider = "T-Mobile_entitlement"
	req.Carrier.E911.WebsheetURL = "https://address.example/"
	if _, err := StartEmergencyAddressUpdate(context.Background(), req); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StartEmergencyAddressUpdate(ctx, req); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestMissingSIMAndRejectedStatusesCannotYieldWebsheet(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields map[string]any
		want   error
	}{
		{"SIM", map[string]any{"status": 1003, "challenge": "ignored"}, ErrChallengeNotImplemented},
		{"failure URL", map[string]any{"status": 6004, "address-update-url": "https://address.example/"}, nil},
		{"missing status", map[string]any{"address-update-url": "https://address.example/"}, nil},
		{"wrong ID", map[string]any{"status": 1000, "response-id": 999999, "address-update-url": "https://address.example/"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := entitlementRequest()
			req.Client = httpFunc(func(r *HTTPRequest) (*HTTPResponse, error) {
				a := decodeActions(t, r)
				if _, ok := tc.fields["response-id"]; !ok {
					tc.fields["response-id"] = a[0]["request-id"]
				}
				return response(t, []any{tc.fields}, false), nil
			})
			if _, err := StartEmergencyAddressUpdate(context.Background(), req); err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("expected rejection, got %v", err)
			}
		})
	}
}
func TestWebsheetPublicHTTPSPolicy(t *testing.T) {
	for _, raw := range []string{"http://address.example/", "https://localhost/", "https://127.0.0.1/", "https://[::1]/", "https://[::ffff:10.0.0.1]/", "https://10.1.2.3/", "https://100.64.0.1/", "https://internal/", "https://address.local/", "https://user:secret@address.example/"} {
		if err := validateWebsheet(raw, "public_https"); err == nil {
			t.Errorf("unsafe URL accepted: %s", raw)
		}
	}
	if err := validateWebsheet("https://address.att.example/update", "public_https"); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestDefaultHTTPCarriesCancellationAndBoundsBody(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := defaultHTTPClient{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		cancel()
		if err := r.Context().Err(); err != context.Canceled {
			t.Fatal("request context disconnected")
		}
		return nil, r.Context().Err()
	})}}
	if _, err := client.Do(&HTTPRequest{URL: "https://entitlement.example/", Context: ctx}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	client.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxBodyBytes+1)))}, nil
	})
	if _, err := client.Do(&HTTPRequest{URL: "https://entitlement.example/"}); err == nil {
		t.Fatal("oversize response accepted")
	}
}
func TestGzipDecompressedBodyLimit(t *testing.T) {
	req := entitlementRequest()
	req.Client = httpFunc(func(r *HTTPRequest) (*HTTPResponse, error) {
		var b bytes.Buffer
		g := gzip.NewWriter(&b)
		g.Write(bytes.Repeat([]byte("x"), maxBodyBytes+1))
		g.Close()
		return &HTTPResponse{StatusCode: 200, Body: b.Bytes()}, nil
	})
	if _, err := StartEmergencyAddressUpdate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "body limit") {
		t.Fatalf("gzip bomb accepted: %v", err)
	}
}
func TestHTTPDeadlineIsBounded(t *testing.T) {
	req := entitlementRequest()
	req.Client = httpFunc(func(r *HTTPRequest) (*HTTPResponse, error) {
		d, _ := r.Context.Deadline()
		if time.Until(d) > operationTimeout {
			t.Fatal("unbounded context")
		}
		return nil, context.DeadlineExceeded
	})
	if _, err := StartEmergencyAddressUpdate(context.Background(), req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestURLWithoutPostDataIsNotCompleteWebsheet(t *testing.T) {
	req := entitlementRequest()
	req.Client = httpFunc(func(r *HTTPRequest) (*HTTPResponse, error) {
		a := decodeActions(t, r)
		return response(t, []any{map[string]any{"status": 1000, "response-id": a[1]["request-id"], "address-update-url": "https://address.example/"}}, false), nil
	})
	if _, err := StartEmergencyAddressUpdate(context.Background(), req); !errors.Is(err, ErrWebsheetUnavailable) {
		t.Fatalf("incomplete handoff accepted: %v", err)
	}
}
func TestAUTSChallengeRetriesAreBounded(t *testing.T) {
	req := entitlementRequest()
	req.Carrier.AKAAppPreference = "usim"
	p := &simFixture{result: sim.AKAResult{AUTS: bytes.Repeat([]byte{0x44}, 14)}, err: sim.ErrSyncFailure}
	req.AKAProvider = p
	challenge, _ := (eap.Packet{Code: eap.Request, Identifier: 7, Type: eap.AKA, Subtype: eap.Challenge, Attributes: []eap.Attribute{{Type: eap.ATRAND, Value: make([]byte, 18)}, {Type: eap.ATAUTN, Value: make([]byte, 18)}, {Type: eap.ATMAC, Value: make([]byte, 18)}}}).Marshal()
	calls := 0
	req.Client = httpFunc(func(r *HTTPRequest) (*HTTPResponse, error) {
		calls++
		a := decodeActions(t, r)
		if calls > 1 {
			b, err := base64.StdEncoding.DecodeString(a[0]["payload"].(string))
			if err != nil {
				t.Fatal(err)
			}
			packet, err := eap.Parse(b)
			if err != nil || packet.Subtype != eap.SynchronizationFailure || packet.Identifier != 7 {
				t.Fatalf("AUTS reply %+v %v", packet, err)
			}
			auts, ok := packet.Get(eap.ATAUTS)
			if !ok || !bytes.Equal(auts, p.result.AUTS) {
				t.Fatalf("AUTS %x", auts)
			}
		}
		return response(t, []any{map[string]any{"status": 1003, "response-id": a[0]["request-id"], "challenge": base64.StdEncoding.EncodeToString(challenge)}}, false), nil
	})
	if _, err := StartEmergencyAddressUpdate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "8 requests") {
		t.Fatalf("unbounded resynchronization: %v", err)
	}
	if calls != 8 || p.calls != 8 {
		t.Fatalf("exchange bounds HTTP=%d SIM=%d", calls, p.calls)
	}
}
